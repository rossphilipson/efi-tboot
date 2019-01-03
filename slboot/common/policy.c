/*
 * policy.c: support functions for tboot verification launch
 *
 * Copyright (c) 2006-2014, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <config.h>
#include <stdarg.h>
#include <types.h>
#include <ctype.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <processor.h>
#include <misc.h>
#include <uuid.h>
#include <loader.h>
#include <hash.h>
#include <tb_error.h>
#define PRINT printk
#include <mle.h>
#include <loader.h>
#include <tboot.h>
#include <tpm.h>
#include <tb_policy.h>
#include <lcp3.h>
#include <lcp3_hlp.h>
#include <cmdline.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/txt.h>
#include <txt/heap.h>

extern void shutdown(void);

extern long s3_flag;

/*
 * policy actions
 */
typedef enum {
    TB_POLACT_CONTINUE,
    TB_POLACT_UNMEASURED_LAUNCH,
    TB_POLACT_HALT,
} tb_policy_action_t;

/* policy map types */
typedef struct {
    tb_error_t         error;
    tb_policy_action_t action;
} tb_policy_map_entry_t;

typedef struct {
    uint8_t                policy_type;
    tb_policy_action_t     default_action;
    tb_policy_map_entry_t  exception_action_table[TB_ERR_MAX];
                           /* have TB_ERR_NONE as last entry */
} tb_policy_map_t;

/* map */
static const tb_policy_map_t g_policy_map[] = {
    { TB_POLTYPE_CONT_NON_FATAL,               TB_POLACT_CONTINUE,
      {
          {TB_ERR_FATAL,                       TB_POLACT_HALT},
          {TB_ERR_PREV_TXT_ERROR,              TB_POLACT_UNMEASURED_LAUNCH}, 
          {TB_ERR_TPM_NOT_READY,               TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SMX_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_VMX_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_VTD_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
	  {TB_ERR_TXT_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SINIT_NOT_PRESENT,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_ACMOD_VERIFY_FAILED,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_CONT_VERIFY_FAIL,             TB_POLACT_HALT,
      {
          {TB_ERR_MODULE_VERIFICATION_FAILED,  TB_POLACT_CONTINUE},
          {TB_ERR_NV_VERIFICATION_FAILED,      TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_NOT_PRESENT,          TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_INVALID,              TB_POLACT_CONTINUE},
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_HALT,                         TB_POLACT_HALT,
      {
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },
};

/* buffer for policy as read from TPM NV */
#define MAX_POLICY_SIZE                             \
    (( MAX_TB_POLICY_SIZE > sizeof(lcp_policy_t) )  \
        ? MAX_TB_POLICY_SIZE                        \
        : sizeof(lcp_policy_t) )
static uint8_t _policy_index_buf[MAX_POLICY_SIZE];

/* default policy */
static const tb_policy_t _def_policy = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    hash_alg       : TB_HALG_SHA1,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 3,
    entries        : {
        {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 19 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 19,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* NV index for geo-tagging will be extended to PCR 22 */
            mod_num    : TB_POL_MOD_NUM_NV_RAW,
            pcr        : 22,
            hash_type  : TB_HTYPE_ANY,
            nv_index   : 0x40000010,
            num_hashes : 0
        }
    }
};

/* default policy for Details/Authorities pcr mapping */
static const tb_policy_t _def_policy_da = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    hash_alg       : TB_HALG_SHA1,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 3,
    entries        : {
        {   /* mod 0 is extended to PCR 17 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 17 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 17,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* NV index for geo-tagging will be extended to PCR 22 */
            mod_num    : TB_POL_MOD_NUM_NV_RAW,
            pcr        : 22,
            hash_type  : TB_HTYPE_ANY,
            nv_index   : 0x40000010,
            num_hashes : 0
        }
    }
};

/* current policy */
static const tb_policy_t* g_policy = &_def_policy;

/*
 * read_policy_from_tpm
 *
 * read policy from TPM NV into buffer
 *
 * policy_index_size is in/out
 */
static bool read_policy_from_tpm(uint32_t index, void* policy_index, size_t *policy_index_size)
{
#define NV_READ_SEG_SIZE    256
    unsigned int offset = 0;
    unsigned int data_size = 0;
    uint32_t ret, index_size;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    if ( policy_index_size == NULL ) {
        printk(TBOOT_ERR"size is NULL\n");
        return false;
    }

    ret = tpm_fp->get_nvindex_size(tpm, tpm->cur_loc, index, &index_size);
    if ( !ret )
        return false;

    if ( index_size > *policy_index_size ) {
        printk(TBOOT_WARN"policy in TPM NV %x was too big for buffer\n", index);
        index_size = *policy_index_size;
    }


    do {
        /* get data_size */
        if ( (index_size - offset) > NV_READ_SEG_SIZE )
            data_size = NV_READ_SEG_SIZE;
        else
            data_size = (uint32_t)(index_size - offset);

        /* read! */
        ret = tpm_fp->nv_read(tpm, tpm->cur_loc, index, offset,
                             (uint8_t *)policy_index + offset, &data_size);
        if ( !ret || data_size == 0 )
            break;

        /* adjust offset */
        offset += data_size;
    } while ( offset < index_size );

    if ( offset == 0 && !ret ) {
        printk(TBOOT_ERR"Error: read TPM error: 0x%x from index %x.\n", ret, index);
        return false;
    }

    *policy_index_size = offset;

    return true;
}

/*
 * unwrap_lcp_policy
 *
 * unwrap custom element in lcp policy into tb policy
 * assume sinit has already verified lcp policy and lcp policy data.
 */
static bool unwrap_lcp_policy(void)
{
    void* lcp_base;
    uint32_t lcp_size;

    // scaffolding
    printk(TBOOT_INFO"in unwrap_lcp_policy\n");

    if ( txt_is_launched() ) {
        txt_heap_t *txt_heap = get_txt_heap();
        os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);

        lcp_base = (void *)(unsigned long)os_sinit_data->lcp_po_base;
        lcp_size = (uint32_t)os_sinit_data->lcp_po_size;
    }
    else {
        extern loader_ctx *g_ldr_ctx;
        if ( !find_lcp_module(g_ldr_ctx, &lcp_base, &lcp_size) )
            return false;
    }

    /* if lcp policy data version is 2+ */
    if ( tb_memcmp((void *)lcp_base, LCP_POLICY_DATA_FILE_SIGNATURE,
             LCP_FILE_SIG_LENGTH) == 0 ) {
        lcp_policy_data_t *poldata = (lcp_policy_data_t *)lcp_base;
        lcp_policy_list_t *pollist = &poldata->policy_lists[0];

        for ( int i = 0; i < poldata->num_lists; i++ ) {
            lcp_policy_element_t *elt = pollist->policy_elements;
            uint32_t elts_size = 0;

            while ( elt ) {
                /* check element type */
                if ( elt->type == LCP_POLELT_TYPE_CUSTOM || 
                     elt->type == LCP_POLELT_TYPE_CUSTOM2 ) {
                    lcp_custom_element_t *custom =
                        (lcp_custom_element_t *)&elt->data;

                    /* check uuid in custom element */
                    if ( are_uuids_equal(&custom->uuid,
                             &((uuid_t)LCP_CUSTOM_ELEMENT_TBOOT_UUID)) ) {
                        tb_memcpy(_policy_index_buf, &custom->data,
                            elt->size - sizeof(*elt) - sizeof(uuid_t));
                        return true; /* find tb policy */
                    }
                }

                elts_size += elt->size;
                if ( elts_size >= pollist->policy_elements_size )
                    break;

                elt = (void *)elt + elt->size;
            }
            if ( pollist->version == LCP_TPM12_POLICY_LIST_VERSION )
                pollist = (void *)pollist + get_tpm12_policy_list_size(pollist);
            else if ( pollist->version == LCP_TPM20_POLICY_LIST_VERSION )
                pollist = (void *)pollist + get_tpm20_policy_list_size(
                        (lcp_policy_list_t2 *)pollist);
        }
    }

    return false;
}

/*
 * set_policy
 *
 * load policy from TPM NV and validate it, else use default
 *
 */
tb_error_t set_policy(void)
{
    const struct tpm_if *tpm = get_tpm();
    
    /* try to read tboot policy from TB_POLICY_INDEX in TPM NV */
    size_t policy_index_size = sizeof(_policy_index_buf);
    printk(TBOOT_INFO"reading Verified Launch Policy from TPM NV...\n");
    if ( read_policy_from_tpm(tpm->tb_policy_index,
             _policy_index_buf, &policy_index_size) ) {
        printk(TBOOT_DETA"\t:%lu bytes read\n", policy_index_size);
        if ( verify_policy((tb_policy_t *)_policy_index_buf,
                 policy_index_size, true) ) {
            goto policy_found;
        }
    }
    printk(TBOOT_WARN"\t:reading failed\n");

    /* tboot policy not found in TB_POLICY_INDEX, so see if it is wrapped
     * in a custom element in the PO policy; if so, SINIT will have verified
     * the policy and policy data for us; we just need to ensure the policy
     * type is LCP_POLTYPE_LIST (since we could have been give a policy data
     * file even though the policy was not a LIST */
    printk(TBOOT_INFO"reading Launch Control Policy from TPM NV...\n");
    if ( read_policy_from_tpm(tpm->lcp_own_index,
             _policy_index_buf, &policy_index_size) ) {
        printk(TBOOT_DETA"\t:%lu bytes read\n", policy_index_size);
        /* assume lcp policy has been verified by sinit already */
        lcp_policy_t *pol = (lcp_policy_t *)_policy_index_buf;
        if ( pol->version == LCP_DEFAULT_POLICY_VERSION_2 &&
             pol->policy_type == LCP_POLTYPE_LIST && unwrap_lcp_policy() ) {
            if ( verify_policy((tb_policy_t *)_policy_index_buf,
                     calc_policy_size((tb_policy_t *)_policy_index_buf),
                     true) )
                goto policy_found;
        }
        lcp_policy_t2 *pol2 = (lcp_policy_t2 *)_policy_index_buf;
        if ( pol2->version == LCP_DEFAULT_POLICY_VERSION &&
             pol2->policy_type == LCP_POLTYPE_LIST && unwrap_lcp_policy() ) {
            if ( verify_policy((tb_policy_t *)_policy_index_buf,
                     calc_policy_size((tb_policy_t *)_policy_index_buf),
                     true) )
                goto policy_found;
        }
    }
    printk(TBOOT_WARN"\t:reading failed\n");

    /* either no policy in TPM NV or policy is invalid, so use default */
    printk(TBOOT_WARN"failed to read policy from TPM NV, using default\n");
    g_policy = g_using_da ? &_def_policy_da : &_def_policy;
    policy_index_size = calc_policy_size(g_policy);

    /* sanity check; but if it fails something is really wrong */
    if ( !verify_policy(g_policy, policy_index_size, true) )
        return TB_ERR_FATAL;
    else
        return TB_ERR_POLICY_NOT_PRESENT;

policy_found:
    /* compatible with tb_policy tools for TPM 1.2 */
    {
        tb_policy_t *tmp_policy = (tb_policy_t *)_policy_index_buf;
        if (tmp_policy->hash_alg == 0)
            tmp_policy->hash_alg = TB_HALG_SHA1;
    }
    g_policy = (tb_policy_t *)_policy_index_buf;
    return TB_ERR_NONE;
}

/* hash current policy */
bool hash_policy(tb_hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL ) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    return hash_buffer((unsigned char *)g_policy, calc_policy_size(g_policy),
                       hash, hash_alg);
}

/* generate hash by hashing cmdline and module image */
static bool hash_module(hash_list_t *hl,
                        const char* cmdline, void *base,
                        size_t size)
{
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    if ( hl == NULL ) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    /* final hash is SHA-1( SHA-1(cmdline) | SHA-1(image) ) */
    /* where cmdline is first stripped of leading spaces, file name, then */
    /* any spaces until the next non-space char */
    /* (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "") */

    /* hash command line */
    if ( cmdline == NULL )
        cmdline = "";
    // else
    //    cmdline = skip_filename(cmdline);

    switch (tpm->extpol) {
    case TB_EXTPOL_FIXED: 
        hl->count = 1;
        hl->entries[0].alg = tpm->cur_alg;

        if ( !hash_buffer((const unsigned char *)cmdline, tb_strlen(cmdline),
                    &hl->entries[0].hash, tpm->cur_alg) )
            return false;
        /* hash image and extend into cmdline hash */
        tb_hash_t img_hash;
        if ( !hash_buffer(base, size, &img_hash, tpm->cur_alg) )
            return false;
        if ( !extend_hash(&hl->entries[0].hash, &img_hash, tpm->cur_alg) )
            return false;

        break;

    case TB_EXTPOL_AGILE: 
    {
        hash_list_t img_hl, final_hl;
        if ( !tpm_fp->hash(tpm, 2, (const unsigned char *)cmdline,
                tb_strlen(cmdline), hl) )
            return false;

        uint8_t buf[128];

        if ( !tpm_fp->hash(tpm, 2, base, size, &img_hl) )
            return false;
        for (unsigned int i=0; i<hl->count; i++) {
            for (unsigned int j=0; j<img_hl.count; j++) {
                if (hl->entries[i].alg == img_hl.entries[j].alg) {
                    copy_hash((tb_hash_t *)buf, &hl->entries[i].hash,
                            hl->entries[i].alg);
                    copy_hash((tb_hash_t *)(buf + get_hash_size(hl->entries[i].alg)),
                            &img_hl.entries[j].hash, hl->entries[i].alg);
                    if ( !tpm_fp->hash(tpm, 2, buf,
                            2*get_hash_size(hl->entries[i].alg), &final_hl) )
                        return false;

                    for (unsigned int k=0; k<final_hl.count; k++) {
                        if (hl->entries[i].alg == final_hl.entries[k].alg) {
                            copy_hash(&hl->entries[i].hash,
                                      &final_hl.entries[k].hash,
                                      hl->entries[i].alg);
                            break;
                        }
                    }
                    
                    break;
                }
            }
        }

        break;
    }

    case TB_EXTPOL_EMBEDDED: 
    {
        tb_hash_t img_hash;
        hl->count = tpm->alg_count;
        for (unsigned int i=0; i<hl->count; i++) {
            hl->entries[i].alg = tpm->algs[i];
            if ( !hash_buffer((const unsigned char *)cmdline, tb_strlen(cmdline),
                        &hl->entries[i].hash, tpm->algs[i]) )
                return false;

            if ( !hash_buffer(base, size, &img_hash, tpm->algs[i]) )
                return false;
            if ( !extend_hash(&hl->entries[i].hash, &img_hash, tpm->algs[i]) )
                return false;
        }

        break;
    }

    default:
        return false;
    }

    return true;
}

static bool is_hash_in_policy_entry(const tb_policy_entry_t *pol_entry,
                                    tb_hash_t *hash, uint16_t hash_alg)
{
    /* assumes policy entry has been validated */

    if ( pol_entry == NULL || hash == NULL) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    if ( pol_entry->hash_type == TB_HTYPE_ANY )
        return true;
    else if ( pol_entry->hash_type == TB_HTYPE_IMAGE ) {
        for ( int i = 0; i < pol_entry->num_hashes; i++ ) {
            if ( are_hashes_equal(get_policy_entry_hash(pol_entry, hash_alg,
                                                        i), hash, hash_alg) )
                return true;
        }
    }

    return false;
}

/*
 * map policy type + error -> action
 */
static tb_policy_action_t evaluate_error(tb_error_t error)
{
    tb_policy_action_t action = TB_POLACT_HALT;

    if ( error == TB_ERR_NONE )
        return TB_POLACT_CONTINUE;

    for ( unsigned int i = 0; i < ARRAY_SIZE(g_policy_map); i++ ) {
        if ( g_policy_map[i].policy_type == g_policy->policy_type ) {
            action = g_policy_map[i].default_action;
            for ( unsigned int j = 0;
                  j < ARRAY_SIZE(g_policy_map[i].exception_action_table);
                  j++ ) {
                if ( g_policy_map[i].exception_action_table[j].error ==
                     error )
                    action = g_policy_map[i].exception_action_table[j].action;
                if ( g_policy_map[i].exception_action_table[j].error ==
                     TB_ERR_NONE )
                    break;
            }
        }
    }

    return action;
}

/*
 * apply policy according to error happened.
 */
void apply_policy(tb_error_t error)
{
    tb_policy_action_t action;

    /* save the error to TPM NV */
    write_tb_error_code(error);

    if ( error != TB_ERR_NONE )
        print_tb_error_msg(error);

    action = evaluate_error(error);
    switch ( action ) {
        case TB_POLACT_CONTINUE:
            return;
        case TB_POLACT_UNMEASURED_LAUNCH:
            /* restore mtrr state saved before */
            restore_mtrrs(NULL);
/*
            if ( s3_flag )
                s3_launch();
            else
                launch_kernel(false);*/
            break; /* if launch xen fails, do halt at the end */
        case TB_POLACT_HALT:
            break; /* do halt at the end */
        default:
            printk(TBOOT_ERR"Error: invalid policy action (%d)\n", action);
            /* do halt at the end */
    }

    /*_tboot_shared.shutdown_type = TB_SHUTDOWN_HALT;*/
    /* TODO deal with apply policy and cases whee we should shutdown */
    /*shutdown();*/
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
