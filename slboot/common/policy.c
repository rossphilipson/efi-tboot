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
