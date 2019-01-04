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
            launch_kernel();
            break; /* if launch xen fails, do halt at the end */
        case TB_POLACT_HALT:
            break; /* do halt at the end */
        default:
            printk(TBOOT_ERR"Error: invalid policy action (%d)\n", action);
            /* do halt at the end */
    }

    /* Deal with apply policy and cases whee we should shutdown */
    shutdown_system(TB_SHUTDOWN_HALT);
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
