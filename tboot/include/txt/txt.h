/*
 * txt.h: Intel(r) TXT support functions
 *
 * Copyright (c) 2003-2008, Intel Corporation
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

#ifndef __TXT_TXT_H__
#define __TXT_TXT_H__

// #include <multiboot.h>

void txt_init_mle_header(void);
bool txt_build_mle_pagetable(void);
void txt_enable_smx(void);
bool txt_is_launched(void);
bool txt_get_error(void);
void txt_get_racm_error(void);
tb_error_t supports_txt(void);
tb_error_t txt_verify_platform(void);
bool txt_prepare_cpu(void);
tb_error_t txt_launch_environment(void);
/* TODO need to address the loader business, stub out for now
tb_error_t txt_launch_racm(loader_ctx *lctx);
*/
void txt_post_launch(void);
tb_error_t txt_protect_mem_regions(void);
tb_error_t txt_post_launch_verify_platform(void);
bool txt_s3_launch_environment(void);
void txt_shutdown(void);
bool txt_is_powercycle_required(void);
void ap_wait(unsigned int cpuid);

uint32_t g_using_da;
atomic_t ap_wfs_count;

#endif      /* __TXT_TXT_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

