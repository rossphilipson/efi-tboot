/*
 * cmdline.h: support functions for command line parsing
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#ifndef __CMDLINE_H__
#define __CMDLINE_H__

#define CMDLINE_SIZE   512
char g_cmdline[CMDLINE_SIZE];


void tboot_parse_cmdline(bool defaults);
void get_tboot_loglvl(void);
void get_tboot_log_targets(void);
bool get_tboot_serial(void);
void get_tboot_baud(void);
void get_tboot_fmt(void);
void get_tboot_vga_delay(void);
bool get_tboot_mwait(void);
bool get_tboot_prefer_da(void);
void get_tboot_min_ram(void);
bool get_tboot_call_racm(void);
bool get_tboot_call_racm_check(void);
bool get_tboot_measure_nv(void);
void get_tboot_extpol(void);

/* for parse cmdline of linux kernel, say vga and mem */
void linux_parse_cmdline(const char *cmdline);
bool get_linux_vga(int *vid_mode);
bool get_linux_mem(uint64_t *initrd_max_mem);

uint8_t get_loglvl_prefix(char **pbuf, int *len);

#endif    /* __CMDLINE_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
