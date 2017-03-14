/*
 * eficonfig.h: EFI related config definitions.
 *
 * Copyright (c) 2017 Assured Information Security.
 *
 * Ross Philipson <philipsonr@ainfosec.com>
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
 */

#ifndef __EFI_CONFIG_H__
#define __EFI_CONFIG_H__

#define EFI_MAX_PATH 512
#define EFI_MAX_CONFIG_FILE 1024 /* plenty of room for a config file */

/* TBOOT config */
#define SECTION_TBOOT "tboot"
# define ITEM_OPTIONS "options"
# define ITEM_XENPATH "xenpath"
# define ITEM_LCP     "lcp"
#define SECTION_ACM   "acm"
#define SECTION_RACM  "racm"

/* Xen config */
#define SECTION_GLOBAL "global"
# define ITEM_DEFAULT  "default"
# define ITEM_KERNEL   "kernel"

enum {
    EFI_CONFIG_TBOOT = 0,
    EFI_CONFIG_TBOOT_PARSED,
    EFI_CONFIG_XEN,
    EFI_CONFIG_XEN_PARSED,
    EFI_CONFIG_MAX
};

typedef struct {
    union {
        char *buffer;
        EFI_PHYSICAL_ADDRESS addr;
    } u;
    uint64_t  size;
} efi_file_t;

wchar_t     g_tboot_dir[EFI_MAX_PATH];
bool        g_post_ebs;
const char *g_kernel_cmdline;

/* Locations of runtime offsets */
void     *g_rtmem_base;
void     *g_image_base;
uint64_t  g_image_size;
void     *g_text_base;
uint64_t  g_text_size;
void     *g_bss_base;
uint64_t  g_bss_size;

void efi_cfg_init(void);
efi_file_t *efi_get_configs(void);
void efi_cfg_pre_parse(efi_file_t *config);
char *efi_cfg_get_value(int index, const char *section,
                        const char *item);

bool efi_split_kernel_line(void);
bool efi_cfg_copy_tboot_path(const wchar_t *file_path);

const efi_file_t *efi_get_platform_sinit(void);
const efi_file_t *efi_get_platform_racm(void);
const efi_file_t *efi_get_lcp(void);
void efi_store_files(const efi_file_t *platform_sinit,
                     const efi_file_t *platform_racm,
                     const efi_file_t *lcp);

const efi_file_t *efi_get_xen(void);
const efi_file_t *efi_get_kernel(void);
const efi_file_t *efi_get_ramdisk(void);
const void *efi_get_memory_map(uint64_t *size_out, uint64_t *size_desc_out);
uint64_t efi_get_xen_post_launch_cb(void);

void efi_store_xen_info(void *base, uint64_t size);
bool efi_store_xen_tboot_data(efi_xen_tboot_data_t *xtd);

#endif /* __EFI_CONFIG_H__ */
