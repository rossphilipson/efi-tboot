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

typedef enum efi_file_select {
    EFI_FILE_INVALID = 0,
    EFI_FILE_TBOOT_CONFIG,
    EFI_FILE_TBOOT_CONFIG_PARSED,
    EFI_FILE_XEN_CONFIG,
    EFI_FILE_XEN_CONFIG_PARSED,
    EFI_FILE_PLATFORM_SINIT,
    EFI_FILE_PLATFORM_RACM,
    EFI_FILE_LCP,
    EFI_FILE_RTMEM,
    EFI_FILE_TBSHARED,
    EFI_FILE_IMAGE,
    EFI_FILE_IMAGE_TEXT,
    EFI_FILE_IMAGE_BSS,
    EFI_FILE_XEN,
    EFI_FILE_KERNEL,
    EFI_FILE_RAMDISK,
    EFI_FILE_UCODE,
    EFI_FILE_MAX
} efi_file_select_t;

typedef struct {
    union {
        uint8_t *base;
        EFI_PHYSICAL_ADDRESS addr;
    } u;
    uint64_t size;
} efi_file_t;

typedef struct {
    void     *base;
    uint64_t  size;
    uint64_t  desc_size;
    uint32_t  desc_ver;
} efi_memmap_t;

void efi_cfg_init(void);
efi_file_t *efi_get_file(efi_file_select_t sel);
efi_memmap_t *efi_get_memmap(void);
void efi_set_postebs(void);
bool efi_is_postebs(void);
const wchar_t *efi_get_tboot_path(void);
const char *efi_get_kernel_cmdline(void);
void efi_cfg_pre_parse(efi_file_t *config);
char *efi_cfg_get_value(efi_file_t *config, const char *section,
                        const char *item);
bool efi_split_kernel_line(void);
bool efi_cfg_copy_tboot_path(const wchar_t *file_path);

#endif /* __EFI_CONFIG_H__ */
