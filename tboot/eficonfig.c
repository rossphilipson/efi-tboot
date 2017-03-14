/*
 * eficonfig.c: EFI related configuration settings and data.
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

#include <config.h>
#include <efibase.h>
#include <stdbool.h>
#include <types.h>
#include <ctype.h>
#include <string.h>
#include <misc.h>
#include <eficore.h>
#include <eficonfig.h>
#include <printk.h>

/* The main config files read from disk */
efi_file_t g_efi_configs[EFI_CONFIG_MAX];

/* Root path to TBOOT image home */
wchar_t g_tboot_dir[EFI_MAX_PATH];

/* Is this pre or post EBS */
bool g_post_ebs = false;

const char *g_kernel_cmdline = "";

/* Core TXT and TBOOT files stored in EfiRuntimeServicesData */
efi_file_t g_platform_sinit;
efi_file_t g_platform_racm;
efi_file_t g_lcp;

/* The xen image plush the kernl and ramdisk images passed back from Xen */
efi_file_t g_xen;
efi_file_t g_kernel;
efi_file_t g_ramdisk;

/* EFI memory map just before EBS from Xen */
void *g_memory_map;
uint64_t g_memory_map_size;
uint64_t g_memory_desc_size;

/* Xen post launch callback */
uint64_t g_xen_post_launch_cb;

void efi_cfg_init(void)
{
    memset(&g_tboot_dir[0], 0, EFI_MAX_PATH*sizeof(wchar_t));
    memset(&g_efi_configs[0], 0, EFI_CONFIG_MAX*sizeof(efi_file_t));
}

efi_file_t *efi_get_configs(void)
{
    return &g_efi_configs[0];
}

void efi_cfg_pre_parse(efi_file_t *config)
{
    char *ptr = config->u.buffer, *end = ptr + config->size;
    bool start = true, comment = false;

    for ( ; ptr < end; ++ptr ) {
        if ( iscntrl(*ptr) ) {
            comment = false;
            start = true;
            *ptr = 0;
        }
        else if ( comment || (start && isspace(*ptr)) ) {
            *ptr = 0;
        }
        else if ( *ptr == '#' || (start && *ptr == ';') ) {
            comment = true;
            *ptr = 0;
        }
        else
            start = false;
    }
    if ( config->size && end[-1] )
         printk("No newline at end of config file last line will be ignored.\n");
}

char *efi_cfg_get_value(int index, const char *section,
                        const char *item)
{
    efi_file_t *config;
    char *ptr, *end;
    size_t slen = section ? strlen(section) : 0, ilen = strlen(item);
    bool match = !slen;

    if (index >= EFI_CONFIG_MAX)
        return NULL;

    config = &g_efi_configs[index];
    ptr = config->u.buffer;
    end = ptr + config->size;

    for ( ; ptr < end; ++ptr ) {
        switch ( *ptr ) {
        case 0:
            continue;
        case '[':
            if ( !slen )
                break;
            if ( match )
                return NULL;
            match = strncmp(++ptr, section, slen) == 0 && ptr[slen] == ']';
            break;
        default:
            if ( match && strncmp(ptr, item, ilen) == 0 && ptr[ilen] == '=' ) {
                ptr += ilen + 1;
                /* strip off any leading spaces */
                while ( *ptr && isspace(*ptr) )
                    ptr++;
                return ptr;
            }
            break;
        }
        ptr += strlen(ptr);
    }
    return NULL;
}

bool efi_split_kernel_line(void)
{
    char *ptr;

    ptr = efi_cfg_get_value(EFI_CONFIG_XEN_PARSED,
                            SECTION_GLOBAL, ITEM_DEFAULT);
    if (!ptr)
        return false;

    ptr = efi_cfg_get_value(EFI_CONFIG_XEN_PARSED,
                            ptr, ITEM_KERNEL);
    if (!ptr)
        return false;

    for ( ; *ptr && !isspace(*ptr); ptr++);

    if (ptr) {
        *ptr = 0;
        g_kernel_cmdline = ptr + 1;
    }
    /* Else there is no kernel cmdline - I guess that is possible */

    return true;
}

bool efi_cfg_copy_tboot_path(const wchar_t *file_path)
{
    uint64_t len = wcslen(file_path);
    wchar_t *ptr = g_tboot_dir + len;

    if (len >= EFI_MAX_PATH)
        return false;

    memcpy(g_tboot_dir, file_path, len*sizeof(wchar_t));

    while (ptr >= g_tboot_dir) {
        if (*ptr == L'\\') {
            *(ptr + 1) = L'\0';
            return true;
        }
        ptr--;
    }

    return false;
}

const efi_file_t *efi_get_platform_sinit(void)
{
    if (g_platform_sinit.size > 0)
        return &g_platform_sinit;
    return NULL;
}

const efi_file_t *efi_get_platform_racm(void)
{
    if (g_platform_racm.size > 0)
        return &g_platform_racm;
    return NULL;
}

const efi_file_t *efi_get_lcp(void)
{
    if (g_lcp.size > 0)
        return &g_lcp;
    return NULL;
}

void efi_store_files(const efi_file_t *platform_sinit,
                     const efi_file_t *platform_racm,
                     const efi_file_t *lcp)
{
    memset(&g_platform_sinit, 0, sizeof(efi_file_t));
    memset(&g_platform_racm, 0, sizeof(efi_file_t));
    memset(&g_lcp, 0, sizeof(efi_file_t));

    if (platform_sinit && platform_sinit->u.buffer)
        g_platform_sinit = *platform_sinit;
    if (platform_racm && platform_racm->u.buffer)
        g_platform_racm = *platform_racm;
    if (lcp && lcp->u.buffer)
        g_lcp = *lcp;
}

const efi_file_t *efi_get_xen(void)
{
    if (g_xen.size > 0)
        return &g_xen;
    return NULL;
}

const efi_file_t *efi_get_kernel(void)
{
    if (g_kernel.size > 0)
        return &g_kernel;
    return NULL;
}

const efi_file_t *efi_get_ramdisk(void)
{
    if (g_ramdisk.size > 0)
        return &g_ramdisk;
    return NULL;
}

const void *efi_get_memory_map(uint64_t *size_out, uint64_t *size_desc_out)
{
    *size_out = g_memory_map_size;
    *size_desc_out = g_memory_desc_size;
    return g_memory_map;
}

uint64_t efi_get_xen_post_launch_cb(void)
{
    return g_xen_post_launch_cb;
}

void efi_store_xen_info(void *base, uint64_t size)
{
    memset(&g_xen, 0, sizeof(efi_file_t));
    g_xen.u.buffer = base;
    g_xen.size = size;
}

bool efi_store_xen_tboot_data(efi_xen_tboot_data_t *xtd)
{
    /* sanity */
    if ( (xtd->kernel == NULL) || (xtd->kernel_size == 0) ||
         (xtd->ramdisk == NULL) || (xtd->ramdisk_size == 0) ||
         (xtd->memory_map == NULL) || (xtd->memory_map_size == 0) ||
         (xtd->memory_desc_size == 0))
        return false;

    memset(&g_kernel, 0, sizeof(efi_file_t));
    memset(&g_ramdisk, 0, sizeof(efi_file_t));

    g_kernel.u.buffer = xtd->kernel;
    g_kernel.size = xtd->kernel_size;
    g_ramdisk.u.buffer = xtd->ramdisk;
    g_ramdisk.size = xtd->ramdisk_size;
    g_memory_map = xtd->memory_map;
    g_memory_map_size = xtd->memory_map_size;
    g_memory_desc_size = xtd->memory_desc_size;
    g_xen_post_launch_cb = xtd->post_launch_cb;

    return true;
}

