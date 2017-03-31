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
#include <tb_error.h>
#include <tboot.h>

/* Memory based file storage */
static efi_file_t __data efi_files[EFI_FILE_MAX];

/* The EFI memory map just after EBS */
static efi_memmap_t __data *efi_memmap;

/* Root path to TBOOT image home */
static wchar_t __data tboot_dir[EFI_MAX_PATH];

static const char __data *kernel_cmdline = "";

/* Is this pre or post EBS */
static bool __data postebs = false;

void efi_cfg_init(void)
{
    memset(&tboot_dir[0], 0, EFI_MAX_PATH*sizeof(wchar_t));
    memset(&efi_files[0], 0, EFI_FILE_MAX*sizeof(efi_file_t));
}

efi_file_t *efi_get_file(efi_file_select_t sel)
{
    return &efi_files[sel];
}

efi_memmap_t *efi_get_memmap(void)
{
    return efi_memmap;
}

void efi_set_postebs(void)
{
    postebs = true;
}

bool efi_is_postebs(void)
{
    return postebs;
}

const wchar_t *efi_get_tboot_path(void)
{
    return &tboot_dir[0];
}

const char *efi_get_kernel_cmdline(void)
{
    return &kernel_cmdline[0];
}

void efi_cfg_pre_parse(efi_file_t *config)
{
    char *ptr = config->u.base, *end = ptr + config->size;
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

char *efi_cfg_get_value(efi_file_t *config, const char *section,
                        const char *item)
{
    char *ptr, *end;
    size_t slen = section ? strlen(section) : 0, ilen = strlen(item);
    bool match = !slen;

    ptr = config->u.base;
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
    char       *ptr;
    efi_file_t *cfg = efi_get_file(EFI_FILE_XEN_CONFIG_PARSED);

    ptr = efi_cfg_get_value(cfg, SECTION_GLOBAL, ITEM_DEFAULT);
    if (!ptr)
        return false;

    ptr = efi_cfg_get_value(cfg, ptr, ITEM_KERNEL);
    if (!ptr)
        return false;

    for ( ; *ptr && !isspace(*ptr); ptr++);

    if (ptr) {
        *ptr = 0;
        kernel_cmdline = ptr + 1;
    }
    /* Else there is no kernel cmdline - I guess that is possible */

    return true;
}

bool efi_cfg_copy_tboot_path(const wchar_t *file_path)
{
    uint64_t len = wcslen(file_path);
    wchar_t *ptr = tboot_dir + len;

    if (len >= EFI_MAX_PATH)
        return false;

    memcpy(tboot_dir, file_path, len*sizeof(wchar_t));

    while (ptr >= tboot_dir) {
        if (*ptr == L'\\') {
            *(ptr + 1) = L'\0';
            return true;
        }
        ptr--;
    }

    return false;
}

void efi_setup_xen_handoff(void)
{
    efi_file_t   *file;
    efi_memmap_t *memmap;

    file = efi_get_file(EFI_FILE_XEN);
    _tboot_handoff->xen = file->u.base;
    _tboot_handoff->xen_size = file->size;
    file = efi_get_file(EFI_FILE_KERNEL);
    _tboot_handoff->kernel = file->u.base;
    _tboot_handoff->kernel_size = file->size;
    file = efi_get_file(EFI_FILE_RAMDISK);
    _tboot_handoff->ramdisk = file->u.base;
    _tboot_handoff->ramdisk_size = file->size;
    file = efi_get_file(EFI_FILE_XSM);
    _tboot_handoff->xsm = file->u.base;
    _tboot_handoff->xsm_size = file->size;
    file = efi_get_file(EFI_FILE_UCODE);
    _tboot_handoff->ucode = file->u.base;
    _tboot_handoff->ucode_size = file->size;
    file = efi_get_file(EFI_FILE_XEN_CONFIG);
    _tboot_handoff->config = file->u.base;
    _tboot_handoff->config_size = file->size;
    _tboot_handoff->tboot_shared = _tboot_shared;

    /* TODO how to validate these ?? */
    _tboot_handoff->system_table = ST;

    memmap = efi_get_memmap();
    _tboot_handoff->memory_map = memmap->base;
    _tboot_handoff->memory_map_size = memmap->size;
    _tboot_handoff->memory_desc_size = memmap->desc_size;
    _tboot_handoff->memory_desc_ver = memmap->desc_ver;

    /*
     * TODO GOP and Console values (in RT data mem)
     * This is going to be a mess because:
     *  - there is a lot to fetch.
     *  - modes need to be set dependend on Xen settings.
     * We can save this misery for later.
     */

    /*
     * N.B. we are currently not supporting and passing:
     *  - PCI ROM information reported by XEN_FW_EFI_PCI_ROM hc.
     *  - EDD disk firmware info reported by XEN_FW_DISK_INFO hc op.
     * This information (if anybody actually uses it) will not be available.
     */
}
