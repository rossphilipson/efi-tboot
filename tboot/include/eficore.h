/*
 * eficore.h: EFI core support definitions.
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

#ifndef __EFICORE_H__
#define __EFICORE_H__

#define EFI_EARLY_PRINTK

/* TODO debug only stuffs */
#define EFI_DEBUG

/* Un-extern these that are defined in the GNU-EFI headers */
EFI_SYSTEM_TABLE         *ST;
EFI_BOOT_SERVICES        *BS;
EFI_RUNTIME_SERVICES     *RT;

EFI_GUID EfiGlobalVariable;
EFI_GUID NullGuid;
EFI_GUID UnknownDevice;
EFI_GUID DevicePathProtocol;
EFI_GUID LoadedImageProtocol;
EFI_GUID FileSystemProtocol;
EFI_GUID GenericFileInfo;
EFI_GUID AcpiTableGuid;
EFI_GUID Acpi20TableGuid;
EFI_GUID SMBIOSTableGuid;
EFI_GUID TbootXenGuid;

#define TB_RESMEM_BLOCKS  128

typedef struct __packed {
    uint64_t addr;
    uint64_t length;
} reserve_map_t;

/* Information passed to Xen at launch by TBOOT */
typedef struct __packed efi_tboot_xen_handoff {
    void          *xen;
    uint64_t       xen_size;
    void          *kernel;
    uint64_t       kernel_size;
    void          *ramdisk;
    uint64_t       ramdisk_size;
    void          *xsm;
    uint64_t       xsm_size;
    void          *ucode;
    uint64_t       ucode_size;
    void          *config;
    uint64_t       config_size;
    void          *system_table;
    void          *memory_map;
    uint64_t       memory_map_size;
    uint64_t       memory_desc_size;
    uint64_t       memory_desc_ver;
    uint64_t       reserve_map_count;
    reserve_map_t  reserve_map[TB_RESMEM_BLOCKS];
} efi_tboot_xen_handoff_t;

/* The TBOOT handoff structure in RT mem */
efi_tboot_xen_handoff_t *_tboot_handoff;

/* The following routines are available before and after EBS */

void atow(wchar_t *dst, const char *src, uint64_t count);
bool wtoa(char *dst, const wchar_t *src, uint64_t count);
uint64_t wcslen(const wchar_t *str);

uint8_t *efi_get_rsdp(void);

void *efi_get_pe_section(const char *name, void *image_base,
                         uint64_t *size_out);
void *efi_get_pe_export(const char *name, void *image_base);

bool efi_load_txt_files(void);

bool efi_load_boot_files(void);

bool efi_exit_boot_services(void);

void efi_shutdown_system(uint32_t shutdown_type);

/* The following routines are only available after EBS */

bool efi_scan_memory_map(void);
bool efi_add_resmap_entry(uint64_t addr, uint64_t length);
bool efi_get_ram_ranges(uint64_t *min_lo_ram, uint64_t *max_lo_ram,
                        uint64_t *min_hi_ram, uint64_t *max_hi_ram);
bool efi_verify_rtmem_layout(uint64_t mle_base);

/* The following routines are unavailable after EBS */

wchar_t *atow_alloc(const char *src);
char *wtoa_alloc(const wchar_t *src);

wchar_t *atow_cat(const wchar_t *base, const char *tail);

void efi_puts(const char *s, unsigned int count);

EFI_DEVICE_PATH *efi_get_device_path(const wchar_t *path,
                                     EFI_HANDLE parent);
EFI_STATUS efi_device_path_to_text(EFI_DEVICE_PATH *dev_path,
                                   wchar_t *path_out,
                                   uint64_t count);
EFI_FILE_INFO *efi_get_file_info(EFI_FILE *target_file,
                                 EFI_MEMORY_TYPE mem_type);
EFI_STATUS efi_read_file(EFI_FILE_IO_INTERFACE *file_system,
                         wchar_t *file_name,
                         EFI_MEMORY_TYPE mem_type,
                         uint64_t *size_out,
                         EFI_PHYSICAL_ADDRESS *addr_out);

void efi_launch_kernel(void);

#endif    /* __EFICORE_H__ */
