/*
 * eficore.c: EFI core support code.
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
#include <string.h>
#include <page.h>
#include <printk.h>
#include <eficore.h>
#include <eficonfig.h>
#include <pe.h>
#include <tb_error.h>
#include <tboot.h>

/* Global Table Pointers */
EFI_SYSTEM_TABLE        *ST;
EFI_BOOT_SERVICES       *BS;
EFI_RUNTIME_SERVICES    *RT;

/* Local device paths */
EFI_DEVICE_PATH EfiRootDevicePath[] = {
   {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {END_DEVICE_PATH_LENGTH,0}}
};

EFI_DEVICE_PATH EfiEndDevicePath[] = {
   {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {END_DEVICE_PATH_LENGTH, 0}}
};

EFI_DEVICE_PATH EfiEndInstanceDevicePath[] = {
   {END_DEVICE_PATH_TYPE, END_INSTANCE_DEVICE_PATH_SUBTYPE, {END_DEVICE_PATH_LENGTH, 0}}
};


/* EFI IDs */
EFI_GUID EfiGlobalVariable  = EFI_GLOBAL_VARIABLE;
EFI_GUID NullGuid = { 0,0,0,{0,0,0,0,0,0,0,0} };
EFI_GUID UnknownDevice      = UNKNOWN_DEVICE_GUID;

/* Protocol IDs */
EFI_GUID DevicePathProtocol       = DEVICE_PATH_PROTOCOL;
EFI_GUID LoadedImageProtocol      = LOADED_IMAGE_PROTOCOL;
EFI_GUID FileSystemProtocol       = SIMPLE_FILE_SYSTEM_PROTOCOL;

/* File system information IDs */
EFI_GUID GenericFileInfo           = EFI_FILE_INFO_ID;

/* Configuration Table GUIDs */
EFI_GUID AcpiTableGuid            = ACPI_TABLE_GUID;
EFI_GUID Acpi20TableGuid          = ACPI_20_TABLE_GUID;
EFI_GUID SMBIOSTableGuid          = SMBIOS_TABLE_GUID;

/* TBOOT/Xen */
EFI_GUID TbootXenGuid             = EFI_TBOOT_XEN_GUID;

void atow(wchar_t *dst, const char *src, uint64_t count)
{
    uint64_t i;

    for (i = 0; i < count; i++, dst++, src++)
        *dst = (*src & 0x7f);
}

bool wtoa(char *dst, const wchar_t *src, uint64_t count)
{
    uint64_t i;
    bool r = true;

    for (i = 0; i < count; i++, dst++, src++) {
        if (*dst <= 0x7f) {
            *dst = *src;
        }
        else {
            r = false;
            *dst = '_';
        }
    }

    return r;
}

uint64_t wcslen(const wchar_t *str)
{
    uint64_t len;

    for (len = 0; *str != L'\0'; str++, len++)
        ;

    return ++len;
}

wchar_t *atow_alloc(const char *src)
{
    EFI_STATUS  status = EFI_SUCCESS;
    wchar_t    *dst;
    uint64_t    count, size;

    if (!src)
        return NULL;

    count = strlen(src);
    size = (count + 1)*sizeof(wchar_t);

    status = BS->AllocatePool(EfiLoaderData, size, (void**)&dst);
    if (EFI_ERROR(status))
        return NULL;

    memset(dst, 0, size);

    atow(dst, src, count);
    return dst;
}

char *wtoa_alloc(const wchar_t *src)
{
    EFI_STATUS  status = EFI_SUCCESS;
    char       *dst;
    uint64_t    count, size;

    if (!src)
        return NULL;

    count = wcslen(src);
    size = (count + 1)*sizeof(char);

    status = BS->AllocatePool(EfiLoaderData, size, (void**)&dst);
    if (EFI_ERROR(status))
        return NULL;

    memset(dst, 0, size);

    wtoa(dst, src, count);
    return dst;
}

wchar_t *atow_cat(const wchar_t *base, const char *tail)
{
    EFI_STATUS  status = EFI_SUCCESS;
    wchar_t    *dst;
    uint64_t    wcount, scount, size;

    if (!base || !tail)
        return NULL;

    scount = strlen(tail);
    wcount = wcslen(base);
    size = (wcount + scount + 1)*sizeof(wchar_t);

    status = BS->AllocatePool(EfiLoaderData, size, (void**)&dst);
    if (EFI_ERROR(status))
        return NULL;

    memset(dst, 0, size);
    memcpy(dst, base, wcount*sizeof(wchar_t));
    atow((dst + wcount - 1), tail, scount);

    return dst;
}

uint8_t *efi_get_rsdp(void)
{
    EFI_CONFIGURATION_TABLE *conf_table = ST->ConfigurationTable;
    uint8_t                 *acpi_rsdp = NULL;
    uint64_t                 count;

    for (count = 0; count < ST->NumberOfTableEntries; count++, conf_table++) {
         if (!memcmp(&Acpi20TableGuid, &conf_table->VendorGuid, sizeof(EFI_GUID)) ||
             !memcmp(&AcpiTableGuid, &conf_table->VendorGuid, sizeof(EFI_GUID))) {
             acpi_rsdp = conf_table->VendorTable;
             break;
         }
    }

    return acpi_rsdp;
}

#define calc_addr(b, o) (void*)(((uint8_t*)b) + o);

void *efi_get_pe_section(const char *name, void *image_base,
                         uint64_t *size_out)
{
    IMAGE_DOS_HEADER     *dosh;
    IMAGE_NT_HEADERS     *nth;
    IMAGE_FILE_HEADER    *fh;
    IMAGE_SECTION_HEADER *sh;
    uint16_t              i;
    void                 *text = NULL;
    size_t                length = strlen(name);

    dosh = (IMAGE_DOS_HEADER*)image_base;
    nth  = (IMAGE_NT_HEADERS*)calc_addr(dosh, dosh->e_lfanew);

    if (dosh->e_magic != IMAGE_DOS_SIGNATURE) {
        printk("Invalid DOS header signature: %x\n", dosh->e_magic);
        return NULL;
    }

    if (nth->Signature != IMAGE_NT_SIGNATURE) {
        printk("Invalid NT header signature: %x\n", nth->Signature);
        return NULL;
    }

    fh  = (IMAGE_FILE_HEADER*)calc_addr(nth, sizeof(uint32_t));
    sh  = (IMAGE_SECTION_HEADER*)calc_addr(fh, sizeof(IMAGE_FILE_HEADER) +
                                           fh->SizeOfOptionalHeader);

    for (i = 0; i < fh->NumberOfSections; i++, sh++) {
        if (!memcmp(name, sh->Name, length)) {
            text = (void*)((uint8_t*)image_base + sh->VirtualAddress);
            if (size_out)
                *size_out = sh->Misc.VirtualSize;
            break;
        }
    }

    return text;
}

typedef struct _IMAGE_EXPORT_DIRECTORY32 {
    UINT32   Characteristics;
    UINT32   TimeDateStamp;
    UINT16   MajorVersion;
    UINT16   MinorVersion;
    UINT32   Name;
    UINT32   Base;
    UINT32   NumberOfFunctions;
    UINT32   NumberOfNames;
    UINT32   AddressOfFunctions;
    UINT32   AddressOfNames;
    UINT32   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY32, *PIMAGE_EXPORT_DIRECTORY32;

void *efi_get_pe_export(const char *name, void *image_base)
{
    IMAGE_EXPORT_DIRECTORY32 *ed;
    void *fptr = NULL;
    uint32_t *fnames, *faddrs;
    const char *fname;
    uint64_t faddr;
    uint32_t i;

    /* Locate the export section and export directory */
    ed = efi_get_pe_section(".edata", image_base, NULL);
    if (!ed) {
        printk("No export section found\n");
        return NULL;
    }

    fnames = (uint32_t*)calc_addr(image_base, ed->AddressOfNames);
    faddrs = (uint32_t*)calc_addr(image_base, ed->AddressOfFunctions);

    for (i = 0; i < ed->NumberOfNames; i++, fnames++, faddrs++) {
        fname = (const char*)calc_addr(image_base, *fnames);
        faddr = (uint64_t)calc_addr(image_base, *faddrs);

        if (!strcmp(fname, name)) {
            fptr = (void*)faddr;
            break;
        }
    }

    return fptr;
}

void efi_shutdown_system(uint32_t shutdown_type)
{
    switch (shutdown_type) {
    case TB_SHUTDOWN_S5:
        RT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    case TB_SHUTDOWN_REBOOT:
        RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
    defaut:
        ;
    };
}

/* Logging support */
static void atow_log(CHAR16 *dst, const char *src, uint32_t count)
{
    uint32_t i;
    char c;

    for (i = 0; i < count; i++, dst++, src++) {
        c = (*src & 0x7f);
        if (c == '\n') {
            *dst = L'\r';
            dst++;
        }
        *dst = c;
    }
}

void efi_puts(const char *s, unsigned int count)
{
    CHAR16 wbuf[2*TBOOT_LOGBUF_SIZE];

    memset(wbuf, 0, sizeof(CHAR16)*2*TBOOT_LOGBUF_SIZE);
    atow_log(wbuf, s, count);
    (void)ST->ConOut->OutputString(ST->ConOut, wbuf);
}

static uint64_t efi_device_path_size(EFI_DEVICE_PATH *dpath)
{
    EFI_DEVICE_PATH *tpath = dpath;

    while (!IsDevicePathEnd(tpath))
        tpath = NextDevicePathNode(tpath);

    return ((uint64_t)tpath - (uint64_t)dpath) + sizeof(EFI_DEVICE_PATH);
}

static EFI_DEVICE_PATH *efi_device_path_instance(EFI_DEVICE_PATH **dpath,
                                                 uint64_t         *size)
{
    EFI_DEVICE_PATH *spath = *dpath, *npath, *tpath = *dpath;

    if (!tpath)
        return NULL;

    for ( ; ; ) {
        npath = NextDevicePathNode(tpath);

        if (IsDevicePathEndType(tpath))
            break;

        tpath = npath;
    }

    if (DevicePathSubType(tpath) == END_ENTIRE_DEVICE_PATH_SUBTYPE)
        npath = NULL;

    *dpath = npath;

    if (size)
       *size = ((uint64_t)tpath) - ((uint64_t)spath);
    return spath;
}

static EFI_DEVICE_PATH *efi_append_device_path(EFI_DEVICE_PATH *dpath1,
                                               EFI_DEVICE_PATH *dpath2)
{
    EFI_STATUS       status = EFI_SUCCESS;
    uint64_t         size1, size2, inst = 0, size;
    EFI_DEVICE_PATH *tpath = dpath1, *ipath, *opath;
    uint8_t         *pos;

    size1 = efi_device_path_size(dpath1);
    size2 = efi_device_path_size(dpath2);

    while (efi_device_path_instance(&tpath, NULL))
        inst++;

    size = (size1 * inst) + size2;

    status = BS->AllocatePool(EfiLoaderData, size, (void**)&opath);
    if (EFI_ERROR(status))
        return NULL;

    pos = (uint8_t*)opath;
    ipath = efi_device_path_instance(&dpath1, &size);

    for ( ; ; ) {
        if (!ipath)
            break;

        memcpy(pos, ipath, size);
        pos += size;
        memcpy(pos, dpath2, size2);
        pos += size2;
        memcpy(pos, EfiEndInstanceDevicePath, sizeof(EFI_DEVICE_PATH));
        pos += sizeof(EFI_DEVICE_PATH);

        ipath = efi_device_path_instance(&dpath1, &size);
    }

    pos -= sizeof(EFI_DEVICE_PATH);
    memcpy(pos, EfiEndDevicePath, sizeof(EFI_DEVICE_PATH));

    return opath;
}

EFI_DEVICE_PATH *efi_get_device_path(const wchar_t *path, EFI_HANDLE parent)
{
    EFI_STATUS            status = EFI_SUCCESS;
    FILEPATH_DEVICE_PATH *file_path = NULL;
    EFI_DEVICE_PATH      *dev_path = NULL, *parent_path, *eo_path;
    uint64_t              size = wcslen(path)*sizeof(wchar_t);

    status = BS->AllocatePool(EfiLoaderData,
                              size + SIZE_OF_FILEPATH_DEVICE_PATH + sizeof(EFI_DEVICE_PATH),
                              (void**)&file_path);
    if (EFI_ERROR(status))
        return NULL;

    status = BS->HandleProtocol(parent, &DevicePathProtocol, (void**)&parent_path);
    if (EFI_ERROR(status)) {
        BS->FreePool(file_path);
        return NULL;
    }

    file_path->Header.Type = MEDIA_DEVICE_PATH;
    file_path->Header.SubType = MEDIA_FILEPATH_DP;
    SetDevicePathNodeLength(&file_path->Header, size + SIZE_OF_FILEPATH_DEVICE_PATH);
    memcpy(file_path->PathName, path, size);
    eo_path = NextDevicePathNode(&file_path->Header);
    SetDevicePathEndNode(eo_path);

    dev_path = efi_append_device_path(parent_path, (EFI_DEVICE_PATH*)file_path);
    BS->FreePool(file_path);

    return dev_path;
}

EFI_STATUS efi_device_path_to_text(EFI_DEVICE_PATH *dev_path,
                                   wchar_t *path_out,
                                   uint64_t count)
{
#define size_needed(d) (DevicePathNodeLength(d) - \
            (sizeof(EFI_DEVICE_PATH) - sizeof(wchar_t)))
#define copy_size(d) (DevicePathNodeLength(d) - sizeof(EFI_DEVICE_PATH))
    EFI_STATUS            status = EFI_SUCCESS;
    FILEPATH_DEVICE_PATH *file_path;
    uint64_t              size = count*sizeof(wchar_t);

    while (DevicePathType(dev_path) != END_DEVICE_PATH_TYPE) {
        /* Space check first */
        if (size < size_needed(dev_path))
            return EFI_BUFFER_TOO_SMALL;

        /* Copy in latest bits of the path */
        file_path = (FILEPATH_DEVICE_PATH*)dev_path;
        memcpy(path_out, file_path->PathName, copy_size(dev_path));
        path_out[copy_size(dev_path)/sizeof(wchar_t)] = 0;
        dev_path = (EFI_DEVICE_PATH*)((uint64_t)dev_path +
                        DevicePathNodeLength(dev_path));
    }

    return EFI_SUCCESS;
}

EFI_FILE_INFO *efi_get_file_info(EFI_FILE *target_file,
                                 EFI_MEMORY_TYPE mem_type)
{
    EFI_STATUS  status;
    void       *buffer = NULL;
    UINTN       size = SIZE_OF_EFI_FILE_INFO + 256;
    uint32_t    i;

    for (i = 0; i < 2; i++) {
        status = BS->AllocatePool(mem_type, size, &buffer);
        if (!buffer)
            return NULL;

        status = target_file->GetInfo(target_file,
                                      &GenericFileInfo,
                                      &size,
                                      buffer);
        if (EFI_ERROR(status)) {
            BS->FreePool(buffer);
            buffer = NULL;
            if (status != EFI_BUFFER_TOO_SMALL)
                return NULL;
            continue;
        }
        break;
    }

    return buffer;
}

EFI_STATUS efi_read_file(EFI_FILE_IO_INTERFACE *file_system,
                         wchar_t *file_name,
                         EFI_MEMORY_TYPE mem_type,
                         uint64_t *size_out,
                         EFI_PHYSICAL_ADDRESS *addr_out)
{
    EFI_FILE             *root_file = NULL;
    EFI_FILE             *target_file = NULL;
    EFI_FILE_INFO        *file_info;
    EFI_STATUS            status = EFI_SUCCESS;
    uint64_t              size;
    EFI_PHYSICAL_ADDRESS  addr = TBOOT_MAX_IMAGE_MEM;
    char                 *print_name = wtoa_alloc(file_name);

    *size_out = 0;
    *addr_out = 0;

    status = file_system->OpenVolume(file_system, &root_file);
    if (EFI_ERROR(status)) {
        printk("Failed to open root File handle - status: %d\n", status);
        goto out;
    }

    status = root_file->Open(root_file,
                             &target_file,
                             file_name,
                             EFI_FILE_MODE_READ,
                             EFI_FILE_READ_ONLY);
    if (EFI_ERROR(status)) {
        printk("Failed to open file %s - status: %d\n", print_name, status);
        goto out;
    }

    status = target_file->SetPosition(target_file, 0);
    if (EFI_ERROR(status)) {
        printk("Failed to seek 0 file %s - status: %d\n", print_name, status);
        goto out;
    }

    file_info = efi_get_file_info(target_file, mem_type);
    if (!file_info) {
        printk("Failed to get file %s information\n", print_name);
        status = EFI_OUT_OF_RESOURCES;
        goto out;
    }
    size = file_info->FileSize;
    BS->FreePool(file_info);

    status = BS->AllocatePages(AllocateMaxAddress,
                               mem_type,
                               PFN_UP(size),
                               &addr);
    if (EFI_ERROR(status)) {
        printk("Failed to allocate buffer to read file %s\n", print_name);
        status = EFI_OUT_OF_RESOURCES;
        goto out;
    }

    status = target_file->Read(target_file, &size, (void*)addr);
    if (EFI_ERROR(status)) {
        printk("Failed to read file %s\n", print_name);
        BS->FreePages(addr, PFN_UP(size));
        goto out;
    }

    *size_out = size;
    *addr_out = addr;

out:
    if (target_file)
        target_file->Close(target_file);

    if (root_file)
        root_file->Close(root_file);

    if (print_name)
        BS->FreePool(print_name);

    return status;
}
