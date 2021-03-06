/*
 * efiboot.c: EFI boot entry, early relocation and load code.
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
#include <string.h>
#include <stdbool.h>
#include <misc.h>
#include <page.h>
#include <printk.h>
#include <eficore.h>
#include <eficonfig.h>
#include <uuid.h>
#include <hash.h>
#include <mle.h>
#include <txt/acmod.h>
#include <tb_error.h>
#include <tboot.h>

static EFI_HANDLE       parent_image_handle;
static EFI_HANDLE       parent_device_handle;
static EFI_DEVICE_PATH *device_path;
static void            *init_base; /* before reloc */
static uint64_t         init_size; /* original size */

static EFI_FILE_IO_INTERFACE *efi_file_system = NULL;

/* Store raw config files in MLE so they can be measured */
static __text uint8_t tboot_config_file[EFI_MAX_CONFIG_FILE];
static __text uint8_t xen_config_file[EFI_MAX_CONFIG_FILE];

/* Store parsed  config files in the data section */
static __data uint8_t tboot_parsed_config_file[EFI_MAX_CONFIG_FILE];
static __data uint8_t xen_parsed_config_file[EFI_MAX_CONFIG_FILE];

#ifdef EFI_DEBUG
static void efi_debug_pause(void)
{
    EFI_STATUS    status;
    EFI_INPUT_KEY key;

    ST->ConIn->Reset(ST->ConIn, FALSE);
    while ((status = ST->ConIn->ReadKeyStroke(ST->ConIn, &key)) == EFI_NOT_READY);
}

static void efi_debug_print_i(void)
{
    printk("EFI init:\n");
    printk("  parent_image_handle  = %p\n", parent_image_handle);
    printk("  parent_device_handle = %p\n", parent_device_handle);
    printk("  device_path          = %p\n", device_path);
    printk("  init_base            = %p\n", init_base);
    printk("  init_size            = %x\n", (uint32_t)init_size);

    efi_debug_pause();
}

static void efi_begin_launch(efi_xen_tboot_data_t *xtd);

static void efi_debug_print_v(efi_tboot_xen_var_t *v)
{
    printk("EFI shared variable:\n");
    printk("  revision        = %llx\n", v->revision);
    printk("  xen_config      = %p\n", v->xen_config);
    printk("  xen_config_size = %llx\n", v->xen_config_size);
    printk("  begin_launch_cb = %llx\n", v->begin_launch_cb);
    printk("  begin_launch    = %p\n", efi_begin_launch);

    efi_debug_pause();
}

static void efi_debug_print_w(const char *pfx, const wchar_t *wstr)
{
    char *p = wtoa_alloc(wstr);
    printk("%s %s\n", pfx, p);
    BS->FreePool(p);
}

#define efi_debug_print_s(p, s) printk("%s %s\n", p, s)

#else
#define efi_debug_pause()
#define efi_debug_print_i()
#define efi_debug_print_v(s)
#define efi_debug_print_w(p, w)
#define efi_debug_print_s(p, s)
#endif

static EFI_STATUS efi_start_next_image(const wchar_t *path)
{
    EFI_STATUS        status = EFI_SUCCESS;
    EFI_DEVICE_PATH  *dev_path = NULL;
    EFI_HANDLE        image_handle = NULL;
    EFI_LOADED_IMAGE *loaded_image;

    dev_path = efi_get_device_path(path, parent_device_handle);
    if (dev_path == NULL) {
        char *p = wtoa_alloc(path);
        printk("Failed to get device path for file %s\n", p);
        BS->FreePool(p);
        return EFI_INVALID_PARAMETER;
    }

    status = BS->LoadImage(FALSE,
                           parent_image_handle,
                           dev_path,
                           NULL,
                           0,
                           &image_handle);
    if (EFI_ERROR(status)) {
        printk("Failed to load image - status: %d\n", status);
        goto out;
    }

    status = BS->HandleProtocol(image_handle,
                                &LoadedImageProtocol,
                                (VOID*)&loaded_image);
    if (EFI_ERROR(status)) {
        printk("Failed to get loaded image info - status: %d\n", status);
        goto out;
    }

    /* TODO need to save the loaded image values to measure */

    status = BS->StartImage(image_handle, NULL, NULL);
    if (EFI_ERROR(status))
        printk("Failed to start image - status: %d\n", status);

out:
    BS->FreePool(dev_path);
    return status;
}

void efi_launch_kernel(void)
{
    EFI_STATUS  status;
    wchar_t    *file_path;
    efi_file_t *cfg = efi_get_file(EFI_FILE_TBOOT_CONFIG_PARSED);

    file_path = atow_alloc(efi_cfg_get_value(cfg, SECTION_TBOOT, ITEM_XENPATH));
    if (!file_path) {
        printk("Failed to allocate buffer for Xen file\n");
        status = EFI_OUT_OF_RESOURCES;
        goto out;
    }

    status = efi_start_next_image(file_path);
    /* If we are still here then someting failed anyway */
out:
    ST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_OUT_OF_RESOURCES, 0, NULL);
}

bool efi_verify_and_restore(uint64_t mle_base)
{
    efi_file_t *discard = efi_get_file(EFI_FILE_INVALID);
    efi_file_t *file;
    uint64_t    size;

    /* Discard the config files that are no longer used post launch */
    memset(discard, 0, sizeof(efi_file_t)*EFI_FILE_DISCARD_MARKER);

    /*
     * The MLE size is stored in the .text section and was measured. All
     * of the MLE page tables and layout including the MLE entry point was
     * validated in launch.S. Since the MLE entry point is known to be good
     * then the 64b page tables in CR3 are correct also.
     *
     * The MLE base passed here from the post launch code in launch.S was
     * validated there. This is our known good starting point. We can validate
     * the rest of the memory layout that we care about which is the TBOOT
     * shared area and that the config files are in the MLE (where they were
     * measured too).
     */
    printk(TBOOT_INFO"Post launch physical MLE base: %llx\n", mle_base);

    /* Validate the config files point to the right locations in the MLE */
    file = efi_get_file(EFI_FILE_TBOOT_CONFIG);
    if ((file->size > EFI_MAX_CONFIG_FILE)||
        (file->u.base != tboot_config_file)) {
        printk(TBOOT_ERR"Invalid TBOOT config location or size,"
               "expected: %p (<= %llx) reported: %p (%llx)\n",
               tboot_config_file, EFI_MAX_CONFIG_FILE, file->u.base, file->size);
        return false;
    }

    /* Reload and reparse the TBOOT config */
    size = file->size;
    memcpy(tboot_parsed_config_file, tboot_config_file, size);
    file = efi_get_file(EFI_FILE_TBOOT_CONFIG_PARSED);
    file->u.base = tboot_parsed_config_file;
    file->size = size;
    efi_cfg_pre_parse(file);

    file = efi_get_file(EFI_FILE_XEN_CONFIG);
    if ((file->size > EFI_MAX_CONFIG_FILE)||
        (file->u.base != xen_config_file)) {
        printk(TBOOT_ERR"Invalid Xen config location or size,"
               "expected: %p (<= %llx) reported: %p (%llx)\n",
               xen_config_file, EFI_MAX_CONFIG_FILE, file->u.base, file->size);
        return false;
    }

    /* Reload and reparse the Xen config */
    size = file->size;
    memcpy(xen_parsed_config_file, xen_config_file, size);
    file = efi_get_file(EFI_FILE_XEN_CONFIG_PARSED);
    file->u.base = xen_parsed_config_file;
    file->size = size;
    efi_cfg_pre_parse(file);

    /* Validate TBOOT shared values and set pointers */
    file = efi_get_file(EFI_FILE_TBSHARED);
    if ((file->size != TBOOT_TBSHARED_SIZE)||
        (file->u.addr != (mle_base - 3*PAGE_SIZE))) {
        printk(TBOOT_ERR"Invalid tbshared location or size,"
               "expected: %llx (%llx) reported: %llx (%llx)\n",
               (mle_base - 3*PAGE_SIZE), TBOOT_TBSHARED_SIZE,
               file->u.addr, file->size);
        return false;
    }

    memset(file->u.base, 0, file->size);
    _tboot_shared = (tboot_shared_t*)file->u.base;

    /* TODO final mem map on 2nd shared page? */

    /* TODO validate other locations */

    return true;
}

static void efi_begin_launch(efi_xen_tboot_data_t *xtd)
{
    efi_set_postebs();
    begin_launch(xtd);
}

static EFI_STATUS efi_setup_tboot_xen_var(void)
{
    EFI_STATUS          status = EFI_SUCCESS;
    efi_tboot_xen_var_t var;
    efi_file_t *cfg = efi_get_file(EFI_FILE_XEN_CONFIG);

    memset(&var, 0, sizeof(efi_tboot_xen_var_t));
    var.revision = EFI_TBOOT_XEN_REV;
    var.begin_launch_cb = (uint64_t)efi_begin_launch;
    var.xen_config = cfg->u.base;
    var.xen_config_size = cfg->size;

    status = RT->SetVariable(EFI_TBOOT_XEN_NAME,
                             &TbootXenGuid,
                             EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS,
                             sizeof(efi_tboot_xen_var_t),
                             &var);
    if (EFI_ERROR(status))
        printk("Failed to set shared RT variable - status: %d\n", status);

    efi_debug_print_v(&var);

    return status;
}

static bool efi_is_platform_sinit_module(wchar_t *file_path,
                                         efi_file_t *file_out)
{
    EFI_STATUS status;

    /* Read the TBOOT config into RT memory and store */
    status = efi_read_file(efi_file_system,
                           file_path,
                           EfiRuntimeServicesData,
                           &file_out->size,
                           &file_out->u.addr);
    if (EFI_ERROR(status)) {
        printk("Failed to read ACM file - status: %d\n", status);
        return false;
    }

    if (is_sinit_acmod(file_out->u.base, file_out->size, true) &&
        does_acmod_match_platform((acm_hdr_t*)file_out->u.base)) {
        printk(TBOOT_DETA"SINIT matches platform\n");
        return true;
    }

    BS->FreePages(file_out->u.addr, PFN_UP(file_out->size));
    file_out->u.addr = 0;
    file_out->size = 0;

    return false;
}

bool efi_load_txt_files(void)
{
    int         key;
    char        keystr[16];
    const char *value;
    wchar_t    *file_path;
    uint32_t    size;
    efi_file_t *sinit_file = efi_get_file(EFI_FILE_PLATFORM_SINIT);
    efi_file_t *cfg = efi_get_file(EFI_FILE_TBOOT_CONFIG_PARSED);

    /* TODO we don't have any RACMs right now so kick the can down the road... */
    /* TODO we don't use an LCP so kick the can down the road... */

    for (key = 0; ; key++) {
        snprintf(keystr, 16, "%d", key);
        value = efi_cfg_get_value(cfg, SECTION_ACM, keystr);
        if (!value)
            break;

        file_path = atow_cat(efi_get_tboot_path(), value);
        if (!file_path) {
            printk("Failed to allocate buffer for ACM file name\n");
            goto err;
        }

        efi_debug_print_w("ACM:", file_path);

        /* Found one */
        if (efi_is_platform_sinit_module(file_path, sinit_file)) {
            BS->FreePool(file_path);
            break;
        }

        BS->FreePool(file_path);
    }

    if (!sinit_file->u.base) {
        printk(TBOOT_ERR"no SINIT AC module found\n");
        goto err;
    }

    return true;
err:
    return false;
}

static void efi_form_config_path(wchar_t *path)
{
    wchar_t *ptr = path + wcslen(path);

    efi_debug_print_w("IMAGE PATH:", path);

    /* Form the config file path */
    while (ptr >= path) {
        if (*ptr == L'.') {
            memcpy((ptr + 1), L"cfg\0", 8);
            break;
        }
        ptr--;
    }

    efi_debug_print_w("CONFIG PATH:", path);
}

static EFI_STATUS efi_load_configs(void)
{
    EFI_STATUS            status;
    wchar_t              *file_path = NULL;
    EFI_PHYSICAL_ADDRESS  addr = TBOOT_MAX_IMAGE_MEM;
    void                 *buffer = NULL;
    uint64_t              size;
    efi_file_t           *cfg;

    /* Get file path for TBOOT image and config */
    status = BS->AllocatePool(EfiLoaderData,
                              (EFI_MAX_PATH + 4)*sizeof(wchar_t),
                              (void**)&file_path);
    if (EFI_ERROR(status)) {
        printk("Failed to alloc image path buffer - status: %d\n", status);
        return status;
    }

    status = efi_device_path_to_text(device_path,
                                     file_path,
                                     EFI_MAX_PATH);
    if (EFI_ERROR(status)) {
        printk("Failed to get TBOOT config path - status: %d\n", status);
        goto err;
    }

    /* Save a copy of the TBOOT dir for later */
    if (!efi_cfg_copy_tboot_path(file_path)) {
        status = EFI_INVALID_PARAMETER;
        printk("Failed to save TBOOT path - status: %d\n", status);
        goto err;
    }

    efi_form_config_path(file_path);
 
    /* Read the TBOOT config into RT memory and store */
    status = efi_read_file(efi_file_system,
                           file_path,
                           EfiRuntimeServicesData,
                           &size,
                           &addr);
    if (EFI_ERROR(status)) {
        printk("Failed to read TBOOT config file - status: %d\n", status);
        goto err;
    }

    if (size > EFI_MAX_CONFIG_FILE) {
        status = EFI_INVALID_PARAMETER;
        printk("TBOOT config file too big - size: %d\n", size);
        BS->FreePool((void*)addr);
        goto err;
    }

    /* Make a copy of the raw TBOOT config in the MLE */
    memcpy(tboot_config_file, (void*)addr, size);
    cfg = efi_get_file(EFI_FILE_TBOOT_CONFIG);
    cfg->u.base = tboot_config_file;
    cfg->size = size;

    /* Make a copy of the parsed TBOOT config in .data */
    memcpy(tboot_parsed_config_file, (void*)addr, size);
    cfg = efi_get_file(EFI_FILE_TBOOT_CONFIG_PARSED);
    cfg->u.base = tboot_parsed_config_file;
    cfg->size = size;
    efi_cfg_pre_parse(cfg);

    BS->FreePool((void*)addr);
    BS->FreePool(file_path);

    /* Get file path for Xen image and config */
    /* TODO use efi_cfg_copy_home_dir from plan-b */
    file_path = atow_alloc(efi_cfg_get_value(cfg, SECTION_TBOOT, ITEM_XENPATH));
    if (!file_path) {
        printk("Failed to allocate buffer for Xen config file\n");
        status = EFI_OUT_OF_RESOURCES;
        goto err;
    }

    efi_form_config_path(file_path);

    /* Read the Xen config (non-modified) into RT memory and store */
    status = efi_read_file(efi_file_system,
                           file_path,
                           EfiRuntimeServicesData,
                           &size,
                           &addr);
    if (EFI_ERROR(status)) {
        printk("Failed to read Xen config file - status: %d\n", status);
        goto err;
    }

    if (size > EFI_MAX_CONFIG_FILE) {
        status = EFI_INVALID_PARAMETER;
        printk("Xen config file too big - size: %d\n", size);
        BS->FreePool((void*)addr);
        goto err;
    }

    /* Make a copy of the raw Xen config in the MLE */
    memcpy(xen_config_file, (void*)addr, size);
    cfg = efi_get_file(EFI_FILE_XEN_CONFIG);
    cfg->u.base = xen_config_file;
    cfg->size = size;

    /* Make a copy of the parsed Xen config in .data */
    memcpy(xen_parsed_config_file, (void*)addr, size);
    cfg = efi_get_file(EFI_FILE_XEN_CONFIG_PARSED);
    cfg->u.base = xen_parsed_config_file;
    cfg->size = size;
    efi_cfg_pre_parse(cfg);

    BS->FreePool((void*)addr);
    BS->FreePool(file_path);

    /* Locate and split off the kernel cmdline */
    if (!efi_split_kernel_line()) {
        printk("Failed to parse and find kernel entry in Xen config\n");
        status = EFI_INVALID_PARAMETER;
        goto err;
    }
    efi_debug_print_s("KERNEL CMDLINE:", efi_get_kernel_cmdline());

    return EFI_SUCCESS;

err:
    /* TODO the cleanup in plan-b is wrong here + missing BS->FreePool((void*)addr) in errors above */
    if (file_path)
        BS->FreePool(file_path);

    return status;
}

static bool efi_setup_memory_blocks(void)
{
    efi_file_t *rtmem = efi_get_file(EFI_FILE_RTMEM);
    efi_file_t *tbshared = efi_get_file(EFI_FILE_TBSHARED);
    efi_memmap_t *memmap = efi_get_memmap(true);

    if (sizeof(tboot_shared_t) > PAGE_SIZE) {
        printk("Shared TBOOT information greater than PAGE_SIZE! 0x%x\n",
               sizeof(tboot_shared_t));
        return false;
    }

    tbshared->u.base = rtmem->u.base + TBOOT_PLEPT_SIZE + TBOOT_MLEPT_SIZE;
    tbshared->size = TBOOT_TBSHARED_SIZE;

    /* This is where the final mem map will live */
    memmap->base = tbshared->u.base + PAGE_SIZE;
    memmap->size = PAGE_SIZE;

    return true;
}

EFI_STATUS efi_start(EFI_HANDLE ImageHandle,
                     EFI_SYSTEM_TABLE *SystemTable)
{
    efi_file_t *image = efi_get_file(EFI_FILE_IMAGE);
    efi_file_t *text = efi_get_file(EFI_FILE_IMAGE_TEXT);
    efi_file_t *bss = efi_get_file(EFI_FILE_IMAGE_BSS);
    EFI_STATUS status;

    printk("TBOOT START Entry Point: %p\n", efi_start);

    /* Open the file system for the boot partition once up front */
    status = BS->OpenProtocol(parent_device_handle,
                              &FileSystemProtocol,
                              (void**)&efi_file_system,
                              parent_image_handle,
                              NULL,
                              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (EFI_ERROR(status)) {
        printk("Failed to open FileSystemProtocol - status: %d\n", status);
        goto out;
    }

    /* Locate the .text section and length */
    text->u.base = efi_get_pe_section(".text", image->u.base,
                                     &text->size);
    if (text->u.base) {
        printk("Located .text section: %p size: %llx\n",
               text->u.base, text->size);
        /* Sanity check the location of the .text section in the image */
        if ((text->u.base - image->u.base) != PAGE_SIZE) {
            printk("The .text offset must be at 1 page into TBOOT image!\n");
            goto out;
        }
    }
    else {
        printk("Failed to locate .text section\n");
        status = EFI_INVALID_PARAMETER;
        goto out;
    }

    /* Locate the .bss section and length */
    bss->u.base = efi_get_pe_section(".bss", image->u.base,
                                     &bss->size);
    if (bss->u.base) {
        printk("Located .bss section: %p size: %llx\n",
               bss->u.base, bss->size);
    }
    else {
        printk("Failed to locate .text section\n");
        status = EFI_INVALID_PARAMETER;
        goto out;
    }

    /* Setup memory files */
    if (!efi_setup_memory_blocks())
        goto out;

    /* Load the configuration files and information */
    status = efi_load_configs();
    if (EFI_ERROR(status))
        goto out;

    /* Setup RT shared variable */
    status = efi_setup_tboot_xen_var();
    if (EFI_ERROR(status))
        goto out;

    /* Begin initial launch */
    begin_initial_launch();

    /* Start Xen here */
    efi_launch_kernel();

    /* SNO */
    printk("FATAL: could not launch Xen!\n");

out:
    efi_debug_pause();

    /* Should not reach here unless something failed */
    ST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);

    return EFI_SUCCESS;
}

static EFI_STATUS efi_reloc_and_call(void)
{
    EFI_STATUS           status;
    uint64_t             size;
    EFI_PHYSICAL_ADDRESS addr = TBOOT_MAX_IMAGE_MEM;
    uint64_t             efi_start_ptr;
    efi_file_t           *rtmem, *image;

    rtmem = efi_get_file(EFI_FILE_RTMEM);
    image = efi_get_file(EFI_FILE_IMAGE);

    image->size = init_size;

    status = BS->AllocatePages(AllocateMaxAddress,
                               EfiRuntimeServicesCode,
                               PFN_UP(image->size) + TBOOT_RTMEM_COUNT,
                               &addr);
    if (EFI_ERROR(status))
        return status;

    rtmem->u.addr = addr;
    image->u.addr = addr + TBOOT_RTMEM_SIZE;
    rtmem->size = image->size + TBOOT_RTMEM_SIZE;
    memset(rtmem->u.base, 0, rtmem->size);

    /* Copy me to new location */
    memcpy(image->u.base, init_base, image->size);

    efi_start_ptr = (uint64_t)image->u.base +
        ((uint64_t)efi_start - (uint64_t)init_base);

    /* End of the line */
    __asm__ __volatile__ (
                   "movq %0, %%rdx\n\t"
                   "movq %1, %%rcx\n\t"
                   "call *%%rax\n\t"
                   :
                   : "g" (ST), "g" (parent_image_handle), "a" (efi_start_ptr));

    return EFI_LOAD_ERROR; /* SNO! */
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle,
                    EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS        status;
    EFI_LOADED_IMAGE *loaded_image;

    /* Store the system table for future use in other functions */
    ST = SystemTable;
    BS = ST->BootServices;
    RT = ST->RuntimeServices;

    /* So we can use printk via EFI console protocol */
    printk_init(INIT_EARLY_EFI);
    printk("TBOOT EFI Entry Point: %p\n", efi_main);

    efi_cfg_init();

    status = BS->HandleProtocol(ImageHandle,
                                &LoadedImageProtocol,
                                (VOID*)&loaded_image);

    if (!EFI_ERROR(status)) {
        /* Device we were loaded from, EFI partition */
        parent_device_handle = loaded_image->DeviceHandle;
        device_path = loaded_image->FilePath;
        init_base = loaded_image->ImageBase;
        init_size = loaded_image->ImageSize;
        parent_image_handle = ImageHandle;
    }
    else {
        printk("TBOOT FATAL! Cannot get loaded image information\n");
        ST->RuntimeServices->ResetSystem(EfiResetShutdown, status, 0, NULL);
    }

    efi_debug_print_i();

    /* Relocate this image and call, never return */
    status = efi_reloc_and_call();

    /* Should not be here! */
    printk("TBOOT FATAL! relocate and call failed - status: %x\n", status);
    ST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);

    return status;
}
