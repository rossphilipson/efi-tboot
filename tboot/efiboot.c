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

static EFI_HANDLE       g_image_handle;
static EFI_HANDLE       g_device_handle;
static EFI_DEVICE_PATH *g_device_path;
static void            *g_init_base;  /* before reloc */
       void            *g_image_base; /* after reloc */
       void            *g_rtmem_base; /* base of TBOOT runtime memory */
       uint64_t         g_image_size;
       void            *g_text_base;
       uint64_t         g_text_size;
       void            *g_bss_base;
       uint64_t         g_bss_size;

static efi_file_t            *g_configs;
static EFI_FILE_IO_INTERFACE *g_file_system = NULL;

/* Store raw config files in MLE so they can be measured */
static __text uint8_t g_tboot_config_file[EFI_MAX_CONFIG_FILE];
static __text uint8_t g_xen_config_file[EFI_MAX_CONFIG_FILE];

#ifdef EFI_DEBUG
static void efi_debug_pause(void)
{
    EFI_STATUS    status;
    EFI_INPUT_KEY key;

    ST->ConIn->Reset(ST->ConIn, FALSE);
    while ((status = ST->ConIn->ReadKeyStroke(ST->ConIn, &key)) == EFI_NOT_READY);
}

static void efi_debug_print_g(void)
{
    printk("EFI global:\n");
    printk("  g_image_handle  = %p\n", g_image_handle);
    printk("  g_device_handle = %p\n", g_device_handle);
    printk("  g_device_path   = %p\n", g_device_path);
    printk("  g_init_base     = %p\n", g_init_base);
    printk("  g_image_base    = %p\n", g_image_base);
    printk("  g_rtmem_base    = %p\n", g_rtmem_base);
    printk("  g_image_size    = %x\n", (uint32_t)g_image_size);

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
#define efi_debug_print_g()
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

    dev_path = efi_get_device_path(path, g_device_handle);
    if (dev_path == NULL) {
        char *p = wtoa_alloc(path);
        printk("Failed to get device path for file %s\n", p);
        BS->FreePool(p);
        return EFI_INVALID_PARAMETER;
    }

    status = BS->LoadImage(FALSE,
                           g_image_handle,
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
    efi_store_xen_info(loaded_image->ImageBase, loaded_image->ImageSize);

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

    file_path = atow_alloc(efi_cfg_get_value(EFI_CONFIG_TBOOT_PARSED,
                                             SECTION_TBOOT, ITEM_XENPATH));
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

static void efi_begin_launch(efi_xen_tboot_data_t *xtd)
{
    g_post_ebs = true;
    begin_launch(xtd);
}

static EFI_STATUS efi_setup_tboot_xen_var(void)
{
    EFI_STATUS          status = EFI_SUCCESS;
    efi_tboot_xen_var_t var;

    memset(&var, 0, sizeof(efi_tboot_xen_var_t));
    var.revision = EFI_TBOOT_XEN_REV;
    var.begin_launch_cb = (uint64_t)efi_begin_launch;
    var.xen_config = g_configs[EFI_CONFIG_XEN].u.buffer;
    var.xen_config_size = g_configs[EFI_CONFIG_XEN].size;

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
    status = efi_read_file(g_file_system,
                           file_path,
                           EfiRuntimeServicesData,
                           &file_out->size,
                           &file_out->u.addr);
    if (EFI_ERROR(status)) {
        printk("Failed to read ACM file - status: %d\n", status);
        return false;
    }

    if (is_sinit_acmod(file_out->u.buffer, file_out->size, true) &&
        does_acmod_match_platform((acm_hdr_t*)file_out->u.buffer)) {
        printk(TBOOT_DETA"SINIT matches platform\n");
        return true;
    }

    BS->FreePages(file_out->u.addr, PFN_UP(file_out->size));
    file_out->u.addr = 0;
    file_out->size = 0;

    return false;
}

static EFI_STATUS efi_load_core_files(void)
{
    EFI_STATUS  status = EFI_SUCCESS;
    int         key;
    char        keystr[16];
    const char *value;
    wchar_t    *file_path;
    uint32_t    size;
    efi_file_t  sinit_file = {0, 0};

    /* TODO we don't have any RACMs right now so kick the can down the road... */
    /* TODO we don't use an LCP so kick the can down the road... */

    for (key = 0; ; key++) {
        snprintf(keystr, 16, "%d", key);
        value = efi_cfg_get_value(EFI_CONFIG_TBOOT_PARSED,
                                  SECTION_ACM, keystr);
        if (!value)
            break;

        file_path = atow_cat(g_tboot_dir, value);
        if (!file_path) {
            printk("Failed to allocate buffer for ACM file name\n");
            status = EFI_OUT_OF_RESOURCES;
            goto out;
        }

        efi_debug_print_w("ACM:", file_path);

        /* Found one */
        if (efi_is_platform_sinit_module(file_path, &sinit_file)) {
            BS->FreePool(file_path);
            break;
        }

        BS->FreePool(file_path);

        /* Errors not fatal but the config likely includes missing files */
    }

    if (!sinit_file.u.buffer) {
        printk(TBOOT_ERR"no SINIT AC module found\n");
        return EFI_INVALID_PARAMETER;
    }

    /* Set the files we found */
    efi_store_files(&sinit_file, NULL, NULL);
out:
    return status;
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
    EFI_STATUS             status;
    wchar_t               *file_path = NULL;
    EFI_PHYSICAL_ADDRESS   addr = TBOOT_MAX_IMAGE_MEM;
    void                  *buffer = NULL;
    uint64_t               size;

    /* Get file path for TBOOT image and config */
    status = BS->AllocatePool(EfiLoaderData,
                              (EFI_MAX_PATH + 4)*sizeof(wchar_t),
                              (void**)&file_path);
    if (EFI_ERROR(status)) {
        printk("Failed to alloc image path buffer - status: %d\n", status);
        return status;
    }

    status = efi_device_path_to_text(g_device_path,
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
    status = efi_read_file(g_file_system,
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
        goto err;
    }

    /* Make a copy of the raw TBOOT config in the MLE */
    memcpy(g_tboot_config_file, (void*)addr, size);
    g_configs[EFI_CONFIG_TBOOT].u.buffer = g_tboot_config_file;
    g_configs[EFI_CONFIG_TBOOT].size = size;

    /* Parse original */
    g_configs[EFI_CONFIG_TBOOT_PARSED].u.addr = addr;
    g_configs[EFI_CONFIG_TBOOT_PARSED].size = size;
    efi_cfg_pre_parse(&g_configs[EFI_CONFIG_TBOOT_PARSED]);
    BS->FreePool(file_path);

    /* Get file path for Xen image and config */
    file_path = atow_alloc(efi_cfg_get_value(EFI_CONFIG_TBOOT_PARSED,
                                             SECTION_TBOOT, ITEM_XENPATH));
    if (!file_path) {
        printk("Failed to allocate buffer for Xen config file\n");
        status = EFI_OUT_OF_RESOURCES;
        goto err;
    }

    efi_form_config_path(file_path);

    /* Read the Xen config (non-modified) into RT memory and store */
    status = efi_read_file(g_file_system,
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
        goto err;
    }

    /* Make a copy of the raw Xen config in the MLE */
    memcpy(g_xen_config_file, (void*)addr, size);
    g_configs[EFI_CONFIG_XEN].u.buffer = g_xen_config_file;
    g_configs[EFI_CONFIG_XEN].size = size;

    /* Parse original */
    g_configs[EFI_CONFIG_XEN_PARSED].u.addr = addr;
    g_configs[EFI_CONFIG_XEN_PARSED].size = size;
    efi_cfg_pre_parse(&g_configs[EFI_CONFIG_XEN_PARSED]);
    BS->FreePool(file_path);

    /* Locate and split off the kernel cmdline */
    if (!efi_split_kernel_line()) {
        printk("Failed to parse and find kernel entry in Xen config\n");
        status = EFI_INVALID_PARAMETER;
        goto err;
    }
    efi_debug_print_s("KERNEL CMDLINE:", g_kernel_cmdline);

    return EFI_SUCCESS;

err:
    if (g_configs[EFI_CONFIG_XEN].u.buffer)
        BS->FreePages(g_configs[EFI_CONFIG_XEN].u.addr,
                      PFN_UP(g_configs[EFI_CONFIG_XEN].size));
    if (g_configs[EFI_CONFIG_TBOOT].u.buffer)
        BS->FreePages(g_configs[EFI_CONFIG_TBOOT].u.addr,
                      PFN_UP(g_configs[EFI_CONFIG_TBOOT].size));

    if (file_path)
        BS->FreePool(file_path);

    return status;
}

EFI_STATUS efi_start(EFI_HANDLE ImageHandle,
                     EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;

    printk("TBOOT START Entry Point: %p\n", efi_start);
    efi_debug_print_g();

    /* Open the file system for the boot partition once up front */
    status = BS->OpenProtocol(g_device_handle, 
                              &FileSystemProtocol,
                              (void**)&g_file_system,
                              g_image_handle,
                              NULL,
                              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (EFI_ERROR(status)) {
        printk("Failed to open FileSystemProtocol - status: %d\n", status);
        goto out;
    }

    efi_cfg_init();
    g_configs = efi_get_configs();

    /* Locate the .text section and length */
    g_text_base = efi_get_pe_section(".text", g_image_base,
                                     &g_text_size);
    if (g_text_base) {
        printk("Located .text section: %p size: %llx\n",
               g_text_base, g_text_size);
        /* Sanity check the location of the .text section in the image */
        if ((g_text_base - g_image_base) != PAGE_SIZE) {
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
    g_bss_base = efi_get_pe_section(".bss", g_image_base,
                                     &g_bss_size);
    if (g_bss_base) {
        printk("Located .bss section: %p size: %llx\n",
               g_bss_base, g_bss_size);
    }
    else {
        printk("Failed to locate .text section\n");
        status = EFI_INVALID_PARAMETER;
        goto out;
    }

    /* Load the configuration files and information */
    status = efi_load_configs();
    if (EFI_ERROR(status))
        goto out;

    /* Load the platform SINIT, RACM and LCP */
    status = efi_load_core_files();
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

    /*
     * TODO we may have to pick and force an address since right now we are at
     * the mercy of EFI picking a runtime service code range. If this ends up
     * outside the PMRs due to the crazy min_ram stuff then pain and misery
     * will ensue.
     */

    status = BS->AllocatePages(AllocateMaxAddress,
                               EfiRuntimeServicesCode,
                               PFN_UP(g_image_size) + TBOOT_RTMEM_COUNT,
                               &addr);
    if (EFI_ERROR(status))
        return status;

    g_rtmem_base = (void*)addr;
    g_image_base = (void*)(addr + TBOOT_RTMEM_SIZE);
    memset(g_rtmem_base, 0, g_image_size + TBOOT_RTMEM_SIZE);

    /* Copy me to new location */
    memcpy(g_image_base, g_init_base, g_image_size);

    efi_start_ptr = (uint64_t)g_image_base +
        ((uint64_t)efi_start - (uint64_t)g_init_base);

    /* End of the line */
    __asm__ __volatile__ (
                   "movq %0, %%rdx\n\t"
                   "movq %1, %%rcx\n\t"
                   "call *%%rax\n\t"
                   :
                   : "g" (ST), "g" (g_image_handle), "a" (efi_start_ptr));

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

    status = BS->HandleProtocol(ImageHandle,
                                &LoadedImageProtocol,
                                (VOID*)&loaded_image);

    if (!EFI_ERROR(status)) {
        /* Device we were loaded from, EFI partition */
        g_device_handle = loaded_image->DeviceHandle;
        g_device_path = loaded_image->FilePath;
        g_init_base = loaded_image->ImageBase;
        g_image_size = loaded_image->ImageSize;
        g_image_handle = ImageHandle;
    }
    else {
        printk("TBOOT FATAL! Cannot get loaded image information\n");
        ST->RuntimeServices->ResetSystem(EfiResetShutdown, status, 0, NULL);
    }

    efi_debug_print_g();

    /* Relocate this image and call, never return */
    status = efi_reloc_and_call();

    /* Should not be here! */
    printk("TBOOT FATAL! relocate and call failed - status: %x\n", status);
    ST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);

    return status;
}
