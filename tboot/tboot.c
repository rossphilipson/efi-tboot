/*
 * tboot.c: main entry point and "generic" routines for measured launch
 *          support
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Copyright (c) 2017 Assured Information Security.
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
 *
 */

#include <config.h>
#include <efibase.h>
#include <types.h>
#include <stdbool.h>
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <printk.h>
#include <uuid.h>
#include <misc.h>
#include <processor.h>
#include <cmdline.h>
#include <eficore.h>
#include <eficonfig.h>
#include <msr.h>
#include <atomic.h>
#include <hash.h>
#include <io.h>
#include <mutex.h>
#include <mle.h>
#include <tpm.h>
#include <tb_error.h>
#include <tb_policy.h>
#include <tboot.h>
#include <acpi.h>
#include <txt/acmod.h>
#include <txt/mtrrs.h>
#include <txt/vmcs.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#include <txt/verify.h>
#include <txt/txt.h>

/* counter timeout for waiting for all APs to exit guests */
#define AP_GUEST_EXIT_TIMEOUT     0x01000000

__data long s3_flag = 0;

/* MLE/kernel shared data structure */
tboot_shared_t *_tboot_shared;

#ifdef EFI_DEBUG
static void efi_debug_print_files(void)
{
    efi_file_t *rtmem = efi_get_file(EFI_FILE_RTMEM);
    efi_file_t *image = efi_get_file(EFI_FILE_IMAGE);
    efi_file_t *text = efi_get_file(EFI_FILE_IMAGE_TEXT);
    efi_file_t *bss = efi_get_file(EFI_FILE_IMAGE_BSS);

    printk("EFI files:\n");
    printk("  rtmem base  = %p\n", rtmem->u.base);
    printk("  rtmem sze   = %x\n", (uint32_t)rtmem->size);
    printk("  image base  = %p\n", image->u.base);
    printk("  image sze   = %x\n", (uint32_t)image->size);
    printk("  text base   = %p\n", text->u.base);
    printk("  text sze    = %x\n", (uint32_t)text->size);
    printk("  bss base    = %p\n", bss->u.base);
    printk("  bss sze     = %x\n", (uint32_t)bss->size);
}
#else
#define efi_debug_print_files()
#endif

static void store_section_sizes(void)
{
    efi_file_t *text = efi_get_file(EFI_FILE_IMAGE_TEXT);
    efi_file_t *bss = efi_get_file(EFI_FILE_IMAGE_BSS);
    uint64_t mle_start_ref;
    uint64_t mle_size_ref;
    uint64_t bss_start_ref;
    uint64_t bss_size_ref;

    /*
     * The _mle_start symbol is exactly at the beginning of the .text section.
     * The _bss_start symbol is exactly at the beginning of the .bss section.
     * The .text and .bss section sizes are gotten from the PE information but
     * for a given build, they will always be the same. So that means they can
     * be put in the MLE and measured.
     */

    lea_reference(_mle_start, mle_start_ref);
    lea_reference(_mle_size, mle_size_ref);
    lea_reference(_bss_start, bss_start_ref);
    lea_reference(_bss_size, bss_size_ref);

    if ((void*)mle_start_ref != text->u.base) {
        printk(TBOOT_ERR"_mle_start != text base\n");
        apply_policy(TB_ERR_FATAL);
    }

    *((uint64_t*)mle_size_ref) = text->size;
    printk(TBOOT_INFO"_mle_start: 0x%llx _mle_size: 0x%llx\n",
           mle_start_ref, *((uint64_t*)mle_size_ref));

    if ((void*)bss_start_ref != bss->u.base) {
        printk(TBOOT_ERR"_bss_start != bss base\n");
        apply_policy(TB_ERR_FATAL);
    }

    *((uint64_t*)bss_size_ref) = bss->size;
    printk(TBOOT_INFO"_bss_start: 0x%llx _bss_size: 0x%llx\n",
           bss_start_ref, *((uint64_t*)bss_size_ref));
}

static tb_error_t verify_platform(void)
{
    return txt_verify_platform();
}

static bool is_launched(void)
{
    if ( supports_txt() == TB_ERR_NONE )
        return txt_is_launched();
    else return false;
}

static bool prepare_cpu(void)
{
    return txt_prepare_cpu();
}

static void copy_s3_wakeup_entry(void)
{
    /* TODO deal with S3 later */
}

void cpu_wakeup(uint32_t cpuid, uint64_t sipi_vec)
{
    printk(TBOOT_INFO"cpu %u waking up, SIPI vector=%llx\n", cpuid, sipi_vec);

    /* change to real mode and then jump to SIPI vector */
    /* TODO _prot_to_real(sipi_vec); */
}

#define ICR_LOW 0x300

/*static*/ void startup_rlps(void)
{
    uint32_t rlp_count = ((cpuid_ecx(1) >> 16) & 0xff) - 1;
    uint64_t apicbase = rdmsr(MSR_APICBASE) & 0xfffffffffffff000;

    if ( rlp_count == 0 )
        return;

    /* send init ipi to all rlp -- Dest Shorthand: 11, Delivery Mode: 101 */
    writel(apicbase + ICR_LOW, 0xc0500);
}

void launch_racm(void)
{
    /* TODO this is gonna do GETSEC[ENTERACCS] */
    /* This means IA-32e */
}

static void shutdown_system(uint32_t);
void check_racm_result(void)
{
    txt_get_racm_error();
    shutdown_system(TB_SHUTDOWN_HALT);
}

void begin_initial_launch(void)
{
    const char *cmdline;
    acm_hdr_t *sinit;
    tb_error_t err;
    efi_file_t *cfg = efi_get_file(EFI_FILE_TBOOT_CONFIG_PARSED);
    const efi_file_t *sinit_file;

    /* always load cmdline defaults */
    tboot_parse_cmdline(true);

    /* on pre-SENTER boot, copy command line to buffer in tboot image
     * (so that it will be measured); buffer must be 0 -filled */
    if ( !is_launched() && !s3_flag ) {
        memset(g_cmdline, '\0', sizeof(g_cmdline));
        cmdline = efi_cfg_get_value(cfg, SECTION_TBOOT, ITEM_OPTIONS);
        if (cmdline)
            strncpy(g_cmdline, cmdline, sizeof(g_cmdline)-1);
    }

    /* always parse cmdline */
    tboot_parse_cmdline(false);

    /* initialize all logging targets */
    printk_init(INIT_PRE_LAUNCH);

    /* DEBUG */
    print_test_chars();

    printk(TBOOT_INFO"******************* TBOOT *******************\n");
    printk(TBOOT_INFO"   %s\n", TBOOT_CHANGESET);
    printk(TBOOT_INFO"*********************************************\n");

    printk(TBOOT_INFO"command line: %s\n", g_cmdline);

    /* DEBUG */
    print_system_values();

    efi_debug_print_files();

    /* Load the TXT platform SINIT, RACM and LCP */
    if ( !efi_load_txt_files() )
        apply_policy(TB_ERR_FATAL);

    /* if telled to check revocation acm result, go with simplified path */
    if ( get_tboot_call_racm_check() )
        check_racm_result(); /* never return */

    /* TODO if (is_launched()) printk(TBOOT_INFO"SINIT ACM successfully returned...\n");*/
    if ( s3_flag ) printk(TBOOT_INFO"Resume from S3...\n");

    /* clear resume vector on S3 resume so any resets will not use it */
    /* TODO if ( !is_launched() && s3_flag )        set_s3_resume_vector(&_tboot_shared->acpi_sinfo, 0);*/

    /* we should only be executing on the BSP */
    if ( !(rdmsr(MSR_APICBASE) & APICBASE_BSP) ) {
        printk(TBOOT_INFO"entry processor is not BSP\n");
        apply_policy(TB_ERR_FATAL);
    }
    printk(TBOOT_INFO"BSP is cpu %u\n", get_apicid());

    /*
     * TODO e820 copied here but TBOOT will not be using it. Xen will have to
     * do e820 fixup work and present it to dom0. We still need to read the
     * min_ram value from the config that used to happen in that call
     */
    get_tboot_min_ram();

    /* make TPM ready for measured launch */
    if (!tpm_detect())
        apply_policy(TB_ERR_TPM_NOT_READY);

    /* we need to make sure this is a (TXT-) capable platform before using */
    /* any of the features, incl. those required to check if the environment */
    /* has already been launched */

    if (!g_sinit) {
        sinit_file = efi_get_file(EFI_FILE_PLATFORM_SINIT);
        if (sinit_file->u.base == NULL)
            apply_policy(TB_ERR_SINIT_NOT_PRESENT);
        /* check if it is newer than BIOS provided version, then copy it to BIOS reserved region */
        g_sinit = copy_sinit((const acm_hdr_t*)sinit_file->u.base);
        if (g_sinit == NULL) 
            apply_policy(TB_ERR_SINIT_NOT_PRESENT);
        if (!verify_acmod(g_sinit)) 
            apply_policy(TB_ERR_ACMOD_VERIFY_FAILED);
    }
    test_virt_to_phys((uint64_t)g_sinit);

    /* read tboot verified launch control policy from TPM-NV (will use default if none in TPM-NV) */
    err = set_policy();
    apply_policy(err);

    /* if telled to call revocation acm, go with simplified path */
    if ( get_tboot_call_racm() )
        launch_racm(); /* never return */

    /* need to verify that platform supports TXT before we can check error */
    /* (this includes TPM support) */
    err = supports_txt();
    apply_policy(err);

    /* print any errors on last boot, which must be from TXT launch */
    txt_get_error();

    /* need to verify that platform can perform measured launch */
    err = verify_platform();
    apply_policy(err);

    /*
     * Check for modules was here but that is not how things work any longer.
     * Xen will load the other modules and have to tell us about them later.
     */

    /* prepare_cpu() will be done later */

    /* check for error from previous boot */
    printk(TBOOT_INFO"checking previous errors on the last boot.\n\t");
    if ( was_last_boot_error() )
        printk(TBOOT_INFO"last boot has error.\n");
    else
        printk(TBOOT_INFO"last boot has no error.\n");

    if ( !prepare_tpm() )
        apply_policy(TB_ERR_TPM_NOT_READY);

    /*
     * Some of the MLE bits can be setup early before we jump off to
     * the next gig. First setup the MLE header with offest relative to
     * where we are then build the MLE page tables. Also load RIP
     * relative addresses for VMCS structures.
     */
    txt_init_mle_header();

    if ( !txt_build_mle_pagetable() )
        apply_policy(TB_ERR_FATAL);

    store_section_sizes();

    /* This is the end of the line for the initial launch. It is time to start
     * Xen and transfer control. The actual SMX launch will be done in a
     * callback from Xen after EBS.
     */
}

void begin_launch(efi_xen_tboot_data_t *xtd)
{
    tb_error_t err;

    /* initialize post EBS logging targets - this must be done first */
    printk_init(INIT_POST_EBS);

    /* store kernel and ramdisk module information */
    if ( !efi_store_xen_tboot_data(xtd) )
        apply_policy(TB_ERR_FATAL);

    /* DEBUG */
    print_system_values();

    if ( !efi_scan_memory_map() )
        apply_policy(TB_ERR_FATAL);

    /* DEBUG */
    /*dump_page_tables();*/

    /* make the CPU ready for measured launch */
    if ( !prepare_cpu() )
        apply_policy(TB_ERR_FATAL);

    /* launch the measured environment */
    err = txt_launch_environment();
    apply_policy(err);

    /* TODO have to figure out how to return to Xen when we pop
     * out elsewhere. Save the ret addr and mock up the function
     * return.
     */
}

void post_launch(void)
{
    /* always load cmdline defaults */
    tboot_parse_cmdline(true);

    /* always parse cmdline */
    tboot_parse_cmdline(false);

    /* initialize all logging targets */
    printk_init(INIT_POST_LAUNCH);

    printk(TBOOT_INFO"******************** MLE ********************\n");
    printk(TBOOT_INFO"   %s\n", TBOOT_CHANGESET);
    printk(TBOOT_INFO"*********************************************\n");

    /* init the bits needed to run APs in mini-VMs */
    init_vmcs_addrs();

    /* TODO figure out how to have common pre/post/s3 launch code */

    /* TODO reparse and load configs stored in the MLE */

    /* TODO measure the memory map */

    /* TODO call efi_scan_memory_map again after measured launch to rebuild map */

    /* TODO pass Xen a new memory map after it has been reconciled w/ MDRs */

    /* TODO hash Xen sections before transferring control back to it (use special pre-ML sections?) */
}

void s3_launch(void)
{
    /* TODO deal with later */
}

static void shutdown_system(uint32_t shutdown_type)
{
    static const char *types[] = { "TB_SHUTDOWN_REBOOT", "TB_SHUTDOWN_S5",
                                   "TB_SHUTDOWN_S4", "TB_SHUTDOWN_S3",
                                   "TB_SHUTDOWN_HALT" };
    char type[32];

    if ( shutdown_type >= ARRAY_SIZE(types) )
        snprintf(type, sizeof(type), "unknown: %u", shutdown_type);
    else
        strncpy(type, types[shutdown_type], sizeof(type));
    printk(TBOOT_INFO"shutdown_system() called for shutdown_type: %s\n", type);

    switch( shutdown_type ) {
        case TB_SHUTDOWN_S3:
            copy_s3_wakeup_entry();
            /* write our S3 resume vector to ACPI resume addr */
            /* TODO handle S3 later set_s3_resume_vector(&_tboot_shared->acpi_sinfo,  TBOOT_S3_WAKEUP_ADDR);*/
            /* fall through for rest of Sx handling */
        case TB_SHUTDOWN_S4:
        case TB_SHUTDOWN_S5:
            machine_sleep(&_tboot_shared->acpi_sinfo);
            /* if machine_sleep() fails, fall through to reset */

        case TB_SHUTDOWN_REBOOT:
            if ( txt_is_powercycle_required() ) {
                /* powercycle by writing 0x0a+0x0e to port 0xcf9 */
                /* (supported by all TXT-capable chipsets) */
                outb(0xcf9, 0x0a);
                outb(0xcf9, 0x0e);
            }
            else {
                /* soft reset by writing 0xfe to keyboard reset vector 0x64 */
                /* BIOSes (that are not performing some special operation, */
                /* such as update) will turn this into a platform reset as */
                /* expected. */
                outb(0x64, 0xfe);
                /* fall back to soft reset by writing 0x06 to port 0xcf9 */
                /* (supported by all TXT-capable chipsets) */
                outb(0xcf9, 0x06);
            }

        case TB_SHUTDOWN_HALT:
        default:
            while ( true )
                halt();
    }
}

void shutdown(void)
{
    /* TODO fill me in */
}

void handle_exception(uint64_t error_code)
{
    printk(TBOOT_INFO"Received exception: 0x%llx - shutting down...\n",
           error_code);

    /* TODO for now, power cycle until the shutdown code is finished */
    outb(0xcf9, 0x0a);
    outb(0xcf9, 0x0e);

    _tboot_shared->shutdown_type = TB_SHUTDOWN_REBOOT;
    shutdown();
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

