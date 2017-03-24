/*
 * txt.c: Intel(r) TXT support functions, including initiating measured
 *        launch, post-launch, AP wakeup, etc.
 *
 * Copyright (c) 2003-2011, Intel Corporation
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

#include <config.h>
#include <efibase.h>
#include <stdbool.h>
#include <types.h>
#include <tb_error.h>
#include <msr.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <processor.h>
#include <printk.h>
#include <atomic.h>
#include <mutex.h>
#include <tpm.h>
#include <uuid.h>
#include <eficore.h>
#include <eficonfig.h>
#include <tboot.h>
#include <mle.h>
#include <hash.h>
#include <cmdline.h>
#include <acpi.h>
#include <txt/txt.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/heap.h>
#include <txt/acmod.h>
#include <txt/smx.h>
#include <txt/verify.h>
#include <txt/vmcs.h>
#include <io.h>

/* counter timeout for waiting for all APs to enter wait-for-sipi */
#define AP_WFS_TIMEOUT     0x01000000

/* MLE/kernel shared data page (in boot.S) */
void apply_policy(tb_error_t error);
void print_event(const tpm12_pcr_event_t *evt);
void print_event_2(void *evt, uint16_t alg);

__data struct acpi_rsdp g_rsdp;

/*
 * this is the structure whose addr we'll put in TXT heap and
 * it needs to be within the MLE pages, so force it to the .text section.
 * It is filled in at runtime with set values that don't change and
 * are based of the relocated fixed physical base address of the TBOOT
 * EFI RT memory region.
 */
__text mle_hdr_t g_mle_hdr = {
    uuid              :  MLE_HDR_UUID,
    length            :  sizeof(mle_hdr_t),
    version           :  MLE_HDR_VER,
    entry_point       :  0, /* Linear virt. offset to the EP, used by ACM */
    first_valid_page  :  0,
    mle_start_off     :  0, /* Offset from TBOOT base, used by SW */
    mle_end_off       :  0, /* Offset from TBOOT base, used by SW */
    capabilities      :  { MLE_HDR_CAPS },
    cmdline_start_off :  0, /* Offset from TBOOT base, used by SW */
    cmdline_end_off   :  0  /* Offset from TBOOT base, used by SW */
};

/*
 * counts of APs going into wait-for-sipi
 */
/* count of APs in WAIT-FOR-SIPI */
atomic_t ap_wfs_count;

static __data uint8_t *g_mle_pt;

__data uint32_t g_using_da = 0;

static __data event_log_container_t *g_elog = NULL;
static __data heap_event_log_ptr_elt2_t *g_elog_2 = NULL;

static void print_file_info(void)
{
    efi_file_t *rtmem = efi_get_file(EFI_FILE_RTMEM);
    efi_file_t *image = efi_get_file(EFI_FILE_IMAGE);
    efi_file_t *text = efi_get_file(EFI_FILE_IMAGE_TEXT);

    printk(TBOOT_DETA"file addresses:\n");
    printk(TBOOT_DETA"\t RTMEM start=%p\n", rtmem->u.base);
    printk(TBOOT_DETA"\t RTMEM end=%p\n", rtmem->u.base + rtmem->size);
    printk(TBOOT_DETA"\t IMAGE start=%p\n", image->u.base);
    printk(TBOOT_DETA"\t IMAGE end=%p\n", image->u.base + image->size);
    printk(TBOOT_DETA"\t MLE start=%p\n", text->u.base);
    printk(TBOOT_DETA"\t MLE end=%p\n", text->u.base + text->size);
    /*printk(TBOOT_DETA"\t &_post_launch_entry=%p\n", &_post_launch_entry);
    printk(TBOOT_DETA"\t &_txt_wakeup=%p\n", &_txt_wakeup);*/
    printk(TBOOT_DETA"\t &g_mle_hdr=%p\n", &g_mle_hdr);
}

static void print_mle_hdr(const mle_hdr_t *mle_hdr)
{
    printk(TBOOT_DETA"MLE header:\n");
    printk(TBOOT_DETA"\t uuid="); print_uuid(&mle_hdr->uuid); 
    printk(TBOOT_DETA"\n");
    printk(TBOOT_DETA"\t length=%x\n", mle_hdr->length);
    printk(TBOOT_DETA"\t version=%08x\n", mle_hdr->version);
    printk(TBOOT_DETA"\t entry_point=%08x\n", mle_hdr->entry_point);
    printk(TBOOT_DETA"\t first_valid_page=%08x\n", mle_hdr->first_valid_page);
    printk(TBOOT_DETA"\t mle_start_off=%x\n", mle_hdr->mle_start_off);
    printk(TBOOT_DETA"\t mle_end_off=%x\n", mle_hdr->mle_end_off);
    printk(TBOOT_DETA"\t cmdline_start_off=%x\n", mle_hdr->cmdline_start_off);
    printk(TBOOT_DETA"\t cmdline_end_off=%x\n", mle_hdr->cmdline_end_off);
    print_txt_caps("\t ", mle_hdr->capabilities);
}

static void __maybe_unused print_mle_pagetable(void)
{
    uint32_t mle_size, mle_off;
    void *pg_dir_ptr_tab, *pg_dir, *pg_tab;
    uint64_t *pte;
    int i = 0;

    mle_size = g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off;
    pg_dir_ptr_tab = g_mle_pt;
    pg_dir         = pg_dir_ptr_tab + PAGE_SIZE;
    pg_tab         = pg_dir + PAGE_SIZE;

    printk(TBOOT_DETA"MLE Page Tables:\n");
    printk("  pg_dir_ptr_tab=%016llx pg_dir_ptr_tab[0]=%016llx pg_dir_ptr_tab[1]=%016llx\n",
           (uint64_t)pg_dir_ptr_tab, *(uint64_t *)pg_dir_ptr_tab, *(uint64_t *)(pg_dir_ptr_tab + 8));

    printk("  pg_dir=%016llx pg_dir[0]=%016llx pg_dir[1]=%016llx\n",
           (uint64_t)pg_dir, *(uint64_t *)pg_dir, *(uint64_t *)(pg_dir + 8));

    pte = pg_tab;
    mle_off = 0;
    printk("  pg_tab=%016llx\n",  (uint64_t)pg_tab);
    for (i = 0; mle_off < mle_size; i++, pte++, mle_off += PAGE_SIZE)
        printk("    pte[%d]=%016llx\n", i, *pte);
}
 
void txt_init_mle_header(void)
{
    efi_file_t *rtmem = efi_get_file(EFI_FILE_RTMEM);
    efi_file_t *image = efi_get_file(EFI_FILE_IMAGE);
    efi_file_t *text = efi_get_file(EFI_FILE_IMAGE_TEXT);
    uint64_t ple;

    lea_reference(post_launch_entry, ple);

    g_mle_hdr.entry_point = (uint32_t)(ple - (uint64_t)text->u.base);
    g_mle_hdr.mle_start_off = (uint32_t)((uint64_t)text->u.base -
                                         (uint64_t)rtmem->u.base);
    g_mle_hdr.mle_end_off   = (uint32_t)((uint64_t)text->u.base +
                                         (uint64_t)text->size -
                                         (uint64_t)rtmem->u.base);
    g_mle_hdr.cmdline_start_off = (uint32_t)((uint64_t)g_cmdline -
                                             (uint64_t)text->u.base);
    g_mle_hdr.cmdline_end_off   = (uint32_t)((uint64_t)g_cmdline +
                                             CMDLINE_SIZE - 1 -
                                             (uint64_t)text->u.base);
    print_mle_hdr(&g_mle_hdr);
}

/* page dir/table entry is phys addr + P + R/W + PWT */
#define MAKE_PDTE(addr)  (((uint64_t)(unsigned long long)(addr) & PAGE_MASK) | 0x01)

/* we assume/know that our image is <2MB and thus fits w/in a single */
/* PT (512*4KB = 2MB) and thus fixed to 1 pg dir ptr and 1 pgdir and */
/* 1 ptable = 3 pages and just 1 loop loop for ptable MLE page table */
/* can only contain 4k pages */

/* pgdir ptr + pgdir + ptab = 3 */

bool txt_build_mle_pagetable(void)
{
    efi_file_t *rtmem = efi_get_file(EFI_FILE_RTMEM);
    uint32_t mle_start, mle_size;
    void *ptab_base;
    uint32_t ptab_size, mle_off;
    void *pg_dir_ptr_tab, *pg_dir, *pg_tab;
    uint64_t *pte;

    /* page tables start at the phys addr of the MLE base and cover MLE */
    mle_start = g_mle_hdr.mle_start_off + (uint32_t)(uint64_t)rtmem->u.base;
    mle_size = g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off;

    /* place PTs in 3 page before the TBOOT image */
    g_mle_pt = rtmem->u.base + TBOOT_PLEPT_SIZE;

    printk(TBOOT_DETA"MLE start=0x%x, end=0x%x, size=0x%x\n",
           mle_start, mle_start+mle_size, mle_size);
    if ( mle_size > 512*PAGE_SIZE ) {
        printk(TBOOT_ERR"MLE size too big for single page table\n");
        return false;
    }

    /* should start on page boundary */
    if ( mle_start & ~PAGE_MASK ) {
        printk(TBOOT_ERR"MLE start is not page-aligned\n");
        return false;
    }

    /* place ptab_base below MLE */
    ptab_size = TBOOT_MLEPT_SIZE;
    ptab_base = g_mle_pt; /* already zeroed */
    printk(TBOOT_DETA"ptab_size=%x, ptab_base=%p\n", ptab_size, ptab_base);

    pg_dir_ptr_tab = ptab_base;
    pg_dir         = pg_dir_ptr_tab + PAGE_SIZE;
    pg_tab         = pg_dir + PAGE_SIZE;

    /* only use first entry in page dir ptr table */
    *(uint64_t *)pg_dir_ptr_tab = MAKE_PDTE(pg_dir);

    /* only use first entry in page dir */
    *(uint64_t *)pg_dir = MAKE_PDTE(pg_tab);

    pte = pg_tab;
    mle_off = 0;
    do {
        *pte = MAKE_PDTE(mle_start + mle_off);

        pte++;
        mle_off += PAGE_SIZE;
    } while ( mle_off < mle_size );

    /* DEBUG print_mle_pagetable();*/

    return true;
}

/* should be called after os_mle_data initialized */
static void *init_event_log(void)
{
    os_mle_data_t *os_mle_data = get_os_mle_data_start(get_txt_heap());
    g_elog = (event_log_container_t *)&os_mle_data->event_log_buffer;

    memcpy((void *)g_elog->signature, EVTLOG_SIGNATURE,
           sizeof(g_elog->signature));
    g_elog->container_ver_major = EVTLOG_CNTNR_MAJOR_VER;
    g_elog->container_ver_minor = EVTLOG_CNTNR_MINOR_VER;
    g_elog->pcr_event_ver_major = EVTLOG_EVT_MAJOR_VER;
    g_elog->pcr_event_ver_minor = EVTLOG_EVT_MINOR_VER;
    g_elog->size = sizeof(os_mle_data->event_log_buffer);
    g_elog->pcr_events_offset = sizeof(*g_elog);
    g_elog->next_event_offset = sizeof(*g_elog);

    return (void *)g_elog;
}

static void init_evtlog_desc(heap_event_log_ptr_elt2_t *evt_log)
{
    unsigned int i;
    os_mle_data_t *os_mle_data = get_os_mle_data_start(get_txt_heap());

    switch (g_tpm->extpol) {
    case TB_EXTPOL_AGILE:
        for (i=0; i<evt_log->count; i++) {
            evt_log->event_log_descr[i].alg = g_tpm->algs_banks[i];
            evt_log->event_log_descr[i].phys_addr =
                    (uint64_t)(os_mle_data->event_log_buffer + i*4096);
            evt_log->event_log_descr[i].size = 4096;
            evt_log->event_log_descr[i].pcr_events_offset = 0;
            evt_log->event_log_descr[i].next_event_offset = 0;
        }
        break;
    case TB_EXTPOL_EMBEDDED:
        for (i=0; i<evt_log->count; i++) {
            evt_log->event_log_descr[i].alg = g_tpm->algs[i];
            evt_log->event_log_descr[i].phys_addr =
                    (uint64_t)(os_mle_data->event_log_buffer + i*4096);
            evt_log->event_log_descr[i].size = 4096;
            evt_log->event_log_descr[i].pcr_events_offset = 0;
            evt_log->event_log_descr[i].next_event_offset = 0;
        }
        break;
    case TB_EXTPOL_FIXED:
        evt_log->event_log_descr[0].alg = g_tpm->cur_alg;
        evt_log->event_log_descr[0].phys_addr =
                    (uint64_t)os_mle_data->event_log_buffer;
        evt_log->event_log_descr[0].size = 4096;
        evt_log->event_log_descr[0].pcr_events_offset = 0;
        evt_log->event_log_descr[0].next_event_offset = 0;
        break;
    default:
        return;
    }
}

static void init_os_sinit_ext_data(heap_ext_data_element_t* elts)
{
    heap_ext_data_element_t* elt = elts;
    heap_event_log_ptr_elt_t *evt_log;

    if ( g_tpm->major == TPM12_VER_MAJOR ) {
        evt_log = (heap_event_log_ptr_elt_t *)elt->data;
        evt_log->event_log_phys_addr = (uint64_t)init_event_log();
        elt->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR;
        elt->size = sizeof(*elt) + sizeof(*evt_log);
    } else if ( g_tpm->major == TPM20_VER_MAJOR ) {
        g_elog_2 = (heap_event_log_ptr_elt2_t *)elt->data;

        if ( g_tpm->extpol == TB_EXTPOL_AGILE )
            g_elog_2->count = g_tpm->banks;
        else if ( g_tpm->extpol == TB_EXTPOL_EMBEDDED )
            g_elog_2->count = g_tpm->alg_count;
        else
            g_elog_2->count = 1;

        init_evtlog_desc(g_elog_2);

        elt->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2;
        elt->size = sizeof(*elt) + sizeof(u32) +
                g_elog_2->count * sizeof(heap_event_log_descr_t);
    }

    elt = (void *)elt + elt->size;
    elt->type = HEAP_EXTDATA_TYPE_END;
    elt->size = sizeof(*elt);
}

/*
 * sets up TXT heap
 */
static txt_heap_t *init_txt_heap(void *ptab_base, acm_hdr_t *sinit)
{
    efi_file_t *text = efi_get_file(EFI_FILE_IMAGE_TEXT);
    txt_heap_t *txt_heap;
    txt_caps_t sinit_caps;
    txt_caps_t caps_mask = { 0 };
    uint64_t *size;
    uint64_t min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram;
    const efi_file_t *lcp_file;
    struct acpi_rsdp *rsdp;

    txt_heap = get_txt_heap();

    /*
     * BIOS data already setup by BIOS
     */
    if ( !verify_txt_heap(txt_heap, true) )
        return NULL;

    /*
     * OS/loader to MLE data
     */
    os_mle_data_t *os_mle_data = get_os_mle_data_start(txt_heap);
    size = (uint64_t *)((uint64_t)os_mle_data - sizeof(uint64_t));
    *size = sizeof(*os_mle_data) + sizeof(uint64_t);
    memset(os_mle_data, 0, sizeof(*os_mle_data));
    os_mle_data->version = 3;
    os_mle_data->saved_misc_enable_msr = rdmsr(MSR_IA32_MISC_ENABLE);

    /*
     * OS/loader to SINIT data
     */
    /* check sinit supported os_sinit_data version */
    uint32_t version = get_supported_os_sinit_data_ver(sinit);
    if ( version < MIN_OS_SINIT_DATA_VER ) {
        printk(TBOOT_ERR"unsupported OS to SINIT data version(%u) in sinit\n",
               version);
        return NULL;
    }
    if ( version > MAX_OS_SINIT_DATA_VER )
        version = MAX_OS_SINIT_DATA_VER;

    os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);
    size = (uint64_t *)((uint64_t)os_sinit_data - sizeof(uint64_t));
    *size = calc_os_sinit_data_size(version);
    memset(os_sinit_data, 0, *size);
    os_sinit_data->version = version;

    /* this is phys addr */
    os_sinit_data->mle_ptab = (uint64_t)ptab_base;
    os_sinit_data->mle_size = g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off;
    /* this is linear addr (offset from MLE base) of mle header */
    os_sinit_data->mle_hdr_base = (uint64_t)&g_mle_hdr - (uint64_t)text->u.base;

    /* VT-d PMRs */
    if ( !efi_get_ram_ranges(&min_lo_ram, &max_lo_ram, &min_hi_ram, &max_hi_ram) )
        return NULL;

    set_vtd_pmrs(os_sinit_data, min_lo_ram, max_lo_ram, min_hi_ram,
                 max_hi_ram);

    /* LCP owner policy data */
    lcp_file = efi_get_file(EFI_FILE_LCP);
    if (lcp_file->u.base) {
        /* copy to heap */
        if ( lcp_file->size > sizeof(os_mle_data->lcp_po_data) ) {
            printk(TBOOT_ERR"LCP owner policy data file is too large (%u)\n",
                   lcp_file->size);
            return NULL;
        }
        memcpy(os_mle_data->lcp_po_data, lcp_file->u.base, lcp_file->size);
        os_sinit_data->lcp_po_base = (unsigned long long)&os_mle_data->lcp_po_data;
        os_sinit_data->lcp_po_size = lcp_file->size;
    }

    sinit_caps = get_sinit_capabilities(sinit);
    caps_mask.rlp_wake_getsec = 1;
    caps_mask.rlp_wake_monitor = 1;
    caps_mask.pcr_map_da = 1;
    os_sinit_data->capabilities._raw = MLE_HDR_CAPS & ~caps_mask._raw;
    if ( sinit_caps.rlp_wake_monitor )
        os_sinit_data->capabilities.rlp_wake_monitor = 1;
    else if ( sinit_caps.rlp_wake_getsec )
        os_sinit_data->capabilities.rlp_wake_getsec = 1;
    else {     /* should have been detected in verify_acmod() */
        printk(TBOOT_ERR"SINIT capabilities are incompatible (0x%x)\n", 
               sinit_caps._raw);
        return NULL;
    }
    /* capabilities : require MLE pagetable in ECX on launch */
    /* TODO: when SINIT ready
     * os_sinit_data->capabilities.ecx_pgtbl = 1;
     */
    os_sinit_data->capabilities.ecx_pgtbl = 0;

    /* Always true for us: if (is_loader_launch_efi(lctx)){ */
    /* we were launched EFI, set efi_rsdt_ptr */
    rsdp = (struct acpi_rsdp*)efi_get_rsdp();
    if (rsdp != NULL){
        if (version < 6){
            /* rsdt */
            /* NOTE: Winston Wang says this doesn't work for v5 */
            os_sinit_data->efi_rsdt_ptr = (uint64_t) rsdp->rsdp1.rsdt;
        } else {
            /* rsdp */
            memcpy((void *)&g_rsdp, rsdp, sizeof(struct acpi_rsdp));
            os_sinit_data->efi_rsdt_ptr = (uint64_t)&g_rsdp;
        }
    } else {
        /* per discussions--if we don't have an ACPI pointer, die */
        printk(TBOOT_ERR"Failed to find RSDP for EFI launch\n");
        return NULL;
    }

    /* capabilities : choose DA/LG */
    os_sinit_data->capabilities.pcr_map_no_legacy = 1;
    if ( sinit_caps.pcr_map_da && get_tboot_prefer_da() )
        os_sinit_data->capabilities.pcr_map_da = 1;
    else if ( !sinit_caps.pcr_map_no_legacy )
        os_sinit_data->capabilities.pcr_map_no_legacy = 0;
    else if ( sinit_caps.pcr_map_da ) {
        printk(TBOOT_INFO
               "DA is the only supported PCR mapping by SINIT, use it\n");
        os_sinit_data->capabilities.pcr_map_da = 1;
    }
    else {
        printk(TBOOT_ERR"SINIT capabilities are incompatible (0x%x)\n", 
               sinit_caps._raw);
        return NULL;
    }
    g_using_da = os_sinit_data->capabilities.pcr_map_da;

    /* PCR mapping selection MUST be zero in TPM2.0 mode
     * since D/A mapping is the only supported by TPM2.0 */
    if ( g_tpm->major >= TPM20_VER_MAJOR ) {
        os_sinit_data->flags = (g_tpm->extpol == TB_EXTPOL_AGILE) ? 0 : 1;
        os_sinit_data->capabilities.pcr_map_no_legacy = 0;
        os_sinit_data->capabilities.pcr_map_da = 0;
        g_using_da = 1;
    }   

    /* Event log initialization */
    if ( os_sinit_data->version >= 6 )
        init_os_sinit_ext_data(os_sinit_data->ext_data_elts);

    print_os_sinit_data(os_sinit_data);

    /*
     * SINIT to MLE data will be setup by SINIT
     */

    return txt_heap;
}

bool txt_is_launched(void)
{
    txt_sts_t sts;

    sts._raw = read_pub_config_reg(TXTCR_STS);

    return sts.senter_done_sts;
}

tb_error_t txt_launch_environment(void)
{
    os_mle_data_t *os_mle_data;
    txt_heap_t *txt_heap;

    /* print some debug info */
    print_file_info();

    /* MLE page table already setup earlier */

    /* initialize TXT heap */
    txt_heap = init_txt_heap(g_mle_pt, g_sinit);
    if ( txt_heap == NULL )
        return TB_ERR_TXT_NOT_SUPPORTED;

    /* save MTRRs before we alter them for SINIT launch */
    os_mle_data = get_os_mle_data_start(txt_heap);
    save_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* set MTRRs properly for AC module (SINIT) */
    if ( !set_mtrrs_for_acmod(g_sinit) )
        return TB_ERR_FATAL;

    /* deactivate current locality */
    if (g_tpm_family == TPM_IF_20_CRB ) {
        printk(TBOOT_INFO"Relinquish CRB localility 0 before executing GETSEC[SENTER]...\n");
        if (!tpm_relinquish_locality_crb(0)){
            printk(TBOOT_INFO"Relinquish CRB locality 0 failed...\n");
            apply_policy(TB_ERR_TPM_NOT_READY) ;
        }
    }

    /* Left behind commented out mess */

    printk(TBOOT_INFO"executing GETSEC[SENTER]...\n");
    /* (optionally) pause before executing GETSEC[SENTER] */
    if ( g_vga_delay > 0 )
        delay(g_vga_delay * 1000);

    /* SINIT has be (and is) located below 4G for SENTER */
    __getsec_senter((uint32_t)(uint64_t)g_sinit, (g_sinit->size)*4);

    printk(TBOOT_INFO"ERROR--we should not get here!\n");

    return TB_ERR_FATAL;
}

bool txt_prepare_cpu(void)
{
    unsigned long cr0;
    uint64_t mcg_cap, mcg_stat, msr_efer, rflags;
    unsigned int i;

    /* must be running at CPL 0 => this is implicit in even getting this far */
    /* since our bootstrap code loads a GDT, etc. */

    msr_efer = rdmsr(MSR_EFER);

    /* must be in IA-32e 16b sub-mode */
    if ( !( msr_efer & (1 << _EFER_LMA) ) ) {
        printk(TBOOT_ERR"ERR: not in IA-32e 16bit sub- mode\n");
        return false;
    }

    cr0 = read_cr0();

    /* cache must be enabled (CR0.CD = CR0.NW = 0) */
    if ( cr0 & CR0_CD ) {
        printk(TBOOT_INFO"CR0.CD set\n");
        cr0 &= ~CR0_CD;
    }
    if ( cr0 & CR0_NW ) {
        printk(TBOOT_INFO"CR0.NW set\n");
        cr0 &= ~CR0_NW;
    }

    /* native FPU error reporting must be enabled for proper */
    /* interaction behavior */
    if ( !(cr0 & CR0_NE) ) {
        printk(TBOOT_INFO"CR0.NE not set\n");
        cr0 |= CR0_NE;
    }

    write_cr0(cr0);

    /* cannot be in virtual-8086 mode (EFLAGS.VM=1) */
    rflags = read_rflags();
    if ( rflags & X86_EFLAGS_VM ) {
        printk(TBOOT_INFO"EFLAGS.VM set\n");
        write_rflags(rflags | ~X86_EFLAGS_VM);
    }

    printk(TBOOT_INFO"IA32_EFER, CR0 and EFLAGS OK\n");

    /*
     * verify that we're not already in a protected environment
     */
    if ( txt_is_launched() ) {
        printk(TBOOT_ERR"already in protected environment\n");
        return false;
    }

    /*
     * verify all machine check status registers are clear (unless
     * support preserving them)
     */

    /* no machine check in progress (IA32_MCG_STATUS.MCIP=1) */
    mcg_stat = rdmsr(MSR_MCG_STATUS);
    if ( mcg_stat & 0x04 ) {
        printk(TBOOT_ERR"machine check in progress\n");
        return false;
    }

    getsec_parameters_t params;
    if ( !get_parameters(&params) ) {
        printk(TBOOT_ERR"get_parameters() failed\n");
        return false;
    }

    /* check if all machine check regs are clear */
    mcg_cap = rdmsr(MSR_MCG_CAP);
    for ( i = 0; i < (mcg_cap & 0xff); i++ ) {
        mcg_stat = rdmsr(MSR_MC0_STATUS + 4*i);
        if ( mcg_stat & (1ULL << 63) ) {
            printk(TBOOT_ERR"MCG[%u] = %Lx ERROR\n", i, mcg_stat);
            if ( !params.preserve_mce )
                return false;
        }
    }

    if ( params.preserve_mce )
        printk(TBOOT_INFO"supports preserving machine check errors\n");
    else
        printk(TBOOT_INFO"no machine check errors\n");

    if ( params.proc_based_scrtm )
        printk(TBOOT_INFO"CPU support processor-based S-CRTM\n");

    /* all is well with the processor state */
    printk(TBOOT_INFO"CPU is ready for SENTER\n");

    return true;
}

bool txt_is_powercycle_required(void)
{
    /* a powercycle is required to clear the TXT_RESET.STS flag */
    txt_ests_t ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    return ests.txt_reset_sts;
}

#define ACM_MEM_TYPE_UC                 0x0100
#define ACM_MEM_TYPE_WC                 0x0200
#define ACM_MEM_TYPE_WT                 0x1000
#define ACM_MEM_TYPE_WP                 0x2000
#define ACM_MEM_TYPE_WB                 0x4000

#define DEF_ACM_MAX_SIZE                0x8000
#define DEF_ACM_VER_MASK                0xffffffff
#define DEF_ACM_VER_SUPPORTED           0x00
#define DEF_ACM_MEM_TYPES               ACM_MEM_TYPE_UC
#define DEF_SENTER_CTRLS                0x00

bool get_parameters(getsec_parameters_t *params)
{
    unsigned long long cr4;
    uint32_t index, eax, ebx, ecx;
    int param_type;

    /* sanity check because GETSEC[PARAMETERS] will fail if not set */
    cr4 = read_cr4();
    if ( !(cr4 & CR4_SMXE) ) {
        printk(TBOOT_ERR"SMXE not enabled, can't read parameters - cr4: %llx\n", cr4);
        return false;
    }

    memset(params, 0, sizeof(*params));
    params->acm_max_size = DEF_ACM_MAX_SIZE;
    params->acm_mem_types = DEF_ACM_MEM_TYPES;
    params->senter_controls = DEF_SENTER_CTRLS;
    params->proc_based_scrtm = false;
    params->preserve_mce = false;

    index = 0;
    do {
        __getsec_parameters(index++, &param_type, &eax, &ebx, &ecx);
        /* the code generated for a 'switch' statement doesn't work in this */
        /* environment, so use if/else blocks instead */

        /* NULL - all reserved */
        if ( param_type == 0 )
            ;
        /* supported ACM versions */
        else if ( param_type == 1 ) {
            if ( params->n_versions == MAX_SUPPORTED_ACM_VERSIONS )
                printk(TBOOT_WARN"number of supported ACM version exceeds "
                       "MAX_SUPPORTED_ACM_VERSIONS\n");
            else {
                params->acm_versions[params->n_versions].mask = ebx;
                params->acm_versions[params->n_versions].version = ecx;
                params->n_versions++;
            }
        }
        /* max size AC execution area */
        else if ( param_type == 2 )
            params->acm_max_size = eax & 0xffffffe0;
        /* supported non-AC mem types */
        else if ( param_type == 3 )
            params->acm_mem_types = eax & 0xffffffe0;
        /* SENTER controls */
        else if ( param_type == 4 )
            params->senter_controls = (eax & 0x00007fff) >> 8;
        /* TXT extensions support */
        else if ( param_type == 5 ) {
            params->proc_based_scrtm = (eax & 0x00000020) ? true : false;
            params->preserve_mce = (eax & 0x00000040) ? true : false;
        }
        else {
            printk(TBOOT_WARN"unknown GETSEC[PARAMETERS] type: %d\n", 
                   param_type);
            param_type = 0;    /* set so that we break out of the loop */
        }
    } while ( param_type != 0 );

    if ( params->n_versions == 0 ) {
        params->acm_versions[0].mask = DEF_ACM_VER_MASK;
        params->acm_versions[0].version = DEF_ACM_VER_SUPPORTED;
        params->n_versions = 1;
    }

    return true;
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
