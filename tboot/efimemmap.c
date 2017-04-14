/*
 * efimemmap.c: EFI memory map processing and storage.
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
#include <atomic.h>
#include <page.h>
#include <printk.h>
#include <eficore.h>
#include <eficonfig.h>
#include <pe.h>
#include <tb_error.h>
#include <tboot.h>
#include <txt/txt.h>

#define MAX_RAMMEM_BLOCKS 128
#define MEM_NONE  0
#define MEM_RAM   1
#define MEM_OTHER 2

typedef struct mem_map {
    uint64_t addr;
    uint64_t length;
    uint64_t type;
} mem_map_t;

static __data mem_map_t g_ram_map[MAX_RAMMEM_BLOCKS];
static __data uint64_t g_ram_map_count = 0;

/* minimum size of RAM (type 1) region that cannot be marked as reserved even
   if it comes after a reserved region; 0 for no minimum (i.e. current
   behavior) */
/* TODO this needs some evaluation - preserve for now. If using this causes the
 * PMRs to not cover the MLE then game over. See the reloc code in boot.c.
 */
uint32_t g_min_ram = 0;

/*
 * All we really care about are conventional RAM regions. This will include
 * coalesced RAM, EFI loader and boot services memory.
 *
 * TODO this needs some work regarding pre/post ML and final mem map
 */
bool efi_scan_memory_map(void)
{
    const EFI_MEMORY_DESCRIPTOR *desc;
    const void *memory_map;
    uint64_t size, size_desc, length, type, last = MEM_NONE, i;
    mem_map_t *entry = g_ram_map - 1;
    efi_memmap_t *memmap = efi_get_memmap(false);

    /* Note the other field holds the descriptor size for mem map file */
    memory_map = memmap->base;
    size       = memmap->size;
    size_desc  = memmap->desc_size;

    if (!memory_map || size == 0 ||
         size_desc < sizeof(EFI_MEMORY_DESCRIPTOR)) {
        printk(TBOOT_ERR"System memory map invalid?!\n");
        return false;
    }

    memset(g_ram_map, 0, sizeof(mem_map_t)*MAX_RAMMEM_BLOCKS);

    printk(TBOOT_DETA"EFI memory map:\n");
    for (i = 0; i < size; i += size_desc) {
        desc = memory_map + i;
        length = desc->NumberOfPages << EFI_PAGE_SHIFT;

        printk(TBOOT_DETA" %016llx - %016llx type=%u attr=%016llx\n",
               desc->PhysicalStart, desc->PhysicalStart + length - 1,
               desc->Type, desc->Attribute);
        switch (desc->Type)
        {
        case EfiBootServicesCode:
        case EfiBootServicesData:
        case EfiLoaderCode:
        case EfiLoaderData:
        case EfiConventionalMemory:
            if (desc->Attribute & EFI_MEMORY_WB)
                type = MEM_RAM;
            else
                type = MEM_OTHER;
            break;
        default:
            type = MEM_OTHER;
        };

        if (g_ram_map_count >= MAX_RAMMEM_BLOCKS) {
            printk(TBOOT_ERR"Exhausted RAM memory blocks\n");
            return false;
        }

        if (g_ram_map_count && type == last &&
             desc->PhysicalStart == entry->addr + entry->length) {
            entry->length += length;
        }
        else {
            ++entry;
            entry->addr = desc->PhysicalStart;
            entry->length = length;
            entry->type = type;
            ++g_ram_map_count;
        }

        last = type;
    }

    entry = g_ram_map;
    printk(TBOOT_DETA"RAM map:\n");
    for (i = 0; i < g_ram_map_count; i++, entry++) {
        printk(TBOOT_DETA" %016llx - %016llx  type: %s\n",
               entry->addr, entry->addr + entry->length,
               (entry->type == MEM_RAM ? "RAM" : "OTHER"));
    }

    return true;
}

bool efi_add_resmap_entry(uint64_t addr, uint64_t length)
{
    /*
     * TODO Xen will have to sort things out like e820_reserve_ram in its
     * copy of the E820 it gives to dom0. We don't do E820 around these parts.
     */

    if (_tboot_shared->reserve_map_count >= TB_RESMEM_BLOCKS) {
        printk(TBOOT_ERR"Exhausted RES memory blocks\n");
        return false;
    }

    _tboot_shared->reserve_map[++_tboot_shared->reserve_map_count].addr = addr;
    _tboot_shared->reserve_map[_tboot_shared->reserve_map_count].length = length;

    return true;
}

/* find highest (< <limit>) RAM region of at least <size> bytes */
static void get_highest_sized_ram(uint64_t size, uint64_t limit,
                                  uint64_t *ram_base, uint64_t *ram_size)
{
    uint64_t last_fit_base = 0, last_fit_size = 0, i;
    mem_map_t *entry = g_ram_map;

    if ( ram_base == NULL || ram_size == NULL )
        return;

    for ( i = 0; i < g_ram_map_count; i++, entry++ ) {
        /* over 4GB so use the last region that fit */
        if ( entry->addr + entry->length > limit )
            break;
        if ( size <= entry->length ) {
            last_fit_base = entry->addr;
            last_fit_size = entry->length;
        }
    }

    *ram_base = last_fit_base;
    *ram_size = last_fit_size;
}

bool efi_get_ram_ranges(uint64_t *min_lo_ram, uint64_t *max_lo_ram,
                        uint64_t *min_hi_ram, uint64_t *max_hi_ram)
{
    bool found_reserved_region = false;
    uint64_t last_min_ram_base = 0, last_min_ram_size = 0, i;
    mem_map_t *entry = g_ram_map;

    if ( min_lo_ram == NULL || max_lo_ram == NULL ||
         min_hi_ram == NULL || max_hi_ram == NULL )
        return false;

    *min_lo_ram = *min_hi_ram = ~0ULL;
    *max_lo_ram = *max_hi_ram = 0;

    /* 
     * if g_min_ram > 0, we will never mark a region > g_min_ram in size
     * as reserved even if it is after a reserved region (effectively
     * we ignore reserved regions below the last type 1 region
     * > g_min_ram in size)
     * so in order to reserve RAM regions above this last region, we need
     * to find it first so that we can tell when we have passed it
     */
    if ( g_min_ram > 0 ) {
        get_highest_sized_ram(g_min_ram, 0x100000000ULL, &last_min_ram_base,
                              &last_min_ram_size);
        printk(TBOOT_DETA"highest min_ram (0x%x) region found: base=0x%Lx, size=0x%Lx\n",
               g_min_ram, last_min_ram_base, last_min_ram_size);
    }

    for ( i = 0; i < g_ram_map_count; i++, entry++ ) {
        uint64_t base = entry->addr;
        uint64_t limit = entry->addr + entry->length;

        if ( entry->type == MEM_RAM ) {
            /* if range straddles 4GB boundary, that is an error */
            if ( base < 0x100000000ULL && limit > 0x100000000ULL ) {
                printk(TBOOT_ERR"e820 memory range straddles 4GB boundary\n");
                return false;
            }

            /*
             * some BIOSes put legacy USB buffers in reserved regions <4GB,
             * which if DMA protected cause SMM to hang, so make sure that
             * we don't overlap any of these even if that wastes RAM
             * ...unless min_ram was specified
             */
            if ( !found_reserved_region || base <= last_min_ram_base ) {
                if ( base < 0x100000000ULL && base < *min_lo_ram )
                    *min_lo_ram = base;
                if ( limit <= 0x100000000ULL && limit > *max_lo_ram )
                    *max_lo_ram = limit;
            }
            else {     /* need to reserve low RAM above reserved regions */
                if ( base < 0x100000000ULL ) {
                    if (txt_is_launched()) {
                        printk(TBOOT_DETA"discarding RAM above reserved"
                               "regions: 0x%Lx - 0x%Lx\n", base, limit);
                        if ( !efi_add_resmap_entry(base, limit - base) )
                            return false;
                    }
                }
            }

            if ( base >= 0x100000000ULL && base < *min_hi_ram )
                *min_hi_ram = base;
            if ( limit > 0x100000000ULL && limit > *max_hi_ram )
                *max_hi_ram = limit;
        }
        else {
            /* parts of low memory may be reserved for cseg, ISA hole,
               etc. but these seem OK to DMA protect, so ignore reserved
               regions <0x100000 */
            if ( *min_lo_ram != ~0ULL && limit > 0x100000ULL )
                found_reserved_region = true;
        }
    }

    /* no low RAM found */
    if ( *min_lo_ram >= *max_lo_ram ) {
        printk(TBOOT_ERR"no low ram in e820 map\n");
        return false;
    }
    /* no high RAM found */
    if ( *min_hi_ram >= *max_hi_ram )
        *min_hi_ram = *max_hi_ram = 0;

    return true;
}
