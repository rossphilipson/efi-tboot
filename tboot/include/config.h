/*
 * config.h: project-wide definitions
 *
 * Copyright (c) 2006-2010, Intel Corporation
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
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

/* EFI and MLE layout values */
/* TODO MLE should cover .rdata too. Address that later */

/**********************************************************
 * TBOOT rumtime layout
 *
 * +---------------+ 0xXXXX0000
 * |               |   Post Launch page tables
 * |    PLETP      |    4K pages below 2M
 * |               |    2M pages below 4G
 * +---------------+ 0xXXXX7000
 * |    MLEPT      |   Measure Launch page tables
 * |               |    Cover MLE/.text section
 * +---------------+ 0xXXXXA000
 * |    PE HDR     |
 * +---------------+ 0xXXXXB000
 * |               |
 * |     MLE       |  The MLE/.text section.
 * |               |
 * +---------------+
 * |               |
 * |     DATA      |
 * |    SHATED     |  The rest of the TBOOT image.
 * |     ETC       |
 * |               |
 * +---------------+
 *
 **********************************************************/
 
/* Somewhere just below 4G */
#define TBOOT_MAX_IMAGE_MEM 0xfffff000

/* TBOOT post launch page table block */
#define TBOOT_PLEPT_COUNT   (7)
#define TBOOT_PLEPT_SIZE    (TBOOT_PLEPT_COUNT*PAGE_SIZE)

/* TBOOT MLE page table block */
#define TBOOT_MLEPT_COUNT  (3)
#define TBOOT_MLEPT_SIZE   (TBOOT_MLEPT_COUNT*PAGE_SIZE)

/* Totals */
#define TBOOT_RTMEM_COUNT (TBOOT_PLEPT_COUNT + TBOOT_MLEPT_COUNT)
#define TBOOT_RTMEM_SIZE  (TBOOT_PLEPT_SIZE + TBOOT_MLEPT_SIZE)

#ifndef NR_CPUS
#define NR_CPUS     512
#endif

#ifdef __ASSEMBLY__
#define ENTRY(name)                             \
  .globl name;                                  \
  .align 16,0x90;                               \
  name:
#endif

#define COMPILE_TIME_ASSERT(e)                 \
{                                              \
    struct tmp {                               \
        int a : ((e) ? 1 : -1);                \
    };                                         \
}

#define __data     __attribute__ ((__section__ (".data#")))
#define __text     __attribute__ ((__section__ (".text#")))

#define __packed        __attribute__ ((packed))
#define __maybe_unused  __attribute__ ((unused))

/* tboot log level */
#ifdef NO_TBOOT_LOGLVL
#define TBOOT_NONE
#define TBOOT_ERR
#define TBOOT_WARN
#define TBOOT_INFO
#define TBOOT_DETA
#define TBOOT_ALL
#else /* NO_TBOOT_LOGLVL */
#define TBOOT_NONE       "<0>"
#define TBOOT_ERR        "<1>"
#define TBOOT_WARN       "<2>"
#define TBOOT_INFO       "<3>"
#define TBOOT_DETA       "<4>"
#define TBOOT_ALL        "<5>"
#endif /* NO_TBOOT_LOGLVL */

#endif /* __CONFIG_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
