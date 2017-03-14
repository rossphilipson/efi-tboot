/* Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

#ifndef __PROCESSOR_H__
#define __PROCESSOR_H__

/* from: @(#)specialreg.h  7.1 (Berkeley) 5/9/91
 * $FreeBSD: stable/8/sys/i386/include/specialreg.h 198989 2009-11-06 15:24:48Z attilio $
 */

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

/*
 * Bits in 386 special registers:
 */
#define CR0_PE  0x00000001 /* Protected mode Enable */
#define CR0_MP  0x00000002 /* "Math" (fpu) Present */
#define CR0_EM  0x00000004 /* EMulate FPU instructions. (trap ESC only) */
#define CR0_TS  0x00000008 /* Task Switched (if MP, trap ESC and WAIT) */
#define CR0_ET  0x00000010 /* Extension type */
#define CR0_PG  0x80000000 /* PaGing enable */

/*
 * Bits in 486 special registers:
 */
#define CR0_NE  0x00000020 /* Numeric Error enable (EX16 vs IRQ13) */
#define CR0_WP  0x00010000 /* Write Protect (honor page protect in all modes) */
#define CR0_AM  0x00040000 /* Alignment Mask (set to enable AC flag) */
#define CR0_NW  0x20000000 /* Not Write-through */
#define CR0_CD  0x40000000 /* Cache Disable */

/*
 * Bits in PPro special registers
 */
#define CR4_VME 0x00000001 /* Virtual 8086 mode extensions */
#define CR4_PVI 0x00000002 /* Protected-mode virtual interrupts */
#define CR4_TSD 0x00000004 /* Time stamp disable */
#define CR4_DE  0x00000008 /* Debugging extensions */
#define CR4_PSE 0x00000010 /* Page size extensions */
#define CR4_PAE 0x00000020 /* Physical address extension */
#define CR4_MCE 0x00000040 /* Machine check enable */
#define CR4_PGE 0x00000080 /* Page global enable */
#define CR4_PCE 0x00000100 /* Performance monitoring counter enable */
#define CR4_FXSR 0x00000200/* Fast FPU save/restore used by OS */
#define CR4_XMM 0x00000400 /* enable SIMD/MMX2 to use except 16 */
#define CR4_VMXE 0x00002000/* enable VMX */
#define CR4_SMXE 0x00004000/* enable SMX */
#define CR4_PCIDE 0x00020000/* enable PCID */

#ifndef __ASSEMBLY__

/* from:
 * $FreeBSD: src/sys/i386/include/cpufunc.h,v 1.158 2010/01/01 20:55:11 obrien Exp $
 */

static inline void do_cpuid(unsigned int ax, uint32_t *p)
{
    __asm__ __volatile__ ("cpuid"
                          : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
                          :  "0" (ax));
}

static inline void do_cpuid1(unsigned int ax, unsigned int cx, uint32_t *p)
{
    __asm__ __volatile__ ("cpuid"
                          : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
                          :  "0" (ax), "c" (cx));
}

static always_inline uint32_t cpuid_eax(unsigned int op)
{
     /* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
    uint32_t regs[4];

    do_cpuid(op, regs);

    return regs[0];
}

static always_inline uint32_t cpuid_ebx(unsigned int op)
{
     /* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
    uint32_t regs[4];

    do_cpuid(op, regs);

    return regs[1];
}

static always_inline uint32_t cpuid_ebx1(unsigned int op1, unsigned int op2)
{
     /* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
    uint32_t regs[4];

    do_cpuid1(op1, op2, regs);

    return regs[1];
}
static always_inline uint32_t cpuid_ecx(unsigned int op)
{
     /* eax: regs[0], ebx: regs[1], ecx: regs[2], edx: regs[3] */
    uint32_t regs[4];

    do_cpuid(op, regs);

    return regs[2];
}

#define CPUID_X86_FEATURE_XMM3   (1<<0)
#define CPUID_X86_FEATURE_VMX    (1<<5)
#define CPUID_X86_FEATURE_SMX    (1<<6)

/* Note, removed read/write ecx, not used */

static inline unsigned long long read_cr0(void)
{
    unsigned long long data;
    /* 64: movl -> movq */
    __asm__ __volatile__ ("movq %%cr0,%0" : "=r" (data));
    return (data);
}

static inline void write_cr0(unsigned long long data)
{
    /* 64: movl -> movq */
    __asm__ __volatile__("movq %0,%%cr0" : : "r" (data));
}

static inline unsigned long long read_cr4(void)
{
    unsigned long long data;
    /* 64: movl -> movq */
    __asm__ __volatile__ ("movq %%cr4,%0" : "=r" (data));
    return (data);
}

static inline void write_cr4(unsigned long long data)
{
    /* 64: movl -> movq */
    __asm__ __volatile__ ("movq %0,%%cr4" : : "r" (data));
}

static inline unsigned long long read_cr3(void)
{
    unsigned long long data;
    /* 64: movl -> movq */
    __asm__ __volatile__ ("movq %%cr3,%0" : "=r" (data));
    return (data);
}

static inline void write_cr3(unsigned long long data)
{
    /* 64: movl -> movq */
    __asm__ __volatile__("movq %0,%%cr3" : : "r" (data) : "memory");
}

static inline uint64_t read_rflags(void)
{
    uint64_t rf;
    /* 32: EFLAGS stuff __asm__ __volatile__ ("pushfl; popl %0" : "=r" (ef));*/
    __asm__ __volatile__ ("pushfq; popq %0" : "=r" (rf));
    return (rf);
}

static inline void write_rflags(uint64_t rf)
{
    /* 32: EFLAGS stuff __asm__ __volatile__ ("pushl %0; popfl" : : "r" (ef));*/
    __asm__ __volatile__ ("pushq %0; popfq" : : "r" (rf));
}

static inline void disable_intr(void)
{
    __asm__ __volatile__ ("cli" : : : "memory");
}

static inline void enable_intr(void)
{
    __asm__ __volatile__ ("sti");
}

/* was ia32_pause() */
static inline void cpu_relax(void)
{
    __asm__ __volatile__ ("pause");
}

static inline void halt(void)
{
    __asm__ __volatile__ ("hlt");
}

static inline unsigned int get_apicid(void)
{
    return cpuid_ebx(1) >> 24;
}

static inline void wbinvd(void)
{
    __asm__ __volatile__ ("wbinvd");
}

static inline uint32_t bsrl(uint32_t mask)
{
    uint32_t   result;

    /* 64: Ok to shift 32b mask */
    __asm__ __volatile__ ("bsrl %1,%0" : "=r" (result) : "rm" (mask) : "cc");
    return (result);
}

static inline int fls(int mask)
{
    return (mask == 0 ? mask : (int)bsrl((u_int)mask) + 1);
}

static always_inline void mb(void)
{
    /* 32: __asm__ __volatile__ ("lock;addl $0,0(%%esp)" : : : "memory"); */
    __asm__ __volatile__ ("lock;addq $0,0(%%rsp)" : : : "memory");
}

static inline void cpu_monitor(const void *addr, int extensions, int hints)
{
    /* 64: a=rax, c=rcx, d=rdx  ints are 32b into ecx, edx */
    __asm __volatile__ ("monitor;" : :"a" (addr), "c" (extensions), "d"(hints));
}

static inline void cpu_mwait(int extensions, int hints)
{
    /* 64: a=rax, c=rcx  ints are 32b into eax, ecx */
    __asm __volatile__ ("mwait;" : :"a" (hints), "c" (extensions));
}

static inline void flush_tlb(void)
{
    __asm__ __volatile__ (
                   "movq %%cr3, %%rax\n"
                   "movq %%rax, %%cr3\n"
                   : : : "rax");
}

typedef struct __packed lmode_desc {
    uint16_t limit;
    uint64_t base;
} lmode_desc_t;

static inline void store_gdt(lmode_desc_t *gdt)
{
    __asm__ __volatile__("sgdt %0\n\t"
                         : "=m" (*gdt) : : "memory");
}

static inline void store_idt(lmode_desc_t *idt)
{
    __asm__ __volatile__("sidt %0\n\t"
                         : "=m" (*idt): : "memory");
}

#define lea_reference(i, o) __asm__ __volatile__ \
      ("lea "#i"(%%rip), %%rax\n\t" : "=a" (o))

#define mov_sel(r, o) __asm__ __volatile__ \
    ("movw %%"#r"s, %0\n\t" : "=m" (o) : : "memory");

/* In inline asm, these 3 use the A constraint to specify the EDX:EAX register
 * pair. The inline assembler was getting the code badly wrong so the
 * implementation of these moved to the assembly module (and renamed).
 */
uint64_t read_msr(uint32_t msr);
void write_msr(uint32_t msr, uint64_t newval);
uint64_t read_tsc(void);

uint64_t get_rip(void);
uint64_t bsp_stack_ref(void);

#define rdmsr read_msr
#define wrmsr write_msr
#define rdtsc read_tsc

#endif /* __ASSEMBLY__ */

#endif /* __PROCESSOR_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
