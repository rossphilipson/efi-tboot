/*
 * launch.S: the MLE post launch entry code.
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
#include <msr.h>
#include <page.h>
#include <processor.h>

/* TXT config regs addrs/offsets */
#define TXT_PRIV_CONFIG_REGS_BASE      0xfed20000
#define TXTCR_STS                      0x0000
#define TXTCR_ERRORCODE                0x0030
#define TXTCR_CMD_RESET                0x0038
#define TXTCR_CMD_UNLOCK_MEM_CONFIG    0x0218
#define TXTCR_HEAP_BASE                0x0300

/* OsSinitData field offsets */
#define MLE_PGTBL_OFFSET       8

/* 64b selectors */
#define CS_SEL64               0x0008
#define DS_SEL64               0x0010

/* errorcode for post-launch memory layout verfication failure */
#define LAYOUT_ERR             0xc0008001

#define BSP_STACK_SIZE         0x4000
#define AP_STACK_SIZE          0x0800

.section .text
	.align PAGE_SIZE, 0

.code32

.global _mle_start
_mle_start:

/* Original:
 * entry point post-launch, to verify memory layout
 * (must all be w/in one page; since _start is page-aligned, it will be;
 * which is why we can't call much other code (e.g. printk, TPM fns, etc.)
 * EFI:
 * this routine is on the first page of the .text section, page aligned and
 * far smaller than PAGE_SIZE.
 */
ENTRY(post_launch_entry)
	/*
	 * Since the spec says these segment registers are undefined (though
	 * actually have valid selectors in them in reality), restore them to
	 * the the selector for the data seg desc just after the code seg desc.
	 */
	xorl	%eax, %eax
	movw	%cs, %ax
	addw	$8, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss

        /*
	 * Per the spec:
	 * EBX - MLE entry point physical address.
	 * ECX - MLE page table base physical address.
	 *
	 * Restore the world, get back into longer mode. EBX contains the entry
	 * point which is our only known location in protected mode. We will
	 * use it to set things right then validate it later. If it is not
	 * what it is supposed to be, the world will come crashing down. Start
	 * by creating our page tables. Store it in ESI so EBX can be used.
	 *
	 * N.B. It seems though that TXT should guarantee the register contains
	 * what it says it should per the specification. Not sure why it would
	 * need verification.
	 *
	 * TODO if we end up needing to validate EBX here we can load a stack
	 * in some scratch location, call and pop to get EIP and then frob up
	 * a location to compare.
	 */
	cli
	movl	%ebx, %esi

	/* Fixup some addresses for the GDT and long jump */
	movl	%ebx, %ecx
	addl	$(gdt_desc64 - _mle_start + 2), %ecx
	movl	%ebx, %eax
	addl	$(gdt_table64 - _mle_start), %eax
	movl	%eax, (%ecx)

	movl	%ebx, %ecx
	addl	$(jump64 - _mle_start + 1), %ecx
	movl	%ebx, %eax
	addl	$(entry64 - _mle_start), %eax
	movl	%eax, (%ecx)

	/* Zero out all page table pages so there are no surprises */
	cld	/* just in case */
	movl	%ebx, %edi
	subl	$(TBOOT_RTMEM_SIZE + PAGE_SIZE), %edi
	xorl	%eax, %eax
	movl	$(TBOOT_PLEPT_SIZE/4), %ecx
	rep stosl

	/* First page is the PML4 table with one PDP entry */
	movl	%ebx, %eax
	subl	$(TBOOT_RTMEM_SIZE + PAGE_SIZE), %eax
	movl	%eax, %ecx
	addl	$PAGE_SIZE, %ecx
	orl	$0x3, %ecx
	movl	%ecx, (%eax)

	/* Second page is the PDP table with 4 PD entries */
	addl	$PAGE_SIZE, %eax
	movl	%eax, %ecx
	xorl	%edx, %edx
1:
	addl	$PAGE_SIZE, %ecx
	cmpb	$4, %dl
	jz	2f
	orl	$0x3, %ecx
	movl	%ecx, (%eax)
	addl	$0x8, %eax
	incb	%dl
	jmp	1b
2:	/* EAX Page 2 + 0x20 */

	/* Next 4 pages are PDs that map all of mem < 4G as 2M pages */
	addl	$(PAGE_SIZE - 0x20), %eax
	xorl	%edx, %edx
	xorl	%ecx, %ecx
	xorl	%ebx, %ebx
	addl	$0x83, %ecx
1:
	cmpw	$512, %dx
	jz	2f
	movl	%ecx, (%eax)
	addl	$0x8, %eax
	addl	$0x200000, %ecx
	incw	%dx
	jmp	1b
2:
	cmpb	$3, %bl	
	jz	3f
	incb	%bl
	xorl	%edx, %edx
	jmp	1b
3:	/* EAX Page 7 */

	/* Return to first PD entry on first PD and setup a PT entry */
	movl	%eax, %ecx
	subl	$(4*PAGE_SIZE), %eax
	orl	$0x3, %ecx
	movl	%ecx, (%eax)

	/* Page 7 is a PT that maps all of mem < 2M as 4K pages */
	addl	$(4*PAGE_SIZE), %eax
	xorl	%edx, %edx
	xorl	%ecx, %ecx
	addl	$0x3, %ecx
1:
	cmpw	$512, %dx
	jz	2f
	movl	%ecx, (%eax)
	addl	$0x8, %eax
	addl	$0x1000, %ecx
	incw	%dx
	jmp	1b
2:	/* EAX Page 8 */

	/*
	 * And done - all memory below 4G is identity mapped. Time to get back
	 * to long mode. EAX contains the base of the page table structures.
	 */
	subl	$(7*PAGE_SIZE), %eax

	/* Restore CR4, PAE must be enabled before IA-32e mode */
	movl	%cr4, %ecx
	orl	$(CR4_PAE | CR4_PGE), %ecx
	movl	%ecx, %cr4

	/* Load PML4 table location into PT base register */
	movl	%eax, %cr3

	/* Enable IA-32e mode and paging */
	movl	$MSR_EFER, %ecx
	rdmsr
	orl	$(1 << _EFER_LME), %eax
	wrmsr
	movl	%cr0, %eax
	orl	$(CR0_PG | CR0_NE | CR0_ET | CR0_MP | CR0_PE), %eax
	movl	%eax, %cr0
	jmp	1f
1:
	/* Now in IA-32e compatibility mode */

	/* Setup GDT and ljmp to 64b mode */
	movl	%esi, %ebx
	addl	$(gdt_desc64 - _mle_start), %ebx
	lgdt	(%ebx)

jump64:
	.byte	0xea       /* far jmp op */
	.long	0x00000000 /* offset (fixed up) */
	.word	CS_SEL64   /* 64b code segment selector */

.code64

entry64:
	/* Load data segment regs */
	movw	$DS_SEL64, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* ESI still has original EBX, put it back */
	xorq	%rbx, %rbx
	movl	%esi, %ebx

	/* 
	 * Layout check from original TBOOT. If EBX did not contain the
	 * physaddr of the entry point we would probably be lost way before
	 * we got here. But check it anyway then check the page tables passed
	 * to SENTER.
	 */
	leaq	post_launch_entry(%rip), %rax
	cmpl	%eax, %ebx
	jnz 	1f

	/*
	 * Verify last entry in MLE page table is the one we expected
	 * this is sufficient because: 1) all addrs must be phys increasing
	 * and 2) tboot is phys contig -- therefore if any page were moved to
	 * a different phys addr then the last page would have to be different
	 * from tboot's last page. Note in paging mode identity mapped so
	 * phys == virt for this verification.
	 *
	 * Get addr of MLE page table from OsSinitData, with the start of
	 * TXT heap == BiosDataSize.
	 */
	movq	$TXT_PRIV_CONFIG_REGS_BASE, %rcx
	movq	TXTCR_HEAP_BASE(%rcx), %rax
	addq	(%rax), %rax                       /* skip BiosData */
	addq	(%rax), %rax                       /* skip OsMleData */
	movq	(MLE_PGTBL_OFFSET + 8)(%rax), %rax /* addr of MLE page table */
	movq	(%rax), %rax /* PDP -> PD page */
	andq	$PAGE_MASK, %rax
	movq	(%rax), %rax /* PD -> PT page */
	andq	$PAGE_MASK, %rax
	/* Get the MLE size; this value was stored in the MLE and measured */
	leaq	_mle_size(%rip), %rdx
	movq	(%rdx), %rcx
	/* Use size to move past last valid PTE then one back */
	decq	%rcx                    /* Handle size not mult of page size */
	shrq	$(PAGE_SHIFT - 3), %rcx /* Size DIV 512 for 8b entries */
	andq	$~7, %rcx               /* Mask to floor */
	addq	%rcx, %rax              /* Offset in PT to PTE */
	movq	(%rax), %rax            /* Addr of last page from PTE */
	andq	$PAGE_MASK, %rax
	/* Calculate expected addr of last page */
	movq	(%rdx), %rdx
	addq	%rdx, %rbx
	decq	%rbx             /* MLE start + size - 1 addr of last byte */
	andq	$PAGE_MASK, %rbx /* ...rounded to page start */
	/* Are they equal? */
	cmpq	%rbx, %rax
	jz	start64
	/* Else fall through and die */

	/* Layout check failed so TXT RESET with a special error code */
1:
	movq	$TXT_PRIV_CONFIG_REGS_BASE, %rcx
	movl	$LAYOUT_ERR, TXTCR_ERRORCODE(%rcx)
	/* unlock memory config (and serialize) */
	movb	$1, TXTCR_CMD_UNLOCK_MEM_CONFIG(%rcx)
	movq	TXTCR_STS(%rcx), %rax
	/* TXT RESET */
	movb	$1, TXTCR_CMD_RESET(%rcx)
	movb	$6, %al
	movw	$0xcf9, %dx
	outb	%al, %dx /* for debug chipsets where TXT RESET may not work */
	ud2

start64:
	/* Clear the .bss of pre-launch stuffs */
	cld
	leaq	_bss_start(%rip), %rdi
	leaq	_bss_size(%rip), %rdx
	movq	(%rdx), %rcx
	xorq	%rax, %rax
	rep stosb

	/* Load up a stack */
	leaq	bsp_stack(%rip), %rax
	movq	%rax, %rsp

	/* Fixup IDT table and descriptor, load and STI */
	leaq	idt_desc64_end(%rip), %rax
	leaq	idt_table64(%rip), %rcx
	movq	%rcx, -8(%rax)

	leaq	int_handler(%rip), %rax
	xorq	%rdx, %rdx
1:
	cmpw	$256, %dx
	jz	1f
	movq	%rax, %rbx
	movw	%bx, (%rcx)
	shrq	$16, %rbx
	movw	%bx, 6(%rcx)
	shrq	$16, %rbx
	movl	%ebx, 8(%rcx)
	cmpw	$18, %dx
	jnz	2f
	/* MCE vector */
	movl	$0x8f00, 8(%rcx) /* P, DPL=0, 64b, Trap */
2:
	incw	%dx
	addq	$16, %rcx
	jmp	1b
1:
	lidt	idt_desc64(%rip)
	sti

	/* Enable MCE */
	movq	%cr4, %rax
	orq	$CR4_MCE, %rax
	movq	%rax, %cr4

	/* And we are outa here... */
	callq	post_launch
	ud2

/*
 * vmexit handler
 */
ENTRY(vmx_asm_vmexit_handler)
        call vmx_vmexit_handler
	/* fall through to loop if callee returns (shouldn't happen) */

ENTRY(_mini_guest)
	pause
	/* TODO rest */
	ret

ENTRY(bsp_stack_ref)
	leaq	bsp_stack(%rip), %rax
	ret

/*
 * Interrupt handler
 */
int_handler:
	movq	(%rsp), %rcx
	call	handle_exception
	ud2

/* GDT */
	.align 16
gdt_desc64:
	.word	gdt_table64_end - gdt_table64 - 1 /* Limit */
	.quad	0x0000000000000000 /* Base */
gdt_desc64_end:

	.align 16
gdt_table64:
	/* Null Segment */
	.quad	0x0000000000000000
	/* Code Segment */
	.word	0x0000 /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9a   /* P=1 DPL=0 11=code C=0 R=1 A=0 */
	.byte	0x20   /* G=0 D=0 L=1 D=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
	/* Data Segment */
	.word	0x0000 /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x92   /* P=1 DPL=0 10=code C=0 W=1 A=0 */ 
	.byte	0x00   /* G=0 D=0 L=0 D=0 AVL=0 Limit 2 */  
	.byte	0x00   /* Base 3 */
gdt_table64_end:

/* IDT */
	.align 16
idt_desc64:
	.word	idt_table64_end - idt_table64 - 1 /* Limit */
	.quad	0x0000000000000000 /* Base */
idt_desc64_end:

	.align	16

idt_table64:
	.rept	256
		.word	0x0000     /* Offset 15 - 0 */
		.word	CS_SEL64   /* Segment selector */
		.word	0x8e00     /* P, DPL=0, 64b, Interrupt (default) */
		.word	0x0000     /* Offset 31 - 16 */
		.long	0x00000000 /* Offset 63 - 32 */
		.long	0x00000000 /* Reserved */
	.endr
idt_table64_end:

.global _mle_size
_mle_size:
	.quad	0x0000000000000000 /* MLE size */

.global _bss_size
_bss_size:
	.quad	0x0000000000000000 /* .bss size */

.section .data
	.align PAGE_SIZE, 0

.section .rdata
	.align PAGE_SIZE, 0

.section .bss
	.align PAGE_SIZE, 0

.global _bss_start
_bss_start:

/* Stacks */

bsp_stack_end:
        .fill BSP_STACK_SIZE, 1, 0
bsp_stack:

ap_stacks_end:
        .fill AP_STACK_SIZE * NR_CPUS, 1, 0
ap_stacks:

/* Page Table and VMCS data for AP bringup */

        .align PAGE_SIZE, 0
	.globl idle_pg_table
idle_pg_table:
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
	.globl host_vmcs
host_vmcs:
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
	.global ap_vmcs /* the input info when os/vmm kerneltrap into tboot */
ap_vmcs:
        .fill NR_CPUS * PAGE_SIZE, 1, 0
