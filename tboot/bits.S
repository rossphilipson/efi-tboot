/*
 * bits.S: Assembly support routines and bits.
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

#define REF(x) x(%rip)

#define SOFF   16

ENTRY(print_test_chars)
	pushq	%rcx
	pushq	%rdx
	xorq	%rcx, %rcx
1:
	cmpb	$5, %cl
	jz	2f
	movw	$0x3f8, %dx
	addw	$5, %dx
3:
	inb	%dx, %al
	testb	$0x20, %al
	jz	3b
	movw	$0x3f8, %dx
	movb	$0x41, %al
	addb	%cl, %al
        outb	%al, %dx
	incb	%cl
	jmp	1b
2:
	popq	%rdx
	popq	%rcx
	ret

ENTRY(memcpy)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rcx, SOFF(%rbp)   # dst
	movq	%rdx, SOFF+8(%rbp) # src
	movq	%r8, SOFF+16(%rbp) # size

	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rcx
	shrq	$3, %rcx
	cld
	rep
	movsq              # mov quad words forward
	movq	%r8, %rcx
	andq	$7, %rcx
	rep
	movsb              # mov remaining bytes forward
	popq	%rbp
	ret

ENTRY(read_msr)
	pushq	%rdx
	/* ECX already has MSR number, go for it */
	rdmsr
	movq	$0xffffffff, %rcx
	andq	%rcx, %rax
	shlq	$32, %rdx
	movq	$0xffffffff00000000, %rcx
	andq	%rcx, %rdx
	orq	%rdx, %rax
	popq	%rdx
	ret

ENTRY(write_msr)
	pushq	%rax
	movq	%rdx, %rax
	shrq	$32, %rdx
	/* ECX already has MSR number */
	wrmsr
	popq	%rax
	ret

ENTRY(read_tsc)
	rdtsc
	movq	$0xffffffff, %rcx
	andq	%rcx, %rax
	shlq	$32, %rdx
	movq	$0xffffffff00000000, %rcx
	andq	%rcx, %rdx
	orq	%rdx, %rax
	ret

/*
 * Mutex code ported to 64b from:
 *      $OpenBSD: mutex.S,v 1.6 2009/04/27 21:48:56 kettenis Exp $
 *
 * Copyright (c) 2004 Artur Grabowski <art@openbsd.org>
 * All rights reserved.
 *
 * BSD 2-Clause
 */

ENTRY(mtx_init)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rcx, SOFF(%rbp) # home var 
	movq	$0, (%rcx)
	popq	%rbp
	ret

ENTRY(mtx_enter)
	pushq	%rbp
	movq	%rsp, %rbp
1:	movq	%rcx, SOFF(%rbp) # home var 
	/*
	 * %rcx contains the mtx as passed from caller
	 */
	movq	$1, %rax
	xchgq	%rax, (%rcx)	# test_and_set(mtx->mtx_lock)
	testq	%rax, %rax	# if (already held)
	jnz	2f
	popq	%rbp
	ret
2:	pause
	movq	(%rcx), %rax
	testq	%rax, %rax
	jz	1b
	jmp	2b

ENTRY(mtx_leave)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rcx, SOFF(%rbp) # home var 
	movq	$0, (%rcx)
	popq	%rbp
	ret

ENTRY(get_rip)
	movq	(%rsp), %rax
	ret
