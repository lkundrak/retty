/*
 * "I'm sure mine only works one way," Alice remarked.
 * "I can't remember things before they happen."
 *
 * "It's a poor sort of memory that only works backwards," the Queen
 * remarked.
 */


        .equ    SYS_close,      3
        .equ    SYS_getpid,     39
        .equ    SYS_kill,       62
        .equ    SYS_ioctl,      16
        .equ    SYS_dup2,       33

	.equ	TCGETS,		0x5401
	.equ	TCSETS,		0x5402

	.equ	SIGWINCH,	28

	.equ	sizeof_termios,	60

detach:
	nop
	nop
	nop
	nop

	nop
	nop
	nop
	nop

        push %rax
        push %rdi
        push %rsi
        push %rdx

	push	%rbp
	mov	%rsp, %rbp
	sub	$sizeof_termios, %rsp


	mov	$SYS_close, %rax
zelena:
	mov	$0x123456789abcdef, %rdi
	syscall

	mov	$SYS_close, %rax
cervena:
	mov	$0x123456789abcdef, %rdi
	syscall

	mov	$SYS_close, %rax
vyblita:
	mov	$0x123456789abcdef, %rdi
	syscall


	mov	$SYS_dup2, %rax
	mov	0x38(%rbp), %rdi
modra:
	mov	$0x123456789abcdef, %rsi
	syscall

	mov	$SYS_dup2, %rax
	mov	0x30(%rbp), %rdi
smoulova:
	mov	$0x123456789abcdef, %rsi
	syscall

	mov	$SYS_dup2, %rax
	mov	0x38(%rbp), %rdi
hneda:
	mov	$0x123456789abcdef, %rsi
	syscall


	mov	$SYS_close, %rax
	mov	0x38(%rbp), %rdi
	syscall

	mov	$SYS_close, %rax
	mov	0x30(%rbp), %rdi
	syscall

	mov	$SYS_close, %rax
	mov	0x28(%rbp), %rdi
	syscall

	mov	$SYS_getpid, %rax
	syscall

	mov	%rax, %rdi
	mov	$SYS_kill, %rax
	mov	$SIGWINCH, %rsi
	syscall

	leave

	pop %rdx
	pop %rsi
	pop %rdi
	pop %rax

	/* The value will be rewritten */
	add	$0x12000000, %rsp

	ret
