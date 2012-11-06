/*
 * "Well, in our country," said Alice, still panting a little, "you'd
 * generally get to somewhere else — if you run very fast for a long time,
 * as we've been doing."
 *
 * "A slow sort of country!" said the Queen. "Now, here, you see, it takes
 * all the running you can do, to keep in the same place. If you want to
 * get somewhere else, you must run at least twice as fast as that!"
 */


        .equ    SYS_open,       2
        .equ    SYS_close,      3
        .equ    SYS_getpid,     39
        .equ    SYS_kill,       62
        .equ    SYS_dup,        32
        .equ    SYS_ioctl,      16
        .equ    SYS_dup2,       33

        .equ    O_RDWR,         02

        .equ    TCGETS,         0x5401
        .equ    TCSETS,         0x5402

        .equ    SIGWINCH,       28

        .equ    sizeof_termios, 60

attach:
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

	mov	$SYS_open, %rax
	mov	0x28(%rbp), %rdi
	mov	$O_RDWR, %rsi
	syscall
	push	%rax	/* fd of the terminal */

	mov	$SYS_dup, %rax
cervena:
	mov	$0x123456789abcdef, %rdi
	syscall
	push	%rax	/* old stdin */

	mov	$SYS_dup, %rax
zelena:
	mov	$0x123456789abcdef, %rdi
	syscall
	push	%rax	/* old stdout */

	mov	$SYS_dup, %rax
modra:
	mov	$0x123456789abcdef, %rdi
	syscall
	push	%rax	/* old stderr */

	mov	$SYS_close, %rax
fialova:
	mov	$0x123456789abcdef, %rdi
	syscall

	mov	$SYS_close, %rax
oranzova:
	mov	$0x123456789abcdef, %rdi
	syscall

	mov	$SYS_close, %rax
bezova:
	mov	$0x123456789abcdef, %rdi
	syscall


	mov	0x18(%rsp), %rdi /* pts fd */

	mov	$SYS_dup2, %rax
zluta:
	mov	$0x123456789abcdef, %rsi
	syscall

	mov	$SYS_dup2, %rax
bila:
	mov	$0x123456789abcdef, %rsi
	syscall

	mov	$SYS_dup2, %rax
cerna:
	mov	$0x123456789abcdef, %rsi
	syscall


	/* From now on, NO %rsp MANIPULATION PERMITTED!
	   We will look back at the stack from the retty process. ;-) */


	mov	$SYS_ioctl, %rax
	mov	(%rsp), %rdi
	mov 	$TCGETS, %rsi
	lea	-sizeof_termios(%rbp), %rdx
	syscall

	mov	$SYS_ioctl, %rax
hnusna:
	mov	$0x123456789abcdef, %rdi
	mov	$TCSETS, %rsi
	lea	-sizeof_termios(%rbp), %rdx
	syscall


	mov	$SYS_ioctl, %rax
	mov	0x8(%rsp), %rdi
	mov	$TCGETS, %rsi
	lea	-sizeof_termios(%rbp), %rdx
	syscall

	mov	$SYS_ioctl, %rax
cokoladova:
	mov	$0x123456789abcdef, %rdi
	mov	$TCSETS, %rsi
	lea	-sizeof_termios(%rbp), %rdx
	syscall


	mov	$SYS_ioctl, %rax
	mov	0x10(%rsp), %rdi
	mov	$TCGETS, %rsi
	lea	-sizeof_termios(%rbp), %rdx
	syscall

	mov	$SYS_ioctl, %rax
vanilkova:
	mov	$0x123456789abcdef, %rdi
	mov	$TCSETS, %rsi
	lea	-sizeof_termios(%rbp), %rdx
	syscall


	mov	$SYS_close, %rax
	mov	0x18(%rsp), %rdi
	syscall


	mov	$SYS_getpid, %rax
	syscall

	mov	%rax, %rdi
	mov	$SYS_kill, %rax
	mov	$SIGWINCH, %rsi

	syscall

	nop

	leave

	pop %rdx
	pop %rsi
	pop %rdi
	pop %rax

	/* The value will be rewritten */
	add	$0x12000000, %rsp

	ret
