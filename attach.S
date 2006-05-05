/* This is bytecode inserted on the stack of the attached application. */
/* When you modify it, check that the length is dword-aligned. */


	.equ	SYS_open,	5
	.equ	SYS_close,	6
	.equ	SYS_getpid,	20
	.equ	SYS_kill,	37
	.equ	SYS_dup,	41
	.equ	SYS_ioctl,	54
	.equ	SYS_dup2,	63

	.equ	O_RDWR,		02

	.equ	TCGETS,		0x5401
	.equ	TCSETS,		0x5402

	.equ	SIGWINCH,	28

	.equ	sizeof_termios,	60

	.file   "attach.S"
        .text
attach:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	pusha
	push	%ebp
	mov	%esp, %ebp
	sub	$sizeof_termios, %esp

	mov	$SYS_open, %eax
	mov	0x24(%ebp), %ebx
	mov	$O_RDWR, %ecx
	int	$0x80
	push	%eax	/* fd of the terminal */

	mov	$SYS_dup, %eax
	mov	$0x0, %ebx
	int	$0x80
	push	%eax	/* old stdin */

	mov	$SYS_dup, %eax
	mov	$0x1, %ebx
	int	$0x80
	push	%eax	/* old stdout */

	mov	$SYS_dup, %eax
	mov	$0x2, %ebx
	int	$0x80
	push	%eax	/* old stderr */

	mov	$SYS_close, %eax
	mov	$0x0, %ebx
	int	$0x80

	mov	$SYS_close, %eax
	mov	$0x1, %ebx
	int	$0x80

	mov	$SYS_close, %eax
	mov	$0x2, %ebx
	int	$0x80


	mov	0xc(%esp), %ebx /* pts fd */

	mov	$SYS_dup2, %eax
	mov	$0x0, %ecx
	int	$0x80

	mov	$SYS_dup2, %eax
	mov	$0x1, %ecx
	int	$0x80

	mov	$SYS_dup2, %eax
	mov	$0x2, %ecx
	int	$0x80


	mov	$SYS_ioctl, %eax
	pop	%ebx
	mov 	$TCGETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80

	mov	$SYS_ioctl, %eax
	mov	$2, %ebx
	mov	$TCSETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80


	mov	$SYS_ioctl, %eax
	pop	%ebx
	mov	$TCGETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80

	mov	$SYS_ioctl, %eax
	mov	$1, %ebx
	mov	$TCSETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80


	mov	$SYS_ioctl, %eax
	pop	%ebx
	mov	$TCGETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80

	mov	$SYS_ioctl, %eax
	mov	$0, %ebx
	mov	$TCSETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80


	mov	$SYS_close, %eax
	pop	%ebx
	int	$0x80


	mov	$SYS_getpid, %eax
	int	$0x80

	mov	%eax, %ebx
	mov	$SYS_kill, %eax
	mov	$SIGWINCH, %ecx
	int	$0x80

	leave
	popa

	/* The value will be rewritten */
	add	$0x12000000, %esp

	ret
