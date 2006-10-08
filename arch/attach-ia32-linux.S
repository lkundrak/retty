/* This is bytecode inserted on the stack of the attached application. */
/* When you modify it, check that the length is dword-aligned. */


/*
 * Thrice he cried. Thrice the great ram boomed. And suddenly  upon the last
 * stroke the Gate of Gondor broke. As if stricken by some blasting spell it
 * burst asunder: there was a flash of searing lightning, and the doors
 * tumbled in riven fragments to the ground.
 */

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
cervena:
	mov	$0x0, %ebx
	int	$0x80
	push	%eax	/* old stdin */

	mov	$SYS_dup, %eax
zelena:
	mov	$0x1, %ebx
	int	$0x80
	push	%eax	/* old stdout */

	mov	$SYS_dup, %eax
modra:
	mov	$0x2, %ebx
	int	$0x80
	push	%eax	/* old stderr */

	mov	$SYS_close, %eax
fialova:
	mov	$0x0, %ebx
	int	$0x80

	mov	$SYS_close, %eax
oranzova:
	mov	$0x1, %ebx
	int	$0x80

	mov	$SYS_close, %eax
bezova:
	mov	$0x2, %ebx
	int	$0x80


	mov	0xc(%esp), %ebx /* pts fd */

	mov	$SYS_dup2, %eax
zluta:
	mov	$0x0, %ecx
	int	$0x80

	mov	$SYS_dup2, %eax
bila:
	mov	$0x1, %ecx
	int	$0x80

	mov	$SYS_dup2, %eax
cerna:
	mov	$0x2, %ecx
	int	$0x80


	/* From now on, NO %esp MANIPULATION PERMITTED!
	   We will look back at the stack from the retty process. ;-) */


	mov	$SYS_ioctl, %eax
	mov	(%esp), %ebx
	mov 	$TCGETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80

	mov	$SYS_ioctl, %eax
hnusna:
	mov	$2, %ebx
	mov	$TCSETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80


	mov	$SYS_ioctl, %eax
	mov	0x4(%esp), %ebx
	mov	$TCGETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80

	mov	$SYS_ioctl, %eax
cokoladova:
	mov	$1, %ebx
	mov	$TCSETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80


	mov	$SYS_ioctl, %eax
	mov	0x8(%esp), %ebx
	mov	$TCGETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80

	mov	$SYS_ioctl, %eax
vanilkova:
	mov	$0, %ebx
	mov	$TCSETS, %ecx
	lea	-sizeof_termios(%ebp), %edx
	int	$0x80


	mov	$SYS_close, %eax
	mov	0xc(%esp), %ebx
	int	$0x80


	mov	$SYS_getpid, %eax
	int	$0x80

	mov	%eax, %ebx
	mov	$SYS_kill, %eax
	mov	$SIGWINCH, %ecx
	int	$0x80

	nop

	leave
	popa

	/* The value will be rewritten */
	add	$0x12000000, %esp

	ret
