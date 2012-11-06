/* This is bytecode inserted on the stack of the attached application. */


/*
 * Ghvn-buri-Ghvn squatted down and touched the earth with his horny brow
 * in token of farewell. Then he got up as if to depart. But suddenly he stood
 * looking up like some startled woodland animal snuffling a strange air.
 * A light came in his eyes.
 *
 * 'Wind is changing!' he cried, and with that, in a twinkling as it seemed,
 * he and his fellows had vanished into the glooms, never to be seen by any
 * Rider of Rohan again.
 */


	.equ	SYS_close,	6
	.equ	SYS_getpid,	20
	.equ	SYS_kill,	37
	.equ	SYS_ioctl,	54
	.equ	SYS_dup2,	63

	.equ	TCGETS,		0x5401
	.equ	TCSETS,		0x5402

	.equ	SIGWINCH,	28

	.equ	sizeof_termios,	60

	.file   "detach.S"
        .text
detach:
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


	mov	$SYS_close, %eax
zelena:
	mov	$0x0, %ebx
	int	$0x80

	mov	$SYS_close, %eax
cervena:
	mov	$0x1, %ebx
	int	$0x80

	mov	$SYS_close, %eax
vyblita:
	mov	$0x2, %ebx
	int	$0x80


	mov	$SYS_dup2, %eax
	mov	0x2c(%ebp), %ebx
modra:
	mov	$0x0, %ecx
	int	$0x80

	mov	$SYS_dup2, %eax
	mov	0x28(%ebp), %ebx
smoulova:
	mov	$0x1, %ecx
	int	$0x80

	mov	$SYS_dup2, %eax
	mov	0x24(%ebp), %ebx
hneda:
	mov	$0x2, %ecx
	int	$0x80


	mov	$SYS_close, %eax
	mov	0x2c(%ebp), %ebx
	int	$0x80

	mov	$SYS_close, %eax
	mov	0x28(%ebp), %ebx
	int	$0x80

	mov	$SYS_close, %eax
	mov	0x24(%ebp), %ebx
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
