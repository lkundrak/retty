/*
 * "And what does IT live on?"
 *
 * "Weak tea with cream in it."
 *
 * A new difficulty came into Alice's head. "Supposing it couldn't find
 * any?" she suggested.
 *
 * "Then it would die, of course."
 *
 * "But that must happen very often," Alice remarked thoughtfully.
 *
 * "It always happens," said the Gnat.
 */

	.equ	SYS_close,	6
	.equ	SYS_getpid,	20
	.equ	SYS_kill,	37
	.equ	SYS_ioctl,	54
	.equ	SYS_dup2,	63

	.equ	SIGWINCH,	28

detach:
	nop
	nop

	push	{fp, lr}
	add	fp, sp, #4

	mov	r7, $SYS_close
zelena:
	mov	r0, $0x0
	swi	$0

	mov	r7, $SYS_close
cervena:
	mov	r0, $0x1
	swi	$0

	mov	r7, $SYS_close
vyblita:
	mov	r0, $0x2
	swi	$0

	mov	r7, $SYS_dup2
	ldr	r0, [fp, #12]
modra:
	mov	r1, $0x0
	swi	$0

	mov	r7, $SYS_dup2
	ldr	r0, [fp, #8]
smoulova:
	mov	r1, $0x1
	swi	$0

	mov	r7, $SYS_dup2
	ldr	r0, [fp, #4]
hneda:
	mov	r1, $0x2
	swi	$0

	mov	r7, $SYS_close
	ldr	r0, [fp, #12]
	swi	$0

	mov	r7, $SYS_close
	ldr	r0, [fp, #8]
	swi	$0

	mov	r7, $SYS_close
	ldr	r0, [fp, #4]
	swi	$0

	mov	r7, $SYS_getpid
	swi	$0

	mov	r7, $SYS_kill
	mov	r1, $SIGWINCH
	swi	$0

	nop
	nop
