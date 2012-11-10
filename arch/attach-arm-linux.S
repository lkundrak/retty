/*
 * Alice was puzzled. "In our country," she remarked, "there's only one day
 * at a time."
 *
 * The Red Queen said, "That's a poor thin way of doing things. Now here, we
 * mostly have days and nights two or three at a time, and sometimes in the
 * winter we take as many as five nights together -- for warmth, you know."
 */

	.equ	SYS_open,	5
	.equ	SYS_close,	6
	.equ	SYS_getpid,	20
	.equ	SYS_kill,	37
	.equ	SYS_dup,	41
	.equ	SYS_ioctl,	54
	.equ	SYS_dup2,	63

	.equ	O_RDWR,		02

	.equ	TCS_BASE,	0x5400
	.equ	TCS_GET,	0x01
	.equ	TCS_SET,	0x02

	.equ	SIGWINCH,	28

	.equ	sizeof_termios, 60

attach:
	nop
	nop

	push	{fp, lr}
	add	fp, sp, #4
	sub	sp, sp, #sizeof_termios

	mov	r7, $SYS_open
	ldr	r0, [fp, #4]
	mov	r1, $O_RDWR
	swi	$0
	push	{r0}	/* fd of the terminal */

	mov	r7, $SYS_dup
cervena:
	mov	r0, $0x0
	swi	$0
	push	{r0}	/* old stdin */

	mov	r7, $SYS_dup
zelena:
	mov	r0, $0x1
	swi	$0
	push	{r0}	/* old stdout */

	mov	r7, $SYS_dup
modra:
	mov	r0, $0x1
	swi	$0
	push	{r0}	/* old stderr */

	mov	r7, $SYS_close
fialova:
	mov	r0, $0x0
	swi	$0

	mov	r7, $SYS_close
oranzova:
	mov	r0, $0x1
	swi	$0

	mov	r7, $SYS_close
bezova:
	mov	r0, $0x2
	swi	$0


	ldr	r0, [sp, #12] /* pts fd */

	mov	r7, $SYS_dup2
zluta:
	mov	r1, $0x0
	swi	$0

	mov	r7, $SYS_dup2
bila:
	mov	r1, $0x1
	swi	$0

	mov	r7, $SYS_dup2
cerna:
	mov	r1, $0x2
	swi	$0

	/* From now on, NO esp MANIPULATION PERMITTED!
	   We will look back at the stack from the retty process. ;-) */

	mov	r7, $SYS_ioctl
	ldr	r0, [sp]
	mov	r2, $TCS_BASE
	add	r1, r2, #TCS_GET
	sub	r2, fp, #sizeof_termios
	swi	$0

	mov	r7, $SYS_ioctl
hnusna:
	mov	r0, $2
	mov	r2, $TCS_BASE
	add	r1, r2, #TCS_SET
	sub	r2, fp, #sizeof_termios
	swi	$0

	mov	r7, $SYS_ioctl
	ldr	r0, [sp, #4]
	mov	r2, $TCS_BASE
	add	r1, r2, #TCS_GET
	sub	r2, fp, #sizeof_termios
	swi	$0

	mov	r7, $SYS_ioctl
cokoladova:
	mov	r0, $1
	mov	r2, $TCS_BASE
	add	r1, r2, #TCS_SET
	sub	r2, fp, #sizeof_termios
	swi	$0

	mov	r7, $SYS_ioctl
	ldr	r0, [sp, #8]
	mov	r2, $TCS_BASE
	add	r1, r2, #TCS_GET
	sub	r2, fp, #sizeof_termios
	swi	$0

	mov	r7, $SYS_ioctl
vanilkova:
	mov	r0, $1
	mov	r2, $TCS_BASE
	add	r1, r2, #TCS_SET
	sub	r2, fp, #sizeof_termios
	swi	$0

	mov	r7, $SYS_close
	ldr	r0, [sp, #0x0c]
	swi	$0

	mov	r7, $SYS_getpid
	swi	$0

	mov	r7, $SYS_kill
	mov	r1, $SIGWINCH
	swi	$0

	nop
	nop
