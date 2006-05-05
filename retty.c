/* retty.c - attach process to current terminal
 *
 * Usage: retty PID
 *
 * PID is the pid of a running process.
 *
 * retty works on x86 Linux.
 *
 * Copyright (c) 2006  Petr Baudis, Jan Sembera
 */


#define _XOPEN_SOURCE 500  /* include pread,pwrite */
#define _GNU_SOURCE
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>


/* Write NLONG 4 byte words from BUF into PID starting
   at address POS.  Calling process must be attached to PID. */
static int
write_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++)
		if (0 > ptrace(PTRACE_POKEDATA, pid, pos+(i*4), *p))
			return -1;
	return 0;
}

static char attach_code[] = {
#include "bc-attach.i"
};

int ptm;

void
sigwinch(int x)
{
	struct winsize w;
	ioctl(1, TIOCGWINSZ, &w);
	ioctl(ptm, TIOCSWINSZ, &w);
}

void
sigint(int x)
{
	tcsendbreak(ptm, 0);
}

ssize_t
process_escapes(char *buf, ssize_t *len)
{
	static enum { ST_NONE, ST_ENTER, ST_ESCAPE } state;
	ssize_t i;
	for (i = 0; i < *len; i++) {
		//fprintf(stderr, "[state=%d %d/%d char=%x]\n", state, i, *len - 1, buf[i]);
		switch (state) {
		case ST_NONE:
			if (buf[i] == '\n' || buf[i] == '\r')
				state = ST_ENTER;
			break;
		case ST_ENTER:
			if (buf[i] == '`') {
				state = ST_ESCAPE;
				memmove(buf + i, buf + i + 1, *len - i - 1);
				(*len)--; i--;
			} else {
				state = ST_NONE;
			}
			break;
		case ST_ESCAPE:
			state = ST_NONE;
			switch (buf[i]) {
			case '.':
			case 'd':
				return i-2+1;
			case '?':
				printf("Supported escape sequences:\n");
				printf("`. - return the process to its original terminal\n");
				printf("`d - return the process to its original terminal\n");
				printf("`? - this message\n");
				printf("`` - send the escape character by typing it twice\n");
				printf("(Note that escapes are only recognized immediately after newline.)\n");
				memmove(buf + i, buf + i + 1, *len - i - 1);
				(*len)--; i--;
				break;
			case '`':
				break;
			default:
				memmove(buf + i + 1, buf + i, *len - i);
				buf[i] = '`';
				(*len)++; i++;
				break;
			}
			break;
		}
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	pid_t pid;
	struct user_regs_struct regs;
	unsigned long codeaddr, ptsnameaddr;
	int fd, n;
	char buf[32];
	char *arg;
	char *pts;
	struct termios t_orig;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PID\n", argv[0]);
		exit(1);
	}
	pid = strtol(argv[1], NULL, 0);

	/* Setup pty */
	ptm = getpt();
	grantpt(ptm);
	unlockpt(ptm);
	pts = ptsname(ptm);
	tcflush(ptm, TCIOFLUSH);
	(void) ioctl(ptm, TIOCEXCL, (char *) 0);

	n = strlen(pts)+1;
	n = n/4 + (n%4 ? 1 : 0);
	arg = malloc(n*sizeof(unsigned long));
	memcpy(arg, pts, n*4);

	signal(SIGWINCH, sigwinch);
	//signal(SIGINT, sigint); // breaks stuff

	/* Attach */
	if (0 > ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		fprintf(stderr, "cannot attach to %d\n", pid);
		exit(1);
	}
	waitpid(pid, NULL, 0);
	ptrace(PTRACE_GETREGS, pid, 0, &regs);


	/* Code injecting */

	/* push EIP */
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, regs.eip);

	/* finish code and push it */
	regs.esp -= sizeof(attach_code);
	codeaddr = regs.esp;
	//printf("codesize: %x codeaddr: %lx\n", sizeof(attach_code), codeaddr));
	*((int*)&attach_code[sizeof(attach_code)-5]) = sizeof(attach_code) + n*4 + 4;
	if (0 > write_mem(pid, (unsigned long*)&attach_code, sizeof(attach_code)/sizeof(long), regs.esp)) {
		fprintf(stderr, "cannot write attach_code\n");
		exit(1);
	}

	/* push ptsname[] */
	regs.esp -= n*4;
	ptsnameaddr = regs.esp;
	if (0 > write_mem(pid, (unsigned long*)arg, n, regs.esp)) {
		fprintf(stderr, "cannot write bla argument (%s)\n",
			strerror(errno));
		exit(1);
	}

	/* push ptsname */
	/* FIXME: This is superfluous now, change bytecode to use lea */
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, ptsnameaddr);

	regs.eip = codeaddr+8;
	printf("stack: %lx eip: %lx sub:%x\n", regs.esp, regs.eip, (int) attach_code[sizeof(attach_code)-7]);


	/* Detach and continue */
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	kill(pid, SIGWINCH); // interrupt any syscall (typically read() ;)
	sigwinch(0); // shellcode will raise another SIGWINCH after PTRACE_DETACH
	ptrace(PTRACE_DETACH, pid, 0, 0);

	ioctl(0, TCGETS, &t_orig);

	while (1) {
		struct termios t;
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(ptm, &fds);
		FD_SET(0, &fds);
		select(ptm+1, &fds, NULL, NULL, NULL);

		ioctl(ptm, TCGETS, &t);
		// we keep 0 raw and let the pts do the terminal work
		t.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL|ICANON);
		ioctl(0, TCSETS, &t);

		if (FD_ISSET(ptm, &fds)) {
			char buf[256];
			ssize_t len = read(ptm, buf, 256);
			if (len < 0 && errno != EINTR && errno != EAGAIN) {
				break;
			}
			write(1, buf, len);
		}

		if (FD_ISSET(0, &fds)) {
			char buf[2*256];
			ssize_t len = read(0, buf, 256);
			ssize_t stop;
			stop = process_escapes(buf, &len);
			if (stop) {
				write(ptm, buf, stop-1);
				break;
			}
			write(ptm, buf, len);
		}
	}

	ioctl(0, TCSETS, &t_orig);

	return 0;
}
