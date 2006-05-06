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


void sigwinch(int x);

static int oldin, oldout, olderr, die, intr;
pid_t pid;
struct termios t_orig;


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


static void
inject_attach(pid_t pid, int n, char ptsname[])
{
	struct user_regs_struct regs;
	unsigned long codeaddr, ptsnameaddr;
	int waitst;

	static char attach_code[] = {
#include "bc-attach.i"
	};

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
	printf("codesize: %x codeaddr: %lx\n", sizeof(attach_code), codeaddr);
	*((int*)&attach_code[sizeof(attach_code)-5]) = sizeof(attach_code) + n*4 + 4;
	if (0 > write_mem(pid, (unsigned long*)&attach_code, sizeof(attach_code)/sizeof(long), regs.esp)) {
		fprintf(stderr, "cannot write attach_code\n");
		exit(1);
	}

	/* push ptsname[] */
	regs.esp -= n*4;
	ptsnameaddr = regs.esp;
	if (0 > write_mem(pid, (unsigned long*)ptsname, n, regs.esp)) {
		fprintf(stderr, "cannot write bla argument (%s)\n",
			strerror(errno));
		exit(1);
	}

	/* push ptsname */
	/* FIXME: This is superfluous now, change bytecode to use lea */
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, ptsnameaddr);

	regs.eip = codeaddr+8;
	printf("stack: %lx eip: %lx sub:%x\n", regs.esp, regs.eip, (int) attach_code[sizeof(attach_code)-5]);


	/* Run the bytecode */
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	sigwinch(0); // bytecode will raise another SIGWINCH later so it will get sync'd thru
	// interrupt any syscall with the WINCH (typically read() ;)
	do {
		ptrace(PTRACE_CONT, pid, 0, (void*) SIGWINCH);
		wait(&waitst);
		if (!WIFSTOPPED(waitst)) {
			fprintf(stderr, "attached task not stopped\n");
			exit(1);
		}
	} while (WSTOPSIG(waitst) != SIGWINCH);

	/* Grab backed up fds from stack */
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	oldin = ptrace(PTRACE_PEEKDATA, pid, regs.esp + 0x8, NULL);
	oldout = ptrace(PTRACE_PEEKDATA, pid, regs.esp + 0x4, NULL);
	olderr = ptrace(PTRACE_PEEKDATA, pid, regs.esp + 0x0, NULL);
	printf("oldfds (esp: %lx): %d, %d, %d\n", regs.esp, oldin, oldout, olderr);

	/* Let go */
	ptrace(PTRACE_DETACH, pid, 0, (void*) SIGWINCH);
}


static void
inject_detach(pid_t pid, int fd0, int fd1, int fd2)
{
	struct user_regs_struct regs;
	unsigned long codeaddr;

	static char detach_code[] = {
#include "bc-detach.i"
	};

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
	regs.esp -= sizeof(detach_code);
	codeaddr = regs.esp;
	printf("codesize: %x codeaddr: %lx\n", sizeof(detach_code), codeaddr);
	*((int*)&detach_code[sizeof(detach_code)-5]) = sizeof(detach_code) + 4 + 4 + 4;
	if (0 > write_mem(pid, (unsigned long*)&detach_code, sizeof(detach_code)/sizeof(long), regs.esp)) {
		fprintf(stderr, "cannot write detach_code\n");
		exit(1);
	}

	/* push fds */
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, fd0);
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, fd1);
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, fd2);

	regs.eip = codeaddr+8;
	printf("stack: %lx eip: %lx sub:%x\n", regs.esp, regs.eip, (int) detach_code[sizeof(detach_code)-5]);


	/* Detach and continue */
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	kill(pid, SIGWINCH); // interrupt any syscall (typically read() ;)
	ptrace(PTRACE_DETACH, pid, 0, 0);
}


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
	intr = 1;
}

void
cleanup(int x)
{
	static int cleanups;
	if (cleanups++ > 0) return;
	inject_detach(pid, oldin, oldout, olderr);
	ioctl(0, TCSETS, &t_orig);
	die = 1;
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
	int n;
	char *arg;
	char *pts;

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
	//tcflush(ptm, TCIOFLUSH);
	//(void) ioctl(ptm, TIOCEXCL, (char *) 0);

	n = strlen(pts)+1;
	n = n/4 + (n%4 ? 1 : 0);
	arg = malloc(n*sizeof(unsigned long));
	memcpy(arg, pts, n*4);

	signal(SIGWINCH, sigwinch);
	signal(SIGINT, sigint); // breaks stuff


	inject_attach(pid, n, arg);

	ioctl(0, TCGETS, &t_orig);

	signal(SIGTERM, cleanup);
	//signal(SIGINT, cleanup);
	signal(SIGQUIT, cleanup);
	signal(SIGPIPE, cleanup);

	while (!die) {
		static struct termios t;
		fd_set fds;

		while (intr) {
			char ibuf = t.c_cc[VINTR];
			write(ptm, &ibuf, 1);
			intr--;
		}

		FD_ZERO(&fds);
		FD_SET(ptm, &fds);
		FD_SET(0, &fds);
		if (select(ptm+1, &fds, NULL, NULL, NULL) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			perror("select()");
			break;
		}

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

	cleanup(0);

	return 0;
}
