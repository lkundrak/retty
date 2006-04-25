/*
 * blindtty - run command in a detached terminal
 *
 * Usage: blindtty CMD [ARGS]...
 *
 * Copyright (c) 2006  Petr Baudis, Jan Sembera
 */

#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


void
sigchld(int s)
{
	_exit(0);
}

int
main(int argc, char *argv[])
{
	int ptm;
	pid_t pid;

	if (argc < 2) {
		fprintf(stderr, "Usage: blindtty CMD [ARG]...\n");
		return 1;
	}

	if (fork())
		return 0;
	setsid();

	pid = forkpty(&ptm, NULL, NULL, NULL);
	if (!pid) {
		int i; for (i=0; i<argc; i++) argv[i] = argv[i+1]; argv[i]=NULL;
		execvp(argv[0], argv);
		perror("execvp() failed");
		return 2;
	}

	signal(SIGCHLD, sigchld);

	while (1) {
		char buf[1024];
		if (read(ptm, buf, 1024) <= 0)
			_exit(0);
	}

	return 0;
}
