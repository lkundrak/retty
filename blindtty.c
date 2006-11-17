/*
 * blindtty - run command in a detached terminal
 *
 * Usage: blindtty CMD [ARGS]...
 *
 * You might find it useful to run it as "setsid blindtty CMD...".
 *
 * Copyright (c) 2006  Petr Baudis, Jan Sembera
 */

/*
 * 'But the night will be too short,' said Gandalf. 'I have come back here,
 * for I must have a little peace, alone. You should sleep, in a bed while you
 * still may. At the sunrise I shall take you to the Lord Denethor again. No,
 * when the summons comes, not at sunrise. The Darkness has begun. There will
 * be no dawn.'
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

	pid = forkpty(&ptm, NULL, NULL, NULL);
	if (!pid) {
		int i; for (i=0; i<argc; i++) argv[i] = argv[i+1]; argv[i]=NULL;
		execvp(argv[0], argv);
		perror("execvp() failed");
		return 2;
	}

	printf("%s started with pid %d\n", argv[1], pid);

	signal(SIGCHLD, sigchld);

	while (1) {
		char buf[1024];
		if (read(ptm, buf, 1024) <= 0)
			_exit(0);
	}

	return 0;
}
