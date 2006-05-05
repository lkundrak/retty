#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void kva(int x)
{
	sleep(4);
}

int main()
{
	printf("%d\n", getpid());
	signal(SIGUSR1, kva);
	sleep(5);
	while (1) {
		char q;
		puts("lala");
		q = getchar();
		printf("baaaa %c\n", q);
		//sleep(5);
	}
	return 1;
}
