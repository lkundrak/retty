CFLAGS=-Wall -g
LIBS=-lutil
LDFLAGS=$(LIBS)

EXE=blindtty retty


all: $(EXE)


blindtty: blindtty.o


retty: retty.c

retty.c: bc-attach.i
	@touch retty.c

bc-attach.i: attach.o
	objdump -j .text -d $^ | ./bytecode.pl >$@


clean:
	rm -f *.o $(EXE) bc-attach.* test
