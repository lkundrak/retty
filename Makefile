CFLAGS=-Wall -g
LIBS=-lutil
LDFLAGS=$(LIBS)

EXE=blindtty retty


all: $(EXE)


blindtty: blindtty.o


retty: retty.o

retty.o: bc-attach.i bc-detach.i

bc-attach.i: attach.o
	objdump -j .text -d $^ | ./bytecode.sh >$@

bc-detach.i: detach.o
	objdump -j .text -d $^ | ./bytecode.sh >$@


clean:
	rm -f *.o $(EXE) bc-attach.* bc-detach.* test
