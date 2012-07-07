ARCH=`./getarch.sh -arch`
OS=`./getarch.sh -os`
FULLARCH=$(ARCH)-$(OS)

CFLAGS=-Wall -g -DARCH=$(ARCH) -DOS=$(OS)
LIBS=-lutil
EXE=blindtty retty

all: $(EXE)

blindtty: blindtty.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

retty: retty.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

retty.o: bc-attach.i bc-detach.i

bc-attach.i: attach.o
	objdump -j .text -d $^ | ./bytecode.pl attach_code >$@

bc-detach.i: detach.o
	objdump -j .text -d $^ | ./bytecode.pl detach_code >$@

attach.o:
	make -f arch/Makefile attach-$(FULLARCH).o
	mv attach-$(FULLARCH).o attach.o

detach.o:
	make -f arch/Makefile detach-$(FULLARCH).o
	mv detach-$(FULLARCH).o detach.o

clean:
	rm -f *.o $(EXE) bc-attach.* bc-detach.* test arch/*.o
