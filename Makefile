CFLAGS=-Wall -g
LIBS=-lutil
LDFLAGS=$(LIBS)

EXE=blindtty retty

all: $(EXE)

blindtty: blindtty.c
retty: retty.c

clean:
	rm -f *.o $(EXE)
