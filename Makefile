CC?=gcc
CFLAGS?= -W -Wall -O2 -s
CFLAGS+= -DNDEBUG
#CFLAGS=-W -Wall -g
LDFLAGS+=-lrt

DESTDIR?=/usr/local

all: des21xx

clean:
	rm -f *.o des21xx

des21xx: des21xx.c
	$(CC) $(CFLAGS) $(LDFLAGS) \
	des21xx.c \
	-o des21xx

install:
	mkdir -p ${DESTDIR}/bin 2> /dev/null
	cp -p des21xx ${DESTDIR}/bin
