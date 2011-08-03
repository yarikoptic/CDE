# really crappy Makefile, which will do for now

PREFIX ?= /usr/local

all: strace-4.5.20/Makefile okapi
	cd readelf-mini && make
	cd strace-4.5.20 && make
	mv -f strace-4.5.20/cde .
	mv -f strace-4.5.20/cde-exec .

install: all
	install cde cde-exec $(PREFIX)/bin

strace-4.5.20/Makefile:
	cd strace-4.5.20 && ./configure

clean:
	cd readelf-mini && make clean
	cd strace-4.5.20 && make clean
	rm -f cde cde-exec okapi

okapi: strace-4.5.20/okapi.c strace-4.5.20/okapi.h
	gcc -Wall -g -O2 -D_GNU_SOURCE -DOKAPI_STANDALONE strace-4.5.20/okapi.c -o okapi
