PREFIX ?= /usr/local
WFLAGS ?= -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast -Wcast-align -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs -Wno-unknown-pragmas -Wpointer-arith -Wredundant-decls -Wstrict-prototypes -Wswitch-enum -Wno-type-limits
CFLAGS ?= -O3 -mcpu=native -fno-exceptions -flto $(WFLAGS)
CFLAGS += -I. -Iext/libhydrogen
OBJ = ext/libhydrogen/hydrogen.o src/encp.o src/safeio.o
STRIP ?= strip

SRC = \
	ext/libhydrogen/hydrogen.c \
	src/common.h \
	src/encp.c \
	src/encp.h \
	src/safeio.c \
	src/safeio.h

all: bin test

bin: encp

$(OBJ): $(SRC)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

encp: $(OBJ)
	$(CC) $(CFLAGS) -o encp $(OBJ)

ext/libhydrogen/hydrogen.c:
	git submodule update --init || echo "** Make sure you cloned the repository **" >&2

install: all
	-$(STRIP) --strip-all encp 2> /dev/null || $(STRIP) encp 2> /dev/null
	mkdir -p $(PREFIX)/bin
	install -o 0 -g 0 -m 0755 encp $(PREFIX)/bin 2> /dev/null || install -m 0755 encp $(PREFIX)/bin

uninstall:
	rm -f $(PREFIX)/bin/encp

test: bin
	@echo test |./encp -k encp |./encp -d -k encp >/dev/null

.PHONY: clean

clean:
	rm -f encp $(OBJ)

distclean: clean

.SUFFIXES: .c .o

check: test

distclean: clean
