ALL: build

BUILD=js
EMCC=/opt/ems/emsdk_portable/emscripten/1.16.0/emcc

ifeq ($(BUILD),native)
CC=cc
else
CC=$(EMCC)
endif

OBJS=entry.o gost89.o gosthash.o util.o sbox.o iit.o pbes2.o

build: uadstu.js

%.o: %.c
	$(CC) $< -o $@ -O3 -c

uadstu.js: $(OBJS)
	 $(CC) $(OBJS) -o $@ -s EXPORTED_FUNCTIONS="['_convert_password', '_decode_data']" -s NO_EXIT_RUNTIME=1 -O3

uadstu: $(OBJS)
	$(CC) $(OBJS) -o $@
