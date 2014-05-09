ALL: build

EMCC=/opt/ems/emsdk_portable/emscripten/1.16.0/emcc
OBJS=entry.o gost89.o gosthash.o util.o sbox.o

build: uadstu.js

%.o: %.c
	$(EMCC) $< -o $@ -O3

uadstu.js: $(OBJS)
	 $(EMCC) $(OBJS) -o $@ -s EXPORTED_FUNCTIONS="['_convert_password', '_decode_data']" -s NO_EXIT_RUNTIME=1 -O3
