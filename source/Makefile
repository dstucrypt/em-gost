ALL: build

BUILD=js
EMCC=/opt/ems/emsdk_portable/emscripten/1.16.0/emcc

ifeq ($(BUILD),native)
CC=cc
else
CC=$(EMCC)
endif

OBJS=gost89.o gosthash.o util.o sbox.o iit.o pbes2.o hash.o dstszi.o api_crypt.o

build: uadstu.js

%.o: %.c
	$(CC) $< -o $@ -O3 -c

clean:
	rm -f $(OBJS)

uadstu.js: $(OBJS)
	 $(CC) $(OBJS) \
		 --post-js ./fixup.js \
		 -o $@ \
		 -s EXPORTED_FUNCTIONS="[ \
				'_iit_convert_password', '_iit_decode_data', \
				'_pbes2_convert_password', '_pbes2_decode_data', \
				'_compute_hash', '_gost_key_wrap', '_gost_key_unwrap', \
				'_gost_crypt' \
				]" \
				-s 'EXPORT_NAME="emdstu"' \
				-s NO_EXIT_RUNTIME=1 -O3

uadstu: entry.o $(OBJS)
	$(CC) $< $(OBJS) -o $@

test_dstszi: test_dstszi.o $(OBJS)
	$(CC) $< $(OBJS) -o $@
	./$@

test: test_dstszi
