.SUFFIXES:
.SUFFIXES: .c .o

CFLAGS = -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -g
LDFLAGS =

VPATH = src:test

PRINT_KEY = 1

ifeq ($(PRINT_KEY),1)
CFLAGS += -DPRINT_KEY
endif

BIN =\
	decrypt \
	encrypt \
	roundtrip

GEN =\
	_cipher_cffi.c

OBJ =\
	cipher.o \
	_cipher_cffi.o

LIB =\
	libcipher.so \
	_cipher_cffi.so

.PHONY: all
all: $(LIB) $(BIN)

cipher.o: CFLAGS += -fPIC -DPRINT_KEY
cipher.o: cipher.c cipher.h

libcipher.so: LDFLAGS += -Wl,-soname,libcipher.so
libcipher.so: LDLIBS += -lgpgme
libcipher.so: cipher.o

encrypt: encrypt.c libcipher.so

decrypt: decrypt.c libcipher.so

roundtrip: CFLAGS += -Isrc
roundtrip: roundtrip.c libcipher.so

lib%.so: %.o
	$(CC) -fPIC -shared $(LDFLAGS) $^ $(LDLIBS) -o $@

_cipher_cffi.so: libcipher.so cipher_build.py
	python3 test/cipher_build.py $@

.PHONY: check test
check test: roundtrip _cipher_cffi.so
	env -i LD_LIBRARY_PATH=$(CURDIR) ./roundtrip
	env -i LD_LIBRARY_PATH=$(CURDIR) PYTHONPATH=$(CURDIR) python3 test/roundtrip.py

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ) $(LIB) $(GEN)
