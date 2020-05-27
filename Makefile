PREFIX      = /usr/local
PROJECT_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

override CFLAGS  += -std=c99 -Wall -Werror -Wextra -Wpedantic
override CFLAGS  += $(shell gpgme-config --cflags)
override LDFLAGS += $(shell gpgme-config --libs)

ENCRYPT_SRC = encrypt.c util.c
ENCRYPT_OBJ = $(ENCRYPT_SRC:.c=.o)
DECRYPT_SRC = decrypt.c util.c
DECRYPT_OBJ = $(DECRYPT_SRC:.c=.o)
EXE         = encrypt decrypt

.PHONY: all
all: $(EXE)

.PHONY: debug
debug: CFLAGS += -DNDEBUG -g
debug: all

$(ENCRYPT_OBJ): config.h util.h Makefile

$(DECRYPT_OBJ): config.h util.h Makefile

.c.o:
	$(CC) -o $@ -c $< $(CFLAGS)

encrypt: $(ENCRYPT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

decrypt: $(DECRYPT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

compile_commands.json: clean
	bear make

.PHONY: check
check: export GNUPGHOME = $(PROJECT_DIR)/example/gnupg
check: $(EXE)
	./test.sh

.PHONY: clean
clean:
	rm -f $(EXE)
	rm -f $(ENCRYPT_OBJ)
	rm -f $(DECRYPT_OBJ)
