PREFIX      = /usr/local
PROJECT_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

override CFLAGS  += -std=c99 -Wall -Werror -Wextra -Wpedantic -g
override CFLAGS  += $(shell gpgme-config --cflags)
override LDFLAGS += $(shell gpgme-config --libs)

SRC = encrypt.c util.c
OBJ = $(SRC:.c=.o)

.PHONY: all
all: encrypt

$(OBJ): config.h util.h Makefile

.c.o:
	$(CC) -o $@ -c $< $(CFLAGS)

encrypt: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

compile_commands.json: clean Makefile
	bear make

.PHONY: check
check: export GNUPGHOME = $(PROJECT_DIR)/example/gnupg
check: encrypt
	./$<

.PHONY: install
install: encrypt
	mkdir -p $(PREFIX)/bin
	install $< $(PREFIX)/bin/$<

clean:
	rm -f encrypt
	rm -f $(OBJ)
