PREFIX      = /usr/local
PROJECT_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

override CFLAGS  += -std=c99 -Wall -Werror -Wextra -Wpedantic
override CFLAGS  += $(shell gpgme-config --cflags)
override LDFLAGS += $(shell gpgme-config --libs)

.PHONY: all
all: encrypt

encrypt.o: encrypt.c Makefile
	$(CC) -o $@ -c $< $(CFLAGS)

encrypt: encrypt.o
	$(CC) -o $@ $< $(LDFLAGS)

.PHONY: test
test: export GNUPGHOME = $(PROJECT_DIR)/example/gnupg
test: encrypt
	./$<

.PHONY: install
install: encrypt
	mkdir -p $(PREFIX)/bin
	install $< $(PREFIX)/bin/$<

.PHONY: clean
clean:
	rm -f encrypt
	rm -f encrypt.o
