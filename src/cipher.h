#ifndef GPGME_BITS_CIPHER_H
#define GPGME_BITS_CIPHER_H

#include <stddef.h>
#include <stdio.h>

int cipher_encrypt(const char *fgpt, const char *input, size_t inputsz, FILE *fpout, const char *home);

int cipher_decrypt(const char *fgpt, FILE *fpin, FILE *fpout, const char *home);

#endif /* GPGME_BITS_CIPHER_H */
