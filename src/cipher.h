#ifndef GPGME_BITS_CIPHER_H
#define GPGME_BITS_CIPHER_H

#include <stddef.h>
#include <stdio.h>

int cipher_encrypt(const char *fingerprint, const char *input, size_t input_size, FILE *file_out, const char *home);

int cipher_decrypt(const char *fingerprint, FILE *file_in, FILE *file_out, const char *home);

#endif /* GPGME_BITS_CIPHER_H */
