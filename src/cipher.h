#ifndef GPGME_BITS_CIPHER_H
#define GPGME_BITS_CIPHER_H

#include <stdio.h>

int cipher_encrypt(char const *fingerprint, char const *input, size_t const input_len, FILE *file_out, char const *home);

int cipher_decrypt(char const *fingerprint, FILE *file_in, FILE *file_out, char const *home);

#endif /* GPGME_BITS_CIPHER_H */
