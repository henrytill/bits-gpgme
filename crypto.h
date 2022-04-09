#ifndef GPGME_BITS_CRYPTO_H
#define GPGME_BITS_CRYPTO_H

#include <stddef.h>
#include <stdio.h>

/* Encrypts given input using key defined by given key fingerprint  */
int crypto_encrypt(char *key_fingerprint, char *input, size_t input_len);

/* Decrypts given input stream using key defined by given key fingerprint */
int crypto_decrypt(char *key_fingerprint, FILE *input_stream);

#endif /* GPGME_BITS_CRYPTO_H */
