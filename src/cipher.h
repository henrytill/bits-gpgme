#ifndef GPGME_BITS_CIPHER_H
#define GPGME_BITS_CIPHER_H

#include <stddef.h>
#include <stdio.h>

/* Encrypts given input using key defined by given key fingerprint  */
int cipher_encrypt(const char *key_fingerprint, const char *input,
	size_t input_len, FILE *output_stream, const char *home_dir);

/* Decrypts given input stream using key defined by given key fingerprint */
int cipher_decrypt(const char *key_fingerprint, FILE *input_stream,
	FILE *output_stream, const char *home_dir);

#endif /* GPGME_BITS_CIPHER_H */
