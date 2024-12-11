#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "data.h"

static const char *const CIPHERTEXT = "ciphertext.asc";
static const char *const OUTPUT = "output.txt";

int main(void) {
  int rc;
  FILE *ciphertext = NULL;
  FILE *output = NULL;

  const size_t input_size = strlen(INPUT);
  char buf[input_size + 1];

  {
    ciphertext = fopen(CIPHERTEXT, "wb");
    if (ciphertext == NULL) {
      perror("failed to open file");
      return EXIT_FAILURE;
    }
    rc = cipher_encrypt(FINGERPRINT, INPUT, input_size, ciphertext, GNUPGHOME);
    if (rc != 0) {
      perror("failed to encrypt");
      (void)fclose(ciphertext);
      (void)remove(CIPHERTEXT);
      return EXIT_FAILURE;
    }
    (void)fclose(ciphertext);
    ciphertext = NULL;
  }

  {
    ciphertext = fopen(CIPHERTEXT, "r");
    if (ciphertext == NULL) {
      perror("failed to open file");
      (void)remove(CIPHERTEXT);
      return EXIT_FAILURE;
    }
    output = fopen(OUTPUT, "wb");
    if (output == NULL) {
      perror("failed to open file");
      (void)fclose(ciphertext);
      (void)remove(CIPHERTEXT);
      return EXIT_FAILURE;
    }
    rc = cipher_decrypt(FINGERPRINT, ciphertext, output, GNUPGHOME);
    if (rc != 0) {
      perror("failed to decrypt");
      (void)fclose(ciphertext);
      (void)remove(CIPHERTEXT);
      (void)fclose(output);
      (void)remove(OUTPUT);
    }
    (void)fclose(ciphertext);
    (void)remove(CIPHERTEXT);
    (void)fclose(output);
    ciphertext = NULL;
    output = NULL;
  }

  {
    output = fopen(OUTPUT, "r");
    if (output == NULL) {
      perror("failed to open file");
      (void)remove(OUTPUT);
      return EXIT_FAILURE;
    }
    while (fgets(buf, (int)sizeof buf, output) != NULL) {
      // continue;
    }
    (void)fclose(output);
    (void)remove(OUTPUT);
    output = NULL;
  }

  return strcmp(INPUT, buf) != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
