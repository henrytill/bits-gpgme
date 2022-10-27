#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "data.h"

enum {
  SUCCESS = 0,
  FAILURE = 1,
};

static const char *const CIPHERTEXT = "ciphertext.asc";
static const char *const OUTPUT = "output.txt";

int main(int argc, char *argv[]) {
  FILE *ciphertext = NULL;
  FILE *output = NULL;

  (void)argc;
  (void)argv;

  const size_t inputsz = strlen(INPUT);
  char buf[inputsz + 1];

  {
    ciphertext = fopen(CIPHERTEXT, "wb");
    if (ciphertext == NULL) {
      perror("failed to open file");
      return EXIT_FAILURE;
    }
    if (cipher_encrypt(FINGERPRINT, INPUT, inputsz, ciphertext, GNUPGHOME) != SUCCESS) {
      perror("failed to encrypt");
      fclose(ciphertext);
      remove(CIPHERTEXT);
      return EXIT_FAILURE;
    }
    fclose(ciphertext);
    ciphertext = NULL;
  }

  {
    ciphertext = fopen(CIPHERTEXT, "r");
    if (ciphertext == NULL) {
      perror("failed to open file");
      remove(CIPHERTEXT);
      return EXIT_FAILURE;
    }
    output = fopen(OUTPUT, "wb");
    if (output == NULL) {
      perror("failed to open file");
      fclose(ciphertext);
      remove(CIPHERTEXT);
      return EXIT_FAILURE;
    }
    if (cipher_decrypt(FINGERPRINT, ciphertext, output, GNUPGHOME) != SUCCESS) {
      perror("failed to decrypt");
      fclose(ciphertext);
      remove(CIPHERTEXT);
      fclose(output);
      remove(OUTPUT);
    }
    fclose(ciphertext);
    remove(CIPHERTEXT);
    fclose(output);
    ciphertext = NULL;
    output = NULL;
  }

  {
    output = fopen(OUTPUT, "r");
    if (output == NULL) {
      perror("failed to open file");
      remove(OUTPUT);
      return EXIT_FAILURE;
    }
    while (fgets(buf, (int)sizeof buf, output) != NULL) continue;
    fclose(output);
    remove(OUTPUT);
    output = NULL;
  }

  if (strcmp(INPUT, buf) != 0) return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
