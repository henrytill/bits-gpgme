#include <stdio.h>

#include "cipher.h"
#include "data.h"

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  return cipher_decrypt(FINGERPRINT, stdin, stdout, NULL);
}
