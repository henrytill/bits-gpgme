#include <stdio.h>
#include <string.h>

#include "cipher.h"
#include "data.h"

int main(void) {
  size_t const input_len = strlen(INPUT);

  return cipher_encrypt(FINGERPRINT, INPUT, input_len, stdout, NULL);
}
