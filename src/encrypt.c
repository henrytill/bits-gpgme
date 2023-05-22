#include <stdio.h>
#include <string.h>

#include "cipher.h"
#include "data.h"

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    const size_t input_len = strlen(INPUT);

    return cipher_encrypt(FINGERPRINT, INPUT, input_len, stdout, NULL);
}
