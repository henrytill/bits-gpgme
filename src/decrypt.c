#include <stdio.h>

#include "cipher.h"
#include "data.h"

int main(void)
{
    return cipher_decrypt(FINGERPRINT, stdin, stdout, NULL);
}
