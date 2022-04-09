#include <string.h>

#include "crypto.h"
#include "data.h"

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    const size_t input_len = strlen(INPUT);

    return crypto_encrypt(FINGERPRINT, INPUT, input_len);
}
