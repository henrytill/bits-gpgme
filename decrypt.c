#include "crypto.h"
#include "data.h"

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    return crypto_decrypt(FINGERPRINT, stdin);
}
