#include <locale.h>
#include <stdbool.h>
#include <stdio.h>

#include <gpgme.h>

#include "cipher.h"

enum {
    BUFFER_SIZE = 512, /* Size of buffer for printing data */
};

#define FAILURES                              \
    X(INIT, "failed to initialize engine")    \
    X(NEW, "failed to create context")        \
    X(HOME, "failed to set homedir")          \
    X(FETCH, "failed to fetch key")           \
    X(INPUT, "failed to create input data")   \
    X(OUTPUT, "failed to create output data") \
    X(ENCRYPT, "failed to encrypt")           \
    X(DECRYPT, "failed to decrypt")           \
    X(WRITE, "failed to write")               \
    X(SEEK, "failed to seek")                 \
    X(READ, "failed to read")

enum {
#define X(variant, str) FAILURE_##variant,
    FAILURES
#undef X
};

static const char *const FAILURE_MESSAGES[] = {
#define X(variant, str) [FAILURE_##variant] = (str),
    FAILURES
#undef X
};

static void print_error(gpgme_error_t error, int i)
{
    fprintf(stderr, "%s: %s: %s\n", FAILURE_MESSAGES[i],
            gpgme_strsource(error), gpgme_strerror(error));
}

/* https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html */
static gpgme_error_t init(gpgme_protocol_t proto)
{
    gpgme_error_t error;

    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    error = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    if (error != 0) {
        return error;
    }
#ifdef LC_MESSAGES
    error = gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
    if (error != 0) {
        return error;
    }
#endif
    return gpgme_engine_check_version(proto);
}

#ifdef PRINT_KEY
static void print_key(gpgme_key_t key)
{
    printf("%s:", key->subkeys->keyid);
    if (key->uids && key->uids->name) {
        printf(" %s", key->uids->name);
    }
    if (key->uids && (strcmp(key->uids->email, "") != 0)) {
        printf(" <%s>", key->uids->email);
    }
    putchar('\n');
}
#else
static inline void print_key(gpgme_key_t key)
{
    (void)key;
}
#endif

static int write_data(gpgme_data_t data, FILE *fp)
{
    gpgme_off_t off;
    gpgme_error_t error;
    char buffer[BUFFER_SIZE + 1];

    off = gpgme_data_seek(data, 0, SEEK_SET);
    if (off != 0) {
        error = gpgme_error_from_errno((int)off);
        print_error(error, FAILURE_SEEK);
        return -1;
    }
    while ((off = gpgme_data_read(data, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, (size_t)off, 1, fp);
    }
    if (off == -1) {
        error = gpgme_error_from_errno((int)off);
        print_error(error, FAILURE_READ);
        return -1;
    }
    return 0;
}

int cipher_encrypt(const char *fingerprint, const char *input, size_t input_size,
                   FILE *file_out, const char *home)
{
    int ret = -1;
    gpgme_error_t error;

    error = init(GPGME_PROTOCOL_OPENPGP);
    if (error != 0) {
        print_error(error, FAILURE_INIT);
        return -1;
    }

    gpgme_ctx_t ctx = NULL;
    error = gpgme_new(&ctx);
    if (error != 0) {
        print_error(error, FAILURE_NEW);
        return -1;
    }

    error = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home);
    if (error != 0) {
        print_error(error, FAILURE_HOME);
        goto out_release_ctx;
    }

    gpgme_key_t key[] = {NULL, NULL};
    error = gpgme_get_key(ctx, fingerprint, &key[0], true);
    if (error != 0) {
        print_error(error, FAILURE_FETCH);
        goto out_release_ctx;
    }

    print_key(key[0]);
    gpgme_set_armor(ctx, true);

    gpgme_data_t in = NULL;
    error = gpgme_data_new_from_mem(&in, input, input_size, true);
    if (error != 0) {
        print_error(error, FAILURE_INPUT);
        goto out_key_release_key;
    }

    gpgme_data_t out = NULL;
    error = gpgme_data_new(&out);
    if (error != 0) {
        print_error(error, FAILURE_OUTPUT);
        goto out_data_release_in;
    }

    error = gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (error != 0) {
        print_error(error, FAILURE_ENCRYPT);
        goto out_data_release_out;
    }

    if (write_data(out, file_out) != 0) {
        perror(FAILURE_MESSAGES[FAILURE_WRITE]);
        goto out_data_release_out;
    }

    ret = 0;
out_data_release_out:
    gpgme_data_release(out);
out_data_release_in:
    gpgme_data_release(in);
out_key_release_key:
    gpgme_key_release(key[0]);
out_release_ctx:
    gpgme_release(ctx);
    return ret;
}

int cipher_decrypt(const char *fingerprint, FILE *file_in, FILE *file_out, const char *home)
{
    int ret = -1;
    gpgme_error_t error;

    error = init(GPGME_PROTOCOL_OPENPGP);
    if (error != 0) {
        print_error(error, FAILURE_INIT);
        return -1;
    }

    gpgme_ctx_t ctx = NULL;
    error = gpgme_new(&ctx);
    if (error != 0) {
        print_error(error, FAILURE_NEW);
        return -1;
    }

    error = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home);
    if (error != 0) {
        print_error(error, FAILURE_NEW);
        goto out_release_ctx;
    }

    gpgme_key_t key[] = {NULL, NULL};
    error = gpgme_get_key(ctx, fingerprint, &key[0], true);
    if (error != 0) {
        print_error(error, FAILURE_FETCH);
        goto out_release_ctx;
    }

    print_key(key[0]);

    gpgme_data_t in = NULL;
    error = gpgme_data_new_from_stream(&in, file_in);
    if (error != 0) {
        print_error(error, FAILURE_INPUT);
        goto out_key_release_key;
    }

    gpgme_data_t out = NULL;
    error = gpgme_data_new(&out);
    if (error != 0) {
        print_error(error, FAILURE_OUTPUT);
        goto out_data_release_in;
    }

    error = gpgme_op_decrypt(ctx, in, out);
    if (error != 0) {
        print_error(error, FAILURE_DECRYPT);
        goto out_data_release_out;
    }

    if (write_data(out, file_out) != 0) {
        perror(FAILURE_MESSAGES[FAILURE_WRITE]);
        goto out_data_release_out;
    }

    ret = 0;
out_data_release_out:
    gpgme_data_release(out);
out_data_release_in:
    gpgme_data_release(in);
out_key_release_key:
    gpgme_key_release(key[0]);
out_release_ctx:
    gpgme_release(ctx);
    return ret;
}
