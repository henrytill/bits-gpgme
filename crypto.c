#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpgme.h>

#include "crypto.h"

/* It must be done */
#define EMPTY_STRING ""

/* Failure messages */
#define FAILURE_MSG_INIT       "could not initialize engine"
#define FAILURE_MSG_NEW        "could not create context"
#define FAILURE_MSG_HOME_DIR   "could not set home_dir"
#define FAILURE_MSG_GET_KEY    "could not fetch key"
#define FAILURE_MSG_NEW_INPUT  "could not create input data"
#define FAILURE_MSG_NEW_OUTPUT "could not create output data"
#define FAILURE_MSG_ENCRYPT    "could not encrypt"
#define FAILURE_MSG_DECRYPT    "could not decrypt"

/* NULL-terminated array of length 1 */
#define KEYS_LEN 2

/* Constants for accessing keys */
enum {
    KEY = 0,
    END = 1
};

/* Size of buffer for printing data */
#define BUF_LEN 512

/* Prints well-formatted error */
#define crypto_gpgme_print_error(err, msg)                                                         \
    do {                                                                                           \
        fprintf(stderr, "%s: %s: %s\n", msg, gpgme_strsource(err), gpgme_strerror(err));           \
    } while (0)

#ifdef LC_MESSAGES
static void set_locale_lc_messages(void) {
    gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
}
#else
static inline void set_locale_lc_messages(void) {}
#endif

/*
 * Initializes GPGME based on the given protocol type
 *
 * https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html
 */
static gpgme_error_t init(gpgme_protocol_t proto) {
    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

    set_locale_lc_messages();

    return gpgme_engine_check_version(proto);
}

#ifndef NDEBUG
/*
 * Prints keyid, name, and email of given key
 */
static void print_key(gpgme_key_t key) {
    /* Print keyid  */
    printf("%s:", key->subkeys->keyid);

    /* Print name */
    if (key->uids && key->uids->name) {
        printf(" %s", key->uids->name);
    }

    /* Print email */
    if (key->uids && (strcmp(key->uids->email, EMPTY_STRING) != 0)) {
        printf(" <%s>", key->uids->email);
    }

    putchar('\n');
}
#else
static inline void print_key(gpgme_key_t key) {
    (void)key;
}
#endif

/*
 * Prints data
 */
static int print_data(gpgme_data_t data, FILE *output_stream) {
    gpgme_off_t ret;
    gpgme_error_t err;
    char buf[BUF_LEN + 1];

    if ((ret = gpgme_data_seek(data, 0, SEEK_SET)) != 0) {
        err = gpgme_error_from_errno((int)ret);
        crypto_gpgme_print_error(err, "could not seek");
        return 1;
    }

    while ((ret = gpgme_data_read(data, buf, BUF_LEN)) != 0) {
        fwrite(buf, (unsigned long)ret, 1, output_stream);
    }

    if (ret) {
        err = gpgme_error_from_errno((int)ret);
        crypto_gpgme_print_error(err, "could not read");
        return 1;
    }

    return 0;
}

int crypto_encrypt(const char *key_fingerprint,
                   const char *input,
                   const size_t input_len,
                   FILE *output_stream,
                   const char *home_dir) {
    int ret = 1;
    gpgme_error_t err;
    gpgme_ctx_t ctx = NULL;
    gpgme_key_t keys[KEYS_LEN];
    gpgme_data_t in = NULL;
    gpgme_data_t out = NULL;
    gpgme_encrypt_flags_t flags;

    /* Initialize */
    if ((err = init(GPGME_PROTOCOL_OPENPGP)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_INIT);
        goto cleanup;
    }

    /* Create new context */
    if ((err = gpgme_new(&ctx)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW);
        goto cleanup;
    }

    /* Set home_dir */
    if ((err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home_dir)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_HOME_DIR);
        goto cleanup;
    }

    /* Fetch key and print its information */
    if ((err = gpgme_get_key(ctx, key_fingerprint, &keys[KEY], true)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_GET_KEY);
        goto cleanup;
    }
    keys[END] = NULL;

    print_key(keys[KEY]);

    /* Turn on ASCII-armored output */
    gpgme_set_armor(ctx, true);

    /* Create input */
    if ((err = gpgme_data_new_from_mem(&in, input, input_len, true)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW_INPUT);
        goto cleanup;
    }

    /* Create empty cipher */
    if ((err = gpgme_data_new(&out)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW_OUTPUT);
        goto cleanup;
    }

    /* Encrypt */
    flags = GPGME_ENCRYPT_ALWAYS_TRUST;
    if ((err = gpgme_op_encrypt(ctx, keys, flags, in, out)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_ENCRYPT);
        goto cleanup;
    }

    if (print_data(out, output_stream) != 0) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    gpgme_data_release(in);
    gpgme_data_release(out);
    gpgme_release(ctx);
    return ret;
}

int crypto_decrypt(const char *key_fingerprint,
                   FILE *input_stream,
                   FILE *output_stream,
                   const char *home_dir) {
    int ret = 1;
    gpgme_error_t err;
    gpgme_ctx_t ctx = NULL;
    gpgme_key_t keys[KEYS_LEN];
    gpgme_data_t in = NULL;
    gpgme_data_t out = NULL;

    /* Initialize */
    if ((err = init(GPGME_PROTOCOL_OPENPGP)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_INIT);
        goto cleanup;
    }

    /* Create new context */
    if ((err = gpgme_new(&ctx)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW);
        goto cleanup;
    }

    if ((err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home_dir)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW);
        goto cleanup;
    }

    /* Fetch key and print its information */
    if ((err = gpgme_get_key(ctx, key_fingerprint, &keys[KEY], true)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_GET_KEY);
        goto cleanup;
    }
    keys[END] = NULL;

    print_key(keys[KEY]);

    /* Create input */
    if ((err = gpgme_data_new_from_stream(&in, input_stream)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW_INPUT);
        goto cleanup;
    }

    /* Create empty output */
    if ((err = gpgme_data_new(&out)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_NEW_OUTPUT);
        goto cleanup;
    }

    /* Decrypt */
    if ((err = gpgme_op_decrypt(ctx, in, out)) != 0) {
        crypto_gpgme_print_error(err, FAILURE_MSG_DECRYPT);
        goto cleanup;
    }

    if (print_data(out, output_stream) != 0) {
        goto cleanup;
    }

    ret = 0;
cleanup:
    gpgme_data_release(in);
    gpgme_data_release(out);
    gpgme_release(ctx);
    return ret;
}
