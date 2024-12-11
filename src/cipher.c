#include "cipher.h"

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef PRINT_KEY
#  include <string.h>
#endif

#include <gpgme.h>

enum {
  BUFFER_SIZE = 512, // Size of buffer used by write_data
};

enum failure {
  FAILURE_INIT,
  FAILURE_NEW,
  FAILURE_HOME,
  FAILURE_FETCH,
  FAILURE_INPUT,
  FAILURE_OUTPUT,
  FAILURE_ENCRYPT,
  FAILURE_DECRYPT,
  FAILURE_WRITE,
  FAILURE_SEEK,
  FAILURE_READ,
  FAILURE_MAX,
};

static const char *const FAILURE_MESSAGES[] = {
  [FAILURE_INIT] = "failed to initialize engine",
  [FAILURE_NEW] = "failed to create context",
  [FAILURE_HOME] = "failed to set homedir",
  [FAILURE_FETCH] = "failed to fetch key",
  [FAILURE_INPUT] = "failed to create input data",
  [FAILURE_OUTPUT] = "failed to create output data",
  [FAILURE_ENCRYPT] = "failed to encrypt",
  [FAILURE_DECRYPT] = "failed to decrypt",
  [FAILURE_WRITE] = "failed to write",
  [FAILURE_SEEK] = "failed to seek",
  [FAILURE_READ] = "failed to read",
  [FAILURE_MAX] = NULL,
};

static void print_error(gpgme_error_t error, enum failure f) {
  (void)printf("%s: %s: %s\n", FAILURE_MESSAGES[f],
               gpgme_strsource(error), gpgme_strerror(error));
}

#ifdef LC_MESSAGES
static gpgme_error_t set_locale_lc_messages(void) {
  return gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
}
#else
static inline gpgme_error_t set_locale_lc_messages(void) {
  return 0;
}
#endif

// https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html
static gpgme_error_t init(gpgme_protocol_t proto) {
  gpgme_error_t error;

  (void)setlocale(LC_ALL, "");
  gpgme_check_version(NULL);
  error = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
  if (error != 0) {
    return error;
  }
  error = set_locale_lc_messages();
  if (error != 0) {
    return error;
  }
  return gpgme_engine_check_version(proto);
}

#ifdef PRINT_KEY
static void print_key(gpgme_key_t key) {
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
static inline void print_key(__attribute__((unused)) gpgme_key_t key) {
}
#endif

static int write_data(gpgme_data_t data, FILE *fp) {
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
    (void)fwrite(buffer, (size_t)off, 1, fp);
  }
  if (off == -1) {
    error = gpgme_error_from_errno((int)off);
    print_error(error, FAILURE_READ);
    return -1;
  }
  return 0;
}

int cipher_encrypt(const char *fingerprint, const char *input, const size_t input_len,
                   FILE *file_out, const char *home) {
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
  error = gpgme_data_new_from_mem(&in, input, input_len, true);
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

int cipher_decrypt(const char *fingerprint, FILE *file_in, FILE *file_out, const char *home) {
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
