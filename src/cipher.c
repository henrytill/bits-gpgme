#include <locale.h>
#include <stdbool.h>
#include <stdio.h>

#include <gpgme.h>

#include "cipher.h"

enum {
  BUFFER_SIZE = 512, /* Size of buffer for printing data */
};

#define FAILURES                            \
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

static void printerr(gpgme_error_t err, int i) {
  fprintf(stderr, "%s: %s: %s\n", FAILURE_MESSAGES[i],
          gpgme_strsource(err), gpgme_strerror(err));
}

/* https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html */
static gpgme_error_t init(gpgme_protocol_t proto) {
  gpgme_error_t err;

  setlocale(LC_ALL, "");
  gpgme_check_version(NULL);
  err = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
  if (err != 0) {
    return err;
  }
#ifdef LC_MESSAGES
  err = gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
  if (err != 0) {
    return err;
  }
#endif
  return gpgme_engine_check_version(proto);
}

#ifdef PRINT_KEY
static void printkey(gpgme_key_t key) {
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
static inline void printkey(gpgme_key_t key) {
  (void)key;
}
#endif

static int writedata(gpgme_data_t data, FILE *fp) {
  gpgme_off_t off;
  gpgme_error_t error;
  char buffer[BUFFER_SIZE + 1];

  off = gpgme_data_seek(data, 0, SEEK_SET);
  if (off != 0) {
    error = gpgme_error_from_errno((int)off);
    printerr(error, FAILURE_SEEK);
    return -1;
  }
  while ((off = gpgme_data_read(data, buffer, BUFFER_SIZE)) > 0) {
    fwrite(buffer, (size_t)off, 1, fp);
  }
  if (off == -1) {
    error = gpgme_error_from_errno((int)off);
    printerr(error, FAILURE_READ);
    return -1;
  }
  return 0;
}

int cipher_encrypt(const char *fingerprint, const char *input, size_t input_size,
                   FILE *file_out, const char *home) {
  int ret = -1;
  gpgme_error_t error;
  gpgme_ctx_t ctx = NULL;
  gpgme_key_t key[] = {NULL, NULL};
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

  error = init(GPGME_PROTOCOL_OPENPGP);
  if (error != 0) {
    printerr(error, FAILURE_INIT);
    return -1;
  }

  error = gpgme_new(&ctx);
  if (error != 0) {
    printerr(error, FAILURE_NEW);
    return -1;
  }

  error = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home);
  if (error != 0) {
    printerr(error, FAILURE_HOME);
    goto out0;
  }

  error = gpgme_get_key(ctx, fingerprint, &key[0], true);
  if (error != 0) {
    printerr(error, FAILURE_FETCH);
    goto out0;
  }

  printkey(key[0]);
  gpgme_set_armor(ctx, true);

  error = gpgme_data_new_from_mem(&in, input, input_size, true);
  if (error != 0) {
    printerr(error, FAILURE_INPUT);
    goto out1;
  }

  error = gpgme_data_new(&out);
  if (error != 0) {
    printerr(error, FAILURE_OUTPUT);
    goto out2;
  }

  error = gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  if (error != 0) {
    printerr(error, FAILURE_ENCRYPT);
    goto out3;
  }

  if (writedata(out, file_out) != 0) {
    perror(FAILURE_MESSAGES[FAILURE_WRITE]);
    goto out3;
  }

  ret = 0;
out3:
  gpgme_data_release(out);
out2:
  gpgme_data_release(in);
out1:
  gpgme_key_release(key[0]);
out0:
  gpgme_release(ctx);
  return ret;
}

int cipher_decrypt(const char *fingerprint, FILE *file_in, FILE *file_out, const char *home) {
  int ret = -1;
  gpgme_error_t error;
  gpgme_ctx_t ctx = NULL;
  gpgme_key_t key[] = {NULL, NULL};
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

  error = init(GPGME_PROTOCOL_OPENPGP);
  if (error != 0) {
    printerr(error, FAILURE_INIT);
    return -1;
  }

  error = gpgme_new(&ctx);
  if (error != 0) {
    printerr(error, FAILURE_NEW);
    return -1;
  }

  error = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home);
  if (error != 0) {
    printerr(error, FAILURE_NEW);
    goto out0;
  }

  error = gpgme_get_key(ctx, fingerprint, &key[0], true);
  if (error != 0) {
    printerr(error, FAILURE_FETCH);
    goto out0;
  }

  printkey(key[0]);

  error = gpgme_data_new_from_stream(&in, file_in);
  if (error != 0) {
    printerr(error, FAILURE_INPUT);
    goto out1;
  }

  error = gpgme_data_new(&out);
  if (error != 0) {
    printerr(error, FAILURE_OUTPUT);
    goto out2;
  }

  error = gpgme_op_decrypt(ctx, in, out);
  if (error != 0) {
    printerr(error, FAILURE_DECRYPT);
    goto out3;
  }

  if (writedata(out, file_out) != 0) {
    perror(FAILURE_MESSAGES[FAILURE_WRITE]);
    goto out3;
  }

  ret = 0;
out3:
  gpgme_data_release(out);
out2:
  gpgme_data_release(in);
out1:
  gpgme_key_release(key[0]);
out0:
  gpgme_release(ctx);
  return ret;
}
