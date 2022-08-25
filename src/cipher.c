#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpgme.h>

#include "cipher.h"

#define FAILINIT    "could not initialize engine"
#define FAILNEW     "could not create context"
#define FAILHOME    "could not set homedir"
#define FAILKEY     "could not fetch key"
#define FAILINPUT   "could not create input data"
#define FAILOUTPUT  "could not create output data"
#define FAILENCRYPT "could not encrypt"
#define FAILDECRYPT "could not decrypt"

enum {
  KEYSZ = 2,   /* NULL-terminated array of length 1 */
  BUFSZ = 512, /* Size of buffer for printing data */
};

enum {
  SUCCESS = 0,
  FAILURE = 1,
};

enum {
  KEY = 0,
  END = 1,
};

/* https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html */
static gpgme_error_t init(gpgme_protocol_t proto) {
  setlocale(LC_ALL, "");
  gpgme_check_version(NULL);
  gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

#ifdef LC_MESSAGES
  gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif

  return gpgme_engine_check_version(proto);
}

static void printerr(gpgme_error_t err, char *msg) {
  fprintf(stderr, "%s: %s: %s\n", msg, gpgme_strsource((err)), gpgme_strerror((err)));
}

#ifdef PRINT_KEY
static void printkey(gpgme_key_t key) {
  printf("%s:", key->subkeys->keyid);

  if (key->uids && key->uids->name)
    printf(" %s", key->uids->name);

  if (key->uids && (strcmp(key->uids->email, "") != 0))
    printf(" <%s>", key->uids->email);

  putchar('\n');
}
#else
static inline void printkey(gpgme_key_t key) {
  (void)key;
}
#endif

static int writedata(gpgme_data_t data, FILE *fp) {
  gpgme_off_t off;
  gpgme_error_t err;
  char buf[BUFSZ + 1];

  off = gpgme_data_seek(data, 0, SEEK_SET);
  if (off != 0) {
    err = gpgme_error_from_errno((int)off);
    printerr(err, "could not seek");
    return FAILURE;
  }

  while ((off = gpgme_data_read(data, buf, BUFSZ)) > 0)
    fwrite(buf, (size_t)off, 1, fp);

  if (off == -1) {
    err = gpgme_error_from_errno((int)off);
    printerr(err, "could not read");
    return FAILURE;
  }

  return SUCCESS;
}

int cipher_encrypt(const char *fgpt, const char *input, size_t inputsz, FILE *fpout, const char *home) {
  int ret = FAILURE;
  gpgme_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_key_t key[KEYSZ];
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;
  gpgme_encrypt_flags_t flags;

  err = init(GPGME_PROTOCOL_OPENPGP);
  if (err != SUCCESS) {
    printerr(err, FAILINIT);
    return FAILURE;
  }

  err = gpgme_new(&ctx);
  if (err != SUCCESS) {
    printerr(err, FAILNEW);
    return FAILURE;
  }

  err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home);
  if (err != SUCCESS) {
    printerr(err, FAILHOME);
    goto out0;
  }

  err = gpgme_get_key(ctx, fgpt, &key[KEY], true);
  if (err != SUCCESS) {
    printerr(err, FAILKEY);
    goto out0;
  }
  key[END] = NULL;

  printkey(key[KEY]);

  gpgme_set_armor(ctx, true);

  err = gpgme_data_new_from_mem(&in, input, inputsz, true);
  if (err != SUCCESS) {
    printerr(err, FAILINPUT);
    goto out1;
  }

  err = gpgme_data_new(&out);
  if (err != SUCCESS) {
    printerr(err, FAILOUTPUT);
    goto out2;
  }

  flags = GPGME_ENCRYPT_ALWAYS_TRUST;
  err = gpgme_op_encrypt(ctx, key, flags, in, out);
  if (err != SUCCESS) {
    printerr(err, FAILENCRYPT);
    goto out3;
  }

  if (writedata(out, fpout) != SUCCESS) {
    goto out3;
  }

  ret = SUCCESS;
out3:
  gpgme_data_release(out);
out2:
  gpgme_data_release(in);
out1:
  gpgme_key_release(key[KEY]);
out0:
  gpgme_release(ctx);
  return ret;
}

int cipher_decrypt(const char *fgpt, FILE *fpin, FILE *fpout, const char *home) {
  int ret = FAILURE;
  gpgme_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_key_t key[KEYSZ];
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

  err = init(GPGME_PROTOCOL_OPENPGP);
  if (err != SUCCESS) {
    printerr(err, FAILINIT);
    return FAILURE;
  }

  err = gpgme_new(&ctx);
  if (err != SUCCESS) {
    printerr(err, FAILNEW);
    return FAILURE;
  }

  err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, NULL, home);
  if (err != SUCCESS) {
    printerr(err, FAILNEW);
    goto out0;
  }

  err = gpgme_get_key(ctx, fgpt, &key[KEY], true);
  if (err != SUCCESS) {
    printerr(err, FAILKEY);
    goto out0;
  }
  key[END] = NULL;

  printkey(key[KEY]);

  err = gpgme_data_new_from_stream(&in, fpin);
  if (err != SUCCESS) {
    printerr(err, FAILINPUT);
    goto out1;
  }

  err = gpgme_data_new(&out);
  if (err != SUCCESS) {
    printerr(err, FAILOUTPUT);
    goto out2;
  }

  err = gpgme_op_decrypt(ctx, in, out);
  if (err != SUCCESS) {
    printerr(err, FAILDECRYPT);
    goto out3;
  }

  if (writedata(out, fpout) != SUCCESS)
    goto out3;

  ret = SUCCESS;
out3:
  gpgme_data_release(out);
out2:
  gpgme_data_release(in);
out1:
  gpgme_key_release(key[KEY]);
out0:
  gpgme_release(ctx);
  return ret;
}
