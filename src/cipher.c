#include <locale.h>
#include <stdbool.h>
#include <stdio.h>

#include <gpgme.h>

#include "cipher.h"

#define FAILINIT    "failed to initialize engine"
#define FAILNEW     "failed to create context"
#define FAILHOME    "failed to set homedir"
#define FAILKEY     "failed to fetch key"
#define FAILINPUT   "failed to create input data"
#define FAILOUTPUT  "failed to create output data"
#define FAILENCRYPT "failed to encrypt"
#define FAILDECRYPT "failed to decrypt"
#define FAILWRITE   "failed to write"
#define FAILSEEK    "failed to seek"
#define FAILREAD    "failed to read"

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
  gpgme_error_t err;

  setlocale(LC_ALL, "");
  gpgme_check_version(NULL);
  err = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
  if (err != SUCCESS)
    return err;
#ifdef LC_MESSAGES
  err = gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
  if (err != SUCCESS)
    return err;
#endif
  return gpgme_engine_check_version(proto);
}

static void printerr(gpgme_error_t err, char *msg) {
  fprintf(stderr, "%s: %s: %s\n", msg,
          gpgme_strsource(err), gpgme_strerror(err));
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
    printerr(err, FAILSEEK);
    return FAILURE;
  }
  while ((off = gpgme_data_read(data, buf, BUFSZ)) > 0)
    fwrite(buf, (size_t)off, 1, fp);
  if (off == -1) {
    err = gpgme_error_from_errno((int)off);
    printerr(err, FAILREAD);
    return FAILURE;
  }
  return SUCCESS;
}

int cipher_encrypt(const char *fgpt, const char *input, size_t inputsz,
                   FILE *fpout, const char *home) {
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

  err = gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  if (err != SUCCESS) {
    printerr(err, FAILENCRYPT);
    goto out3;
  }

  if (writedata(out, fpout) != SUCCESS) {
    perror(FAILWRITE);
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

  if (writedata(out, fpout) != SUCCESS) {
    perror(FAILWRITE);
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
