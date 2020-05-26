#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpgme.h>

#include "config.h"

/* The contents of argv[0] */
static char *executable_name = NULL;

/* It must be done */
#define EMPTY_STRING ""

/* NULL-terminated array of length 1 */
#define KEYS_LEN 2

/* Size of buffer for printing data */
#define BUF_LEN 512

/* Prints well-formatted error, releases context, and exits */
#define gpgme_failure(ctx, err, msg)                                           \
	do {                                                                   \
		fprintf(stderr,                                                \
		        "%s: %s: %s: %s\n",                                    \
		        executable_name,                                       \
		        msg,                                                   \
		        gpgme_strsource(err),                                  \
		        gpgme_strerror(err));                                  \
		if (ctx) {                                                     \
			gpgme_release(ctx);                                    \
		}                                                              \
		exit(1);                                                       \
	} while (0)

/*
 * Initializes GPGME based on the given protocol type
 *
 * https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html
 */
gpgme_error_t
init_gpgme(gpgme_protocol_t proto)
{
	setlocale(LC_ALL, "");
	gpgme_check_version(NULL);
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

#ifdef LC_MESSAGES
	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif

	return gpgme_engine_check_version(proto);
}

/*
 * Prints keyid, name, and email of given key
 */
void
print_key_info(gpgme_key_t key)
{
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

/*
 * Prints data
 */
void
print_data(gpgme_ctx_t ctx, gpgme_data_t data)
{
	off_t         ret;
	gpgme_error_t err;
	char          buf[BUF_LEN + 1];

	if ((ret = gpgme_data_seek(data, 0, SEEK_SET)) != 0) {
		err = gpgme_error_from_errno(ret);
		gpgme_failure(ctx, err, "could not seek");
	}

	while ((ret = gpgme_data_read(data, buf, BUF_LEN)) != 0) {
		fwrite(buf, ret, 1, stdout);
	}

	if (ret != 0) {
		err = gpgme_error_from_errno(ret);
		gpgme_failure(ctx, err, "could not read");
	}
}

int
main(int argc, char *argv[])
{
	gpgme_error_t err;
	gpgme_ctx_t   ctx;
	gpgme_key_t   keys[KEYS_LEN];
	gpgme_data_t  in;
	gpgme_data_t  out;

	(void)argc;
	executable_name = argv[0];

	/* Initialize */
	if ((err = init_gpgme(GPGME_PROTOCOL_OPENPGP)) != 0) {
		gpgme_failure(NULL, err, "could not initialize engine");
	}

	/* Create new context */
	if ((err = gpgme_new(&ctx)) != 0) {
		gpgme_failure(ctx, err, "could not create context");
	}

	/* Fetch key and print its information */
	if ((err = gpgme_get_key(ctx, FINGERPRINT, &keys[0], true)) != 0) {
		gpgme_failure(ctx, err, "could not fetch key");
	}
	keys[1] = NULL;

#ifdef NDEBUG
	print_key_info(keys[0]);
#endif

	/* Turn on ASCII-armored output */
	gpgme_set_armor(ctx, true);

	/* Create input */
	if ((err = gpgme_data_new_from_mem(&in, INPUT, INPUT_LEN, true)) != 0) {
		gpgme_failure(ctx, err, "could not create input data");
	}

	/* Create empty cipher */
	if ((err = gpgme_data_new(&out)) != 0) {
		gpgme_failure(ctx, err, "could not create output data");
	}

	/* Encrypt */
	if ((err = gpgme_op_encrypt(
	         ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out)) != 0) {
		gpgme_failure(ctx, err, "could not encrypt");
	}
	print_data(ctx, out);

	gpgme_release(ctx);

	return 0;
}
