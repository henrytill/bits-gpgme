#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "config.h"
#include "util.h"

/* NULL-terminated array of length 1 */
#define KEYS_LEN 2

/* Failure messages */
#define FAILURE_MSG_INIT       "could not initialize engine"
#define FAILURE_MSG_NEW        "could not create context"
#define FAILURE_MSG_GET_KEY    "could not fetch key"
#define FAILURE_MSG_NEW_INPUT  "could not create input data"
#define FAILURE_MSG_NEW_OUTPUT "could not create output data"
#define FAILURE_MSG_ENCRYPT    "could not encrypt"

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
		gpgme_failure(NULL, err, FAILURE_MSG_INIT);
	}

	/* Create new context */
	if ((err = gpgme_new(&ctx)) != 0) {
		gpgme_failure(ctx, err, FAILURE_MSG_NEW);
	}

	/* Fetch key and print its information */
	if ((err = gpgme_get_key(ctx, FINGERPRINT, &keys[0], true)) != 0) {
		gpgme_failure(ctx, err, FAILURE_MSG_GET_KEY);
	}
	keys[1] = NULL;

#ifdef NDEBUG
	print_key_info(keys[0]);
#endif

	/* Turn on ASCII-armored output */
	gpgme_set_armor(ctx, true);

	/* Create input */
	if ((err = gpgme_data_new_from_mem(&in, INPUT, INPUT_LEN, true)) != 0) {
		gpgme_failure(ctx, err, FAILURE_MSG_NEW_INPUT);
	}

	/* Create empty cipher */
	if ((err = gpgme_data_new(&out)) != 0) {
		gpgme_failure(ctx, err, FAILURE_MSG_NEW_OUTPUT);
	}

	/* Encrypt */
	if ((err = gpgme_op_encrypt(
	         ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out)) != 0) {
		gpgme_failure(ctx, err, FAILURE_MSG_ENCRYPT);
	}
	print_data(ctx, out);

	gpgme_release(ctx);

	return 0;
}
