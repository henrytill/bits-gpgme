#include <stdbool.h>
#include <stdlib.h>

#include <gpgme.h>

#include "config.h"
#include "util.h"

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
	if ((err = util_gpgme_init(GPGME_PROTOCOL_OPENPGP))) {
		util_gpgme_failure(NULL, err, FAILURE_MSG_INIT);
	}

	/* Create new context */
	if ((err = gpgme_new(&ctx))) {
		util_gpgme_failure(ctx, err, FAILURE_MSG_NEW);
	}

	/* Fetch key and print its information */
	if ((err = gpgme_get_key(ctx, FINGERPRINT, &keys[KEY], true))) {
		util_gpgme_failure(ctx, err, FAILURE_MSG_GET_KEY);
	}
	keys[END] = NULL;

#ifdef NDEBUG
	util_gpgme_print_key(keys[KEY]);
#endif

	/* Create input */
	if ((err = gpgme_data_new_from_stream(&in, stdin))) {
		gpgme_data_release(in);
		util_gpgme_failure(ctx, err, FAILURE_MSG_NEW_INPUT);
	}

	/* Create empty output */
	if ((err = gpgme_data_new(&out))) {
		gpgme_data_release(in);
		gpgme_data_release(out);
		util_gpgme_failure(ctx, err, FAILURE_MSG_NEW_OUTPUT);
	}

	/* Decrypt */
	if ((err = gpgme_op_decrypt(ctx, in, out))) {
		gpgme_data_release(in);
		gpgme_data_release(out);
		util_gpgme_failure(ctx, err, FAILURE_MSG_DECRYPT);
	}
	util_gpgme_print_data(ctx, out);

	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);

	return 0;
}
