#include <stdbool.h>
#include <stdlib.h>

#include "config.h"
#include "util.h"

int
main(int argc, char *argv[])
{
	gpgme_error_t err;
	gpgme_ctx_t   ctx = NULL;
	gpgme_key_t   keys[KEYS_LEN];
	gpgme_data_t  in = NULL;
	gpgme_data_t  out = NULL;

	(void)argc;
	executable_name = argv[0];

	/* Initialize */
	if ((err = util_gpgme_init(GPGME_PROTOCOL_OPENPGP)) != 0) {
		util_gpgme_print_error(err, FAILURE_MSG_INIT);
		goto fail;
	}

	/* Create new context */
	if ((err = gpgme_new(&ctx)) != 0) {
		util_gpgme_print_error(err, FAILURE_MSG_NEW);
		goto fail;
	}

	/* Fetch key and print its information */
	if ((err = gpgme_get_key(ctx, FINGERPRINT, &keys[KEY], true)) != 0) {
		util_gpgme_print_error(err, FAILURE_MSG_GET_KEY);
		goto fail;
	}
	keys[END] = NULL;

#ifdef NDEBUG
	util_gpgme_print_key(keys[KEY]);
#endif

	/* Create input */
	if ((err = gpgme_data_new_from_stream(&in, stdin)) != 0) {
		util_gpgme_print_error(err, FAILURE_MSG_NEW_INPUT);
		goto fail;
	}

	/* Create empty output */
	if ((err = gpgme_data_new(&out)) != 0) {
		util_gpgme_print_error(err, FAILURE_MSG_NEW_OUTPUT);
		goto fail;
	}

	/* Decrypt */
	if ((err = gpgme_op_decrypt(ctx, in, out)) != 0) {
		util_gpgme_print_error(err, FAILURE_MSG_DECRYPT);
		goto fail;
	}

	if (util_gpgme_print_data(out) != 0) {
		goto fail;
	}

	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);
	return 0;

fail:
	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);
	exit(1);
}
