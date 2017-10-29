#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include <gpgme.h>

#include "config.h"

/* The contents of argv[0] */
static char *executable_name = NULL;

#define GPGME_FAILURE(ctx, err, msg)                                           \
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

/* Initializes GPGME based on the given protocol type
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

/* Prints keyid, name, and email of given key */
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
	if (key->uids && key->uids->email) {
		printf(" <%s>", key->uids->email);
	}
	putchar('\n');
}

int
main(int argc, char *argv[])
{
	gpgme_error_t err;
	gpgme_ctx_t   ctx;
	gpgme_key_t   key;

	(void)argc;
	executable_name = argv[0];

	/* Initialize */
	err = init_gpgme(GPGME_PROTOCOL_OPENPGP);
	if (err) {
		GPGME_FAILURE(NULL, err, "could not initialize engine");
	}

	/* Create new context */
	err = gpgme_new(&ctx);
	if (err) {
		GPGME_FAILURE(ctx, err, "could not create context");
	}

	/* Fetch key and print its information */
	err = gpgme_get_key(ctx, FINGERPRINT, &key, 0);
	if (err) {
		GPGME_FAILURE(ctx, err, "could not fetch key");
	}
	print_key_info(key);

	/* Turn on ASCII-armored output */
	gpgme_set_armor(ctx, 0);

	gpgme_release(ctx);

	return 0;
}
