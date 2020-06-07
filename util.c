#include <locale.h>
#include <string.h>

#include "util.h"

gpgme_error_t
util_gpgme_init(gpgme_protocol_t proto)
{
	setlocale(LC_ALL, "");
	gpgme_check_version(NULL);
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

#ifdef LC_MESSAGES
	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif

	return gpgme_engine_check_version(proto);
}

void
util_gpgme_print_key(gpgme_key_t key)
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

int
util_gpgme_print_data(gpgme_data_t data)
{
	off_t         ret;
	gpgme_error_t err;
	char          buf[BUF_LEN + 1];

	if ((ret = gpgme_data_seek(data, 0, SEEK_SET)) != 0) {
		err = gpgme_error_from_errno(ret);
		util_gpgme_print_error(err, "could not seek");
		return 1;
	}

	while ((ret = gpgme_data_read(data, buf, BUF_LEN)) != 0) {
		fwrite(buf, ret, 1, stdout);
	}

	if (ret) {
		err = gpgme_error_from_errno(ret);
		util_gpgme_print_error(err, "could not read");
		return 1;
	}

	return 0;
}
