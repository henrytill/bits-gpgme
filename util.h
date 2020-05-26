#ifndef GPGME_BITS_UTIL_H
#define GPGME_BITS_UTIL_H

/* The contents of argv[0] */
static char *executable_name = NULL;

/* It must be done */
#define EMPTY_STRING ""

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
init_gpgme(gpgme_protocol_t proto);

/*
 * Prints keyid, name, and email of given key
 */
void
print_key_info(gpgme_key_t key);

/*
 * Prints data
 */
void
print_data(gpgme_ctx_t ctx, gpgme_data_t data);

#endif