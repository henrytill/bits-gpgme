#ifndef GPGME_BITS_UTIL_H
#define GPGME_BITS_UTIL_H

#include <assert.h>

#include <gpgme.h>

/* The contents of argv[0] */
extern char *executable_name;

/* It must be done */
#define EMPTY_STRING ""

/* Failure messages */
#define FAILURE_MSG_INIT       "could not initialize engine"
#define FAILURE_MSG_NEW        "could not create context"
#define FAILURE_MSG_GET_KEY    "could not fetch key"
#define FAILURE_MSG_NEW_INPUT  "could not create input data"
#define FAILURE_MSG_NEW_OUTPUT "could not create output data"
#define FAILURE_MSG_ENCRYPT    "could not encrypt"
#define FAILURE_MSG_DECRYPT    "could not decrypt"

/* NULL-terminated array of length 1 */
#define KEYS_LEN 2

/* Constants for accessing keys */
enum { KEY = 0, END = 1 };

/* Size of buffer for printing data */
#define BUF_LEN 512

/* Prints well-formatted error, releases context, and exits */
#define util_gpgme_print_error(err, msg)                                       \
	do {                                                                   \
		assert(executable_name != NULL);                               \
		fprintf(stderr,                                                \
		        "%s: %s: %s: %s\n",                                    \
		        executable_name,                                       \
		        msg,                                                   \
		        gpgme_strsource(err),                                  \
		        gpgme_strerror(err));                                  \
	} while (0)

/*
 * Initializes GPGME based on the given protocol type
 *
 * https://gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html
 */
gpgme_error_t
util_gpgme_init(gpgme_protocol_t proto);

/*
 * Prints keyid, name, and email of given key
 */
void
util_gpgme_print_key(gpgme_key_t key);

/*
 * Prints data
 */
int
util_gpgme_print_data(gpgme_data_t data);

#endif
