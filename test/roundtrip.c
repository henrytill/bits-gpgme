#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "data.h"

enum {
	SUCCESS = 0,
	FAILURE = 1,
};

static const char *const CIPHERTEXT_FILE = "test_ciphertext.asc";
static const char *const OUTPUT_FILE = "test_output.txt";

static const char *const READ_FLAGS = "r";
static const char *const WRITE_FLAGS = "wb";

static inline void
safe_fclose(FILE **file)
{
	if (*file != NULL) {
		fclose(*file);
		*file = NULL;
	}
}

int
main(int argc, char *argv[])
{
	int error;
	FILE *ciphertext = NULL;
	FILE *output = NULL;

	(void)argc;
	(void)argv;

	const size_t input_len = strlen(INPUT);

	char output_buf[input_len + 1];

	{
		ciphertext = fopen(CIPHERTEXT_FILE, WRITE_FLAGS);
		if (ciphertext == NULL) {
			perror("Failed to open file");
			error = FAILURE;
			goto out;
		}

		error = cipher_encrypt(FINGERPRINT,
			INPUT,
			input_len,
			ciphertext,
			GNUPGHOME);
		if (error != SUCCESS) {
			goto out;
		}

		safe_fclose(&ciphertext);
	}

	{
		ciphertext = fopen(CIPHERTEXT_FILE, READ_FLAGS);
		if (ciphertext == NULL) {
			perror("Failed to open file");
			error = FAILURE;
			goto out;
		}

		output = fopen(OUTPUT_FILE, WRITE_FLAGS);
		if (output == NULL) {
			perror("Failed to open file");
			error = FAILURE;
			goto out;
		}

		error = cipher_decrypt(FINGERPRINT,
			ciphertext,
			output,
			GNUPGHOME);
		if (error != SUCCESS) {
			goto out;
		}

		safe_fclose(&output);
		safe_fclose(&ciphertext);
	}

	{
		output = fopen(OUTPUT_FILE, READ_FLAGS);
		if (output == NULL) {
			perror("Failed to open file");
			error = FAILURE;
			goto out;
		}

		while (fgets(output_buf, (int)sizeof output_buf, output)
			!= NULL) {
			/* read */
		}

		safe_fclose(&output);
	}

	error = strcmp(INPUT, output_buf);
out:
	safe_fclose(&ciphertext);
	safe_fclose(&output);
	remove(CIPHERTEXT_FILE);
	remove(OUTPUT_FILE);
	return error;
}
