/*
 * pw: print a PBKDF2 hash of a password, for the add-on's users file and
 * for `password_pre_hashed` logins.
 *
 * Usage: pw -p <password> [-i <iterations>]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pbkdf2.h"

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s -p <password> [-i <iterations>]\n", name);
}

int main(int argc, char *argv[])
{
	const char *password = NULL;
	int iterations = PBKDF2_DEFAULT_ITERATIONS;
	char hash[256];
	int opt;

	while((opt = getopt(argc, argv, "p:i:h")) != -1){
		switch(opt){
			case 'p':
				password = optarg;
				break;
			case 'i':
				iterations = atoi(optarg);
				break;
			default:
				usage(argv[0]);
				return 1;
		}
	}

	if(!password || optind != argc){
		usage(argv[0]);
		return 1;
	}

	if(pbkdf2_create(password, iterations, hash, sizeof(hash))){
		fprintf(stderr, "Error: could not hash password.\n");
		return 1;
	}

	printf("%s\n", hash);
	return 0;
}
