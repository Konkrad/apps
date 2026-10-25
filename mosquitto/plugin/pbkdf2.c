/*
 * PBKDF2 password hashes in the format used by mosquitto-go-auth.
 * See pbkdf2.h for the accepted formats.
 */
#include "pbkdf2.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_FIELDS 6
#define MAX_BYTES 256
#define MAX_ITERATIONS 10000000

struct parsed_hash {
	const EVP_MD *md;
	int iterations;
	unsigned char salt[MAX_BYTES];
	size_t salt_len;
	unsigned char key[MAX_BYTES];
	size_t key_len;
};

struct field {
	const char *start;
	size_t len;
};

/* Splits `s` on '$', skipping empty fields (so a leading '$' is allowed).
 * Returns the number of fields, or -1 if there are more than `max`. */
static int split_fields(const char *s, struct field *fields, int max)
{
	int count = 0;
	const char *p = s;

	while(*p){
		const char *end = strchr(p, '$');
		size_t len = end ? (size_t)(end - p) : strlen(p);

		if(len > 0){
			if(count == max){
				return -1;
			}
			fields[count].start = p;
			fields[count].len = len;
			count++;
		}
		if(!end){
			break;
		}
		p = end + 1;
	}
	return count;
}

static bool field_equals(const struct field *f, const char *s)
{
	return f->len == strlen(s) && !strncmp(f->start, s, f->len);
}

/* Parses a positive decimal integer of at most `max`. */
static bool parse_int(const char *s, size_t len, int max, int *out)
{
	char buf[16];
	char *end;
	long v;

	if(len == 0 || len >= sizeof(buf)){
		return false;
	}
	memcpy(buf, s, len);
	buf[len] = '\0';

	errno = 0;
	v = strtol(buf, &end, 10);
	if(errno || *end != '\0' || v < 1 || v > max){
		return false;
	}
	*out = (int)v;
	return true;
}

/* Decodes standard base64, with or without padding. */
static bool b64_decode(const struct field *f, unsigned char *out, size_t *out_len)
{
	char buf[MAX_BYTES * 2];
	size_t n = f->len;
	size_t pad = 0;
	int decoded;

	if(n == 0 || n % 4 == 1 || n + 3 >= sizeof(buf)){
		return false;
	}
	memcpy(buf, f->start, n);
	while(n % 4){
		buf[n++] = '=';
	}
	buf[n] = '\0';

	if(buf[n - 1] == '='){
		pad++;
	}
	if(buf[n - 2] == '='){
		pad++;
	}
	if(n / 4 * 3 > MAX_BYTES){
		return false;
	}

	decoded = EVP_DecodeBlock(out, (const unsigned char *)buf, (int)n);
	if(decoded < 0 || (size_t)decoded <= pad){
		return false;
	}
	*out_len = (size_t)decoded - pad;
	return true;
}

/* Parses "i=<iterations>,l=<keylen>" from the PHC-style format. */
static bool parse_phc_params(const struct field *f, int *iterations, int *key_len)
{
	const char *p = f->start;
	const char *end = f->start + f->len;

	*iterations = 0;
	*key_len = 0;

	while(p < end){
		const char *comma = memchr(p, ',', (size_t)(end - p));
		const char *item_end = comma ? comma : end;

		if(item_end - p < 3 || p[1] != '='){
			return false;
		}
		if(p[0] == 'i'){
			if(!parse_int(p + 2, (size_t)(item_end - p - 2), MAX_ITERATIONS, iterations)){
				return false;
			}
		}else if(p[0] == 'l'){
			if(!parse_int(p + 2, (size_t)(item_end - p - 2), MAX_BYTES, key_len)){
				return false;
			}
		}else{
			return false;
		}
		p = comma ? comma + 1 : end;
	}
	return *iterations > 0;
}

static bool parse_hash(const char *hash, struct parsed_hash *ph)
{
	struct field fields[MAX_FIELDS];
	int count;

	if(!hash){
		return false;
	}
	count = split_fields(hash, fields, MAX_FIELDS);
	if(count < 1){
		return false;
	}

	if(field_equals(&fields[0], "PBKDF2")){
		/* PBKDF2$<algorithm>$<iterations>$<salt>$<hash> */
		if(count != 5){
			return false;
		}
		if(field_equals(&fields[1], "sha512")){
			ph->md = EVP_sha512();
		}else if(field_equals(&fields[1], "sha256")){
			ph->md = EVP_sha256();
		}else{
			return false;
		}
		if(!parse_int(fields[2].start, fields[2].len, MAX_ITERATIONS, &ph->iterations)){
			return false;
		}
		return b64_decode(&fields[3], ph->salt, &ph->salt_len)
			&& b64_decode(&fields[4], ph->key, &ph->key_len);
	}

	if(field_equals(&fields[0], "pbkdf2-sha512")){
		/* pbkdf2-sha512$i=<iterations>,l=<keylen>$<salt>$<hash> */
		int key_len;

		if(count != 4){
			return false;
		}
		ph->md = EVP_sha512();
		if(!parse_phc_params(&fields[1], &ph->iterations, &key_len)){
			return false;
		}
		if(!b64_decode(&fields[2], ph->salt, &ph->salt_len)
				|| !b64_decode(&fields[3], ph->key, &ph->key_len)){
			return false;
		}
		/* If a key length is given, it must match the stored hash. */
		return key_len == 0 || (size_t)key_len == ph->key_len;
	}

	return false;
}

bool pbkdf2_hash_valid(const char *hash)
{
	struct parsed_hash ph;

	return parse_hash(hash, &ph);
}

bool pbkdf2_verify(const char *password, const char *hash)
{
	struct parsed_hash ph;
	unsigned char computed[MAX_BYTES];
	bool match;

	if(!password || !parse_hash(hash, &ph)){
		return false;
	}

	if(PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
				ph.salt, (int)ph.salt_len, ph.iterations, ph.md,
				(int)ph.key_len, computed) != 1){
		return false;
	}

	match = CRYPTO_memcmp(computed, ph.key, ph.key_len) == 0;
	OPENSSL_cleanse(computed, sizeof(computed));
	return match;
}

int pbkdf2_create(const char *password, int iterations, char *out, size_t outlen)
{
	unsigned char salt[PBKDF2_DEFAULT_SALT_LEN];
	unsigned char key[PBKDF2_DEFAULT_KEY_LEN];
	char salt_b64[((PBKDF2_DEFAULT_SALT_LEN + 2) / 3) * 4 + 1];
	char key_b64[((PBKDF2_DEFAULT_KEY_LEN + 2) / 3) * 4 + 1];
	int written;

	if(!password || iterations < 1 || iterations > MAX_ITERATIONS){
		return -1;
	}
	if(RAND_bytes(salt, sizeof(salt)) != 1){
		return -1;
	}
	if(PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, sizeof(salt),
				iterations, EVP_sha512(), sizeof(key), key) != 1){
		return -1;
	}

	EVP_EncodeBlock((unsigned char *)salt_b64, salt, sizeof(salt));
	EVP_EncodeBlock((unsigned char *)key_b64, key, sizeof(key));
	OPENSSL_cleanse(key, sizeof(key));

	written = snprintf(out, outlen, "PBKDF2$sha512$%d$%s$%s", iterations, salt_b64, key_b64);
	if(written < 0 || (size_t)written >= outlen){
		return -1;
	}
	return 0;
}
