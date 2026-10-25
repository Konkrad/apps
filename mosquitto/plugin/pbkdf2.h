/*
 * PBKDF2 password hashes in the format used by mosquitto-go-auth.
 *
 * Two formats are accepted, matching what go-auth's pbkdf2 hasher accepts:
 *
 *   PBKDF2$<sha512|sha256>$<iterations>$<base64 salt>$<base64 hash>
 *   pbkdf2-sha512$i=<iterations>,l=<keylen>$<base64 salt>$<base64 hash>
 *
 * The first one is what the `pw` tool produces and what the add-on stores.
 */
#ifndef HA_AUTH_PBKDF2_H
#define HA_AUTH_PBKDF2_H

#include <stdbool.h>
#include <stddef.h>

#define PBKDF2_DEFAULT_ITERATIONS 100000
#define PBKDF2_DEFAULT_SALT_LEN 16
#define PBKDF2_DEFAULT_KEY_LEN 32

/* Returns true if `hash` is a password hash this module can verify. */
bool pbkdf2_hash_valid(const char *hash);

/* Returns true if `password` matches `hash`. Returns false for any
 * malformed hash. */
bool pbkdf2_verify(const char *password, const char *hash);

/* Writes a new PBKDF2$sha512$... hash of `password` into `out`.
 * Returns 0 on success, -1 on error. */
int pbkdf2_create(const char *password, int iterations, char *out, size_t outlen);

#endif
