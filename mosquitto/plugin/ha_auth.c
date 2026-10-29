/*
 * ha-auth: Mosquitto authentication plugin for the Home Assistant add-on.
 *
 * Authenticates MQTT clients with a username and password, checking in order:
 *
 *   1. Local users from a file of "username:hash" lines, written by the
 *      add-on at startup (its internal users and the `logins` option).
 *      Lines are split on the last colon, so usernames may contain colons
 *      (for example devices that use their MAC address as username).
 *   2. Home Assistant users, through the Supervisor's /auth endpoint.
 *
 * Results are cached for a short time, as both checks are expensive.
 *
 * The plugin only handles authentication. It does not register an ACL
 * check, so Mosquitto's own acl_file applies when one is configured and
 * authenticated clients otherwise have full access.
 *
 * Options:
 *   plugin_opt_users_file <path>       local users file (optional)
 *   plugin_opt_supervisor_url <url>    default: http://supervisor/auth
 *   plugin_opt_cache_seconds <n>       default: 300, 0 disables the cache
 *   plugin_opt_http_timeout_ms <n>     default: 5000
 *
 * Home Assistant user logins are enabled when the SUPERVISOR_TOKEN
 * environment variable is set.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <mosquitto.h>

#include "pbkdf2.h"

#define DEFAULT_SUPERVISOR_URL "http://supervisor/auth"
#define DEFAULT_CACHE_SECONDS 300
#define DEFAULT_HTTP_TIMEOUT_MS 5000
#define CACHE_SIZE 256
#define CACHE_KEY_LEN 32

#define UNUSED(x) (void)(x)

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

enum auth_result {
	AUTH_GRANTED,
	AUTH_DENIED,
	AUTH_ERROR,
};

struct local_user {
	char *username;
	char *hash;
	struct local_user *next;
};

struct cache_entry {
	unsigned char key[CACHE_KEY_LEN];
	time_t expires;
	bool granted;
	bool used;
};

struct plugin_data {
	mosquitto_plugin_id_t *pid;
	struct local_user *users;
	char *users_file;
	char *supervisor_url;
	long http_timeout_ms;
	int cache_seconds;
	CURL *curl;
	struct curl_slist *headers;
	struct cache_entry cache[CACHE_SIZE];
};

static struct plugin_data plugin;


static time_t now_seconds(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* ========================================================================
 * Local users
 * ======================================================================== */

static struct local_user *find_user(struct local_user *users, const char *username)
{
	for(struct local_user *u = users; u; u = u->next){
		if(!strcmp(u->username, username)){
			return u;
		}
	}
	return NULL;
}

static void free_users(struct local_user *users)
{
	while(users){
		struct local_user *next = users->next;

		free(users->username);
		free(users->hash);
		free(users);
		users = next;
	}
}

static int load_users(struct plugin_data *pd)
{
	FILE *fp;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;
	int line_no = 0;
	int count = 0;
	struct local_user *last = NULL;

	fp = fopen(pd->users_file, "r");
	if(!fp){
		mosquitto_log_printf(MOSQ_LOG_ERR, "ha-auth: Unable to open users file %s: %s",
				pd->users_file, strerror(errno));
		return MOSQ_ERR_INVAL;
	}

	while((len = getline(&line, &cap, fp)) != -1){
		char *sep;
		struct local_user *user;

		line_no++;
		while(len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')){
			line[--len] = '\0';
		}
		if(len == 0 || line[0] == '#'){
			continue;
		}

		/* Password hashes never contain a colon, usernames may. */
		sep = strrchr(line, ':');
		if(!sep || sep == line){
			mosquitto_log_printf(MOSQ_LOG_WARNING, "ha-auth: Ignoring malformed line %d in users file", line_no);
			continue;
		}
		*sep = '\0';

		if(!pbkdf2_hash_valid(sep + 1)){
			mosquitto_log_printf(MOSQ_LOG_WARNING, "ha-auth: Ignoring user '%s': unsupported password hash", line);
			continue;
		}
		if(find_user(pd->users, line)){
			mosquitto_log_printf(MOSQ_LOG_WARNING, "ha-auth: Ignoring duplicate user '%s'", line);
			continue;
		}

		user = calloc(1, sizeof(*user));
		if(!user || !(user->username = strdup(line)) || !(user->hash = strdup(sep + 1))){
			if(user){
				free(user->username);
				free(user);
			}
			free(line);
			fclose(fp);
			return MOSQ_ERR_NOMEM;
		}
		if(last){
			last->next = user;
		}else{
			pd->users = user;
		}
		last = user;
		count++;
	}

	free(line);
	fclose(fp);
	mosquitto_log_printf(MOSQ_LOG_INFO, "ha-auth: Loaded %d local user(s)", count);
	return MOSQ_ERR_SUCCESS;
}

static enum auth_result check_local(struct plugin_data *pd, const char *username, const char *password)
{
	struct local_user *user = find_user(pd->users, username);

	if(user && pbkdf2_verify(password, user->hash)){
		return AUTH_GRANTED;
	}
	return AUTH_DENIED;
}

/* ========================================================================
 * Home Assistant users (Supervisor)
 * ======================================================================== */

static size_t discard_body(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	UNUSED(ptr);
	UNUSED(userdata);
	return size * nmemb;
}

static int setup_supervisor(struct plugin_data *pd)
{
	const char *token = getenv("SUPERVISOR_TOKEN");
	char *header;
	size_t header_len;

	if(!token || !token[0]){
		mosquitto_log_printf(MOSQ_LOG_WARNING,
				"ha-auth: SUPERVISOR_TOKEN is not set, Home Assistant user logins are disabled");
		return MOSQ_ERR_SUCCESS;
	}

	if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK){
		return MOSQ_ERR_UNKNOWN;
	}
	pd->curl = curl_easy_init();
	if(!pd->curl){
		return MOSQ_ERR_NOMEM;
	}

	header_len = strlen("X-Supervisor-Token: ") + strlen(token) + 1;
	header = malloc(header_len);
	if(!header){
		return MOSQ_ERR_NOMEM;
	}
	snprintf(header, header_len, "X-Supervisor-Token: %s", token);
	pd->headers = curl_slist_append(NULL, header);
	OPENSSL_cleanse(header, header_len);
	free(header);
	if(!pd->headers){
		return MOSQ_ERR_NOMEM;
	}

	curl_easy_setopt(pd->curl, CURLOPT_URL, pd->supervisor_url);
	curl_easy_setopt(pd->curl, CURLOPT_HTTPHEADER, pd->headers);
	curl_easy_setopt(pd->curl, CURLOPT_TIMEOUT_MS, pd->http_timeout_ms);
	curl_easy_setopt(pd->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(pd->curl, CURLOPT_WRITEFUNCTION, discard_body);
	curl_easy_setopt(pd->curl, CURLOPT_POST, 1L);

	return MOSQ_ERR_SUCCESS;
}

static enum auth_result check_supervisor(struct plugin_data *pd, const char *username, const char *password)
{
	char *esc_user = NULL;
	char *esc_pass = NULL;
	char *body = NULL;
	size_t body_len;
	CURLcode res;
	long status = 0;
	enum auth_result result = AUTH_ERROR;

	if(!pd->curl){
		return AUTH_DENIED;
	}

	esc_user = curl_easy_escape(pd->curl, username, 0);
	esc_pass = curl_easy_escape(pd->curl, password, 0);
	if(!esc_user || !esc_pass){
		goto out;
	}

	body_len = strlen("username=&password=") + strlen(esc_user) + strlen(esc_pass) + 1;
	body = malloc(body_len);
	if(!body){
		goto out;
	}
	snprintf(body, body_len, "username=%s&password=%s", esc_user, esc_pass);

	curl_easy_setopt(pd->curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(pd->curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));

	res = curl_easy_perform(pd->curl);
	curl_easy_setopt(pd->curl, CURLOPT_POSTFIELDS, NULL);

	if(res != CURLE_OK){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "ha-auth: Supervisor request failed: %s", curl_easy_strerror(res));
		goto out;
	}

	curl_easy_getinfo(pd->curl, CURLINFO_RESPONSE_CODE, &status);
	if(status == 200){
		result = AUTH_GRANTED;
	}else if(status == 400 || status == 401){
		result = AUTH_DENIED;
	}else{
		mosquitto_log_printf(MOSQ_LOG_WARNING, "ha-auth: Unexpected response from Supervisor: HTTP %ld", status);
	}

out:
	if(body){
		OPENSSL_cleanse(body, body_len);
		free(body);
	}
	if(esc_pass){
		OPENSSL_cleanse(esc_pass, strlen(esc_pass));
		curl_free(esc_pass);
	}
	curl_free(esc_user);
	return result;
}

/* ========================================================================
 * Cache
 * ======================================================================== */

/* The cache stores a hash of the credentials, never the password itself. */
static bool cache_key(const char *username, const char *password, unsigned char *key)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int len = 0;
	bool ok;

	if(!ctx){
		return false;
	}
	ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
		&& EVP_DigestUpdate(ctx, username, strlen(username) + 1) == 1
		&& EVP_DigestUpdate(ctx, password, strlen(password) + 1) == 1
		&& EVP_DigestFinal_ex(ctx, key, &len) == 1
		&& len == CACHE_KEY_LEN;
	EVP_MD_CTX_free(ctx);
	return ok;
}

static bool cache_lookup(struct plugin_data *pd, const unsigned char *key, time_t now, bool *granted)
{
	for(int i = 0; i < CACHE_SIZE; i++){
		struct cache_entry *e = &pd->cache[i];

		if(e->used && e->expires > now && !memcmp(e->key, key, CACHE_KEY_LEN)){
			*granted = e->granted;
			return true;
		}
	}
	return false;
}

static void cache_store(struct plugin_data *pd, const unsigned char *key, bool granted, time_t now)
{
	struct cache_entry *slot = NULL;

	if(pd->cache_seconds <= 0){
		return;
	}

	/* Reuse the entry for this key, a free or expired one, or else the
	 * one closest to expiring. */
	for(int i = 0; i < CACHE_SIZE; i++){
		struct cache_entry *e = &pd->cache[i];

		if(e->used && !memcmp(e->key, key, CACHE_KEY_LEN)){
			slot = e;
			break;
		}
		if(!e->used || e->expires <= now){
			if(!slot || slot->used){
				slot = e;
			}
		}else if(!slot || (slot->used && e->expires < slot->expires)){
			slot = e;
		}
	}

	memcpy(slot->key, key, CACHE_KEY_LEN);
	slot->expires = now + pd->cache_seconds;
	slot->granted = granted;
	slot->used = true;
}

/* ========================================================================
 * Plugin entry points
 * ======================================================================== */

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	struct plugin_data *pd = userdata;
	unsigned char key[CACHE_KEY_LEN];
	bool have_key;
	bool granted;
	time_t now;
	enum auth_result result;

	UNUSED(event);

	/* Anonymous connections are not ours to decide. */
	if(!ed->username || !ed->password){
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	now = now_seconds();
	have_key = cache_key(ed->username, ed->password, key);
	if(have_key && cache_lookup(pd, key, now, &granted)){
		return granted ? MOSQ_ERR_SUCCESS : MOSQ_ERR_PLUGIN_DEFER;
	}

	result = check_local(pd, ed->username, ed->password);
	if(result == AUTH_GRANTED){
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "ha-auth: User '%s' authenticated as local user", ed->username);
	}else{
		result = check_supervisor(pd, ed->username, ed->password);
		if(result == AUTH_GRANTED){
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "ha-auth: User '%s' authenticated as Home Assistant user", ed->username);
		}
	}

	if(result == AUTH_ERROR){
		/* Don't cache: the Supervisor may be back on the next attempt. */
		return MOSQ_ERR_PLUGIN_DEFER;
	}

	granted = result == AUTH_GRANTED;
	if(!granted){
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "ha-auth: Login failed for user '%s'", ed->username);
	}
	if(have_key){
		cache_store(pd, key, granted, now);
	}
	return granted ? MOSQ_ERR_SUCCESS : MOSQ_ERR_PLUGIN_DEFER;
}

static int parse_options(struct plugin_data *pd, struct mosquitto_opt *opts, int opt_count)
{
	for(int i = 0; i < opt_count; i++){
		const char *key = opts[i].key;
		const char *value = opts[i].value;

		if(!strcmp(key, "users_file")){
			free(pd->users_file);
			pd->users_file = strdup(value);
			if(!pd->users_file){
				return MOSQ_ERR_NOMEM;
			}
		}else if(!strcmp(key, "supervisor_url")){
			free(pd->supervisor_url);
			pd->supervisor_url = strdup(value);
			if(!pd->supervisor_url){
				return MOSQ_ERR_NOMEM;
			}
		}else if(!strcmp(key, "cache_seconds")){
			pd->cache_seconds = atoi(value);
		}else if(!strcmp(key, "http_timeout_ms")){
			pd->http_timeout_ms = atol(value);
		}else{
			mosquitto_log_printf(MOSQ_LOG_WARNING, "ha-auth: Unknown option '%s'", key);
		}
	}

	if(!pd->supervisor_url){
		pd->supervisor_url = strdup(DEFAULT_SUPERVISOR_URL);
		if(!pd->supervisor_url){
			return MOSQ_ERR_NOMEM;
		}
	}
	if(pd->http_timeout_ms <= 0){
		pd->http_timeout_ms = DEFAULT_HTTP_TIMEOUT_MS;
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	int rc;

	memset(&plugin, 0, sizeof(plugin));
	plugin.pid = identifier;
	plugin.cache_seconds = DEFAULT_CACHE_SECONDS;
	*user_data = &plugin;

	rc = parse_options(&plugin, opts, opt_count);
	if(rc == MOSQ_ERR_SUCCESS && plugin.users_file){
		rc = load_users(&plugin);
	}
	if(rc == MOSQ_ERR_SUCCESS){
		rc = setup_supervisor(&plugin);
	}
	if(rc == MOSQ_ERR_SUCCESS){
		rc = mosquitto_callback_register(plugin.pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, &plugin);
	}
	return rc;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	struct plugin_data *pd = user_data;

	UNUSED(opts);
	UNUSED(opt_count);

	mosquitto_callback_unregister(pd->pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL);
	free_users(pd->users);
	if(pd->curl){
		curl_easy_cleanup(pd->curl);
		curl_global_cleanup();
	}
	curl_slist_free_all(pd->headers);
	free(pd->users_file);
	free(pd->supervisor_url);
	memset(pd, 0, sizeof(*pd));
	return MOSQ_ERR_SUCCESS;
}
