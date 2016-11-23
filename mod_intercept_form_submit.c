
/*
 * Copyright 2013--2016 Jan Pazdziora
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_strings.h"
#include "apr_optional.h"
#include "http_core.h"
#include "http_log.h"
#include "http_config.h"
#include "http_request.h"

#include "mod_auth.h"

typedef struct ifs_config {
	char * login_name;
	char * password_name;
	int password_redact;
	char * pam_service;
	apr_hash_t * login_blacklist;
	int clear_blacklisted;
	int success_to_get;
	apr_array_header_t * realms;
} ifs_config;

typedef struct {
	apr_status_t cached_ret;
	apr_bucket_brigade * cached_brigade;
	apr_bucket * password_fragment_start_bucket;
	int password_fragment_start_bucket_offset;
} ifs_filter_ctx_t;


module AP_MODULE_DECLARE_DATA intercept_form_submit_module;

#ifdef APLOG_USE_MODULE
#define SHOW_MODULE ""
#else
#define SHOW_MODULE "mod_intercept_form_submit: "
#endif

APR_DECLARE_OPTIONAL_FN(authn_status, pam_authenticate_with_login_password,
	(request_rec * r, const char * pam_service,
	const char * login, const char * password, int steps));
static APR_OPTIONAL_FN_TYPE(pam_authenticate_with_login_password) * pam_authenticate_with_login_password_fn = NULL;

static const char * add_login_to_blacklist(cmd_parms * cmd, void * conf_void, const char * arg) {
	ifs_config * cfg = (ifs_config *) conf_void;
	if (cfg) {
		if (! cfg->login_blacklist) {
			cfg->login_blacklist = apr_hash_make(cmd->pool);
		}
		apr_hash_set(cfg->login_blacklist, apr_pstrdup(cmd->pool, arg), APR_HASH_KEY_STRING, "1");
	}
	return NULL;
}

static const char * add_realm(cmd_parms * cmd, void * conf_void, const char * arg) {
	ifs_config * cfg = (ifs_config *) conf_void;
	if (cfg) {
		if (! cfg->realms) {
			cfg->realms = apr_array_make(cmd->pool, 1, sizeof(char *));
		}
		*(const char **) apr_array_push(cfg->realms) = arg;
	}
	return NULL;
}

static const command_rec directives[] = {
	AP_INIT_TAKE1("InterceptFormLogin", ap_set_string_slot, (void *)APR_OFFSETOF(ifs_config, login_name), ACCESS_CONF, "Name of the login parameter in the POST request"),
	AP_INIT_TAKE1("InterceptFormPassword", ap_set_string_slot, (void *)APR_OFFSETOF(ifs_config, password_name), ACCESS_CONF, "Name of the password parameter in the POST request"),
	AP_INIT_FLAG("InterceptFormPasswordRedact", ap_set_flag_slot, (void *)APR_OFFSETOF(ifs_config, password_redact), ACCESS_CONF, "When password is seen in the POST for non-blacklisted user, the value will be redacted"),
	AP_INIT_TAKE1("InterceptFormPAMService", ap_set_string_slot, (void *)APR_OFFSETOF(ifs_config, pam_service), ACCESS_CONF, "PAM service to authenticate against"),
	AP_INIT_ITERATE("InterceptFormLoginSkip", add_login_to_blacklist, NULL, ACCESS_CONF, "Login name(s) for which no PAM authentication will be done"),
	AP_INIT_FLAG("InterceptFormClearRemoteUserForSkipped", ap_set_flag_slot, (void *)APR_OFFSETOF(ifs_config, clear_blacklisted), ACCESS_CONF, "When authentication is skipped for users listed with InterceptFormLoginSkip, clear r->user and REMOTE_USER"),
	AP_INIT_FLAG("InterceptGETOnSuccess", ap_set_flag_slot, (void *)APR_OFFSETOF(ifs_config, success_to_get), ACCESS_CONF, "When authentication passes, turn the POST request to GET internally"),
	AP_INIT_ITERATE("InterceptFormLoginRealms", add_realm, NULL, ACCESS_CONF, "Realm(s) that will be appended to login name which does not have one"),
	{ NULL }
};

#define _REMOTE_USER_ENV_NAME "REMOTE_USER"

static void register_pam_authenticate_with_login_password_fn(void) {
	pam_authenticate_with_login_password_fn = APR_RETRIEVE_OPTIONAL_FN(pam_authenticate_with_login_password);
}

static int hex2char(int c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 10;
	return -1;
}

static char * intercept_form_submit_process_keyval(apr_pool_t * pool, const char * name,
	const char * key, int key_len, const char * val, int val_len) {
	if (val_len == 0)
		return NULL;
	int i;
	for (i = 0; i < key_len; i++, name++) {
		if (*name == '\0')
			return NULL;
		int c = key[i];
		if (c == '+')
			c = ' ';
		else if (c == '%') {
			if (i > key_len - 3)
				return NULL;
			int m = hex2char(key[++i]);
			int n = hex2char(key[++i]);
			if (m < 0 || n < 0)
				return NULL;
			c = (m << 4) + n;
		}
		if (c != *name)
			return NULL;
	}
	if (*name != '\0')
		return NULL;
	char * ret = apr_palloc(pool, val_len + 1);
	char * p = ret;
	for (i = 0; i < val_len; i++, p++) {
		if (val[i] == '+')
			*p = ' ';
		else if (val[i] == '%') {
			if (i > val_len - 3)
				return NULL;
			int m = hex2char(val[++i]);
			int n = hex2char(val[++i]);
			if (m < 0 || n < 0)
				return NULL;
			*p = (m << 4) + n;
		} else {
			*p = val[i];
		}
	}
	*p = '\0';
	return ret;
}

static authn_status pam_authenticate_in_realms(request_rec * r, const char * pam_service,
	const char * login, const char * password, apr_array_header_t * realms, int steps) {

	if (strchr(login, '@') || (! realms) || (! realms->nelts)) {
		return pam_authenticate_with_login_password_fn(r, pam_service, login, password, steps);
	}

	authn_status first_status = AUTH_GENERAL_ERROR;
	int i;
	for (i = 0; i < realms->nelts; i++) {
		const char * realm = ((const char**)realms->elts)[i];
		const char * full_login = login;
		if (realm && strlen(realm))
			full_login = apr_pstrcat(r->pool, login, "@", realm, NULL);
		authn_status status = pam_authenticate_with_login_password_fn(r, pam_service, full_login, password, steps);
		if (status == AUTH_GRANTED)
			return status;
		if (i == 0)
			first_status = status;
	}
	return first_status;
}

#define _REDACTED_STRING "[REDACTED]"
static void intercept_form_redact_password(ap_filter_t * f, ifs_config * config) {
	request_rec * r = f->r;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "will redact password (value of %s) in the POST data", config->password_name);
	ifs_filter_ctx_t * ctx = f->ctx;
	apr_bucket * b = ctx->password_fragment_start_bucket;
	int fragment_start_bucket_offset = ctx->password_fragment_start_bucket_offset;
	if (fragment_start_bucket_offset) {
		apr_bucket_split(b, fragment_start_bucket_offset);
		b = APR_BUCKET_NEXT(b);
	}
	char * new_password_data = apr_pstrcat(r->pool, config->password_name, "=", _REDACTED_STRING, NULL);
	int new_password_data_length = strlen(new_password_data);
	apr_bucket * new_b = apr_bucket_immortal_create(new_password_data, new_password_data_length, f->c->bucket_alloc);
	APR_BUCKET_INSERT_BEFORE(b, new_b);

	int password_remove_length = 0;
	apr_bucket * remove_b = NULL;
	do {
		if (remove_b) {
			apr_bucket_delete(remove_b);
			remove_b = NULL;
		}
		if (b == APR_BRIGADE_SENTINEL(ctx->cached_brigade)) {
			break;
		}
		if (APR_BUCKET_IS_METADATA(b))
			continue;
		const char * buffer;
		apr_size_t nbytes;
		if (apr_bucket_read(b, &buffer, &nbytes, APR_BLOCK_READ) != APR_SUCCESS)
			continue;
		if (! nbytes)
			continue;

		const char * e = memchr(buffer, '&', nbytes);
		if (e) {
			password_remove_length += (e - buffer);
			remove_b = b;
			apr_bucket_split(b, (e - buffer));
			break;
		} else {
			password_remove_length += nbytes;
			remove_b = b;
		}
	} while ((b = APR_BUCKET_NEXT(b)));
	if (remove_b) {
		apr_bucket_delete(remove_b);
	}

	if (password_remove_length != new_password_data_length) {
		const char * orig_content_length = apr_table_get(r->headers_in, "Content-Length");
		if (orig_content_length) {
			char * end;
			apr_off_t content_length;
			apr_status_t status = apr_strtoff(&content_length, orig_content_length, &end, 10);
			if (status != APR_SUCCESS || *end || end == orig_content_length || content_length < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, SHOW_MODULE "Failed to parse the original Content-Length value %s, cannot update it after redacting password, clearing", orig_content_length);
				apr_table_unset(r->headers_in, "Content-Length");
			} else {
				apr_table_setn(r->headers_in, "Content-Length", apr_psprintf(r->pool, "%ld", content_length - password_remove_length + new_password_data_length));
			}
		}
	}
}

static int intercept_form_submit_process_buffer(ap_filter_t * f, ifs_config * config, char ** login_value, char ** password_value,
	const char * buffer, int buffer_length, apr_bucket * fragment_start_bucket, int fragment_start_bucket_offset, authn_status * out_status) {
	char * sep = memchr(buffer, '=', buffer_length);
	if (! sep) {
		return 0;
	}
	request_rec * r = f->r;
	int run_auth = 0;
	if (! *login_value) {
		*login_value = intercept_form_submit_process_keyval(r->pool, config->login_name,
			buffer, sep - buffer, sep + 1, buffer_length - (sep - buffer) - 1);
		if (*login_value) {
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
				SHOW_MODULE "login found in POST: %s=%s", config->login_name, *login_value);
			if (config->login_blacklist && apr_hash_get(config->login_blacklist, *login_value, APR_HASH_KEY_STRING)) {
				ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
					SHOW_MODULE "login %s in blacklist, stopping", *login_value);
				if (config->clear_blacklisted > 0) {
					apr_table_unset(r->subprocess_env, _REMOTE_USER_ENV_NAME);
					r->user = NULL;
				}
				return 1;
			}
			if (*password_value) {
				run_auth = 1;
			}
		}
	}
	if (! *password_value) {
		*password_value = intercept_form_submit_process_keyval(r->pool, config->password_name,
			buffer, sep - buffer, sep + 1, buffer_length - (sep - buffer) - 1);
		if (*password_value) {
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
				SHOW_MODULE "password found in POST: %s=" _REDACTED_STRING, config->password_name);
			if (*login_value) {
				run_auth = 1;
			}
			ifs_filter_ctx_t * ctx = f->ctx;
			ctx->password_fragment_start_bucket = fragment_start_bucket;
			ctx->password_fragment_start_bucket_offset = fragment_start_bucket_offset;
		}
	}
	if (run_auth) {
		if (! pam_authenticate_with_login_password_fn) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, SHOW_MODULE "pam_authenticate_with_login_password not found; perhaps mod_authnz_pam is not loaded");
			return 0;
		}
		(*out_status) = pam_authenticate_in_realms(r, config->pam_service, *login_value, *password_value, config->realms, 3);
		if (config->password_redact > 0) {
			intercept_form_redact_password(f, config);
		}
		return 1;
	}
	return 0;
}

static apr_status_t intercept_form_submit_filter(ap_filter_t * f, apr_bucket_brigade * bb,
	ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
	ifs_filter_ctx_t * ctx = f->ctx;
	if (ctx && ctx->cached_brigade) {
		APR_BRIGADE_CONCAT(bb, ctx->cached_brigade);
		apr_brigade_cleanup(ctx->cached_brigade);
		ctx->cached_brigade = NULL;
		return ctx->cached_ret;
	}
	return ap_get_brigade(f->next, bb, mode, block, readbytes);
}

static apr_status_t intercept_form_submit_filter_prefetch(request_rec * r, ifs_config * config, ap_filter_t * f) {
	if (r->status != 200)
		return DECLINED;

	ifs_filter_ctx_t * ctx = f->ctx;
	if (! ctx) {
		f->ctx = ctx = apr_pcalloc(r->pool, sizeof(ifs_filter_ctx_t));
		ctx->cached_brigade = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
	}

	char * login_value = NULL;
	char * password_value = NULL;

	char * fragment = NULL;
	int fragment_length = 0;
	apr_bucket * fragment_start_bucket = NULL;
	int fragment_start_bucket_offset = 0;

	authn_status out_status = AUTH_GENERAL_ERROR;

	apr_bucket_brigade * bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
	int fetch_more = 1;
	while (fetch_more) {
		ctx->cached_ret = ap_get_brigade(f->next, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
		if (ctx->cached_ret != APR_SUCCESS)
			break;

		apr_bucket * b = APR_BRIGADE_FIRST(bb);
		APR_BRIGADE_CONCAT(ctx->cached_brigade, bb);
		for (; b != APR_BRIGADE_SENTINEL(ctx->cached_brigade); b = APR_BUCKET_NEXT(b)) {
			if (! fetch_more)
				break;
			if (APR_BUCKET_IS_EOS(b)) {
				if (fragment)
					intercept_form_submit_process_buffer(f, config, &login_value, &password_value,
						fragment, fragment_length, fragment_start_bucket, fragment_start_bucket_offset, &out_status);
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "hit EOS");
				fetch_more = 0;
				break;
			}
			if (APR_BUCKET_IS_METADATA(b))
				continue;

			const char * buffer;
			apr_size_t nbytes;
			if (apr_bucket_read(b, &buffer, &nbytes, APR_BLOCK_READ) != APR_SUCCESS)
				continue;
			if (! nbytes)
				continue;

			const char * p = buffer;
			const char * e;
			while ((nbytes > 0) && (e = memchr(p, '&', nbytes))) {
				if (fragment) {
					int new_length = fragment_length + (e - p);
					fragment = realloc(fragment, new_length);
					memcpy(fragment + fragment_length, p, e - p);
					if (intercept_form_submit_process_buffer(f, config, &login_value, &password_value,
						fragment, new_length, fragment_start_bucket, fragment_start_bucket_offset, &out_status)) {
						fetch_more = 0;
						break;
					}
					free(fragment);
					fragment = NULL;
				} else {
					if (intercept_form_submit_process_buffer(f, config, &login_value, &password_value,
						p, e - p, b, (p - buffer), &out_status)) {
						fetch_more = 0;
						break;
					}
				}
				nbytes -= (e - p) + 1;
				p = e + 1;
			}
			if (! fetch_more)
				break;
			if (nbytes > 0) {
				if (fragment) {
					int new_length = fragment_length + nbytes;
					fragment = realloc(fragment, new_length);
					memcpy(fragment + fragment_length, p, nbytes);
					fragment_length = new_length;
				} else if (APR_BUCKET_NEXT(b) && APR_BUCKET_IS_EOS(APR_BUCKET_NEXT(b))) {
					/* shortcut if this is the last bucket, slurp the rest */
					intercept_form_submit_process_buffer(f, config, &login_value, &password_value,
						p, nbytes, b, (p - buffer), &out_status);
					fetch_more = 0;
				} else {
					fragment = malloc(nbytes);
					memcpy(fragment, p, nbytes);
					fragment_length = nbytes;
					fragment_start_bucket = b;
					fragment_start_bucket_offset = p - buffer;
				}
			}
		}
	}
	if (fragment)
		free(fragment);
	return out_status == AUTH_GRANTED ? OK : DECLINED;
}

#define _INTERCEPT_CONTENT_TYPE "application/x-www-form-urlencoded"
static apr_status_t intercept_form_submit_init(request_rec * r) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "intercept_form_submit_init invoked");
	if (r->method_number != M_POST) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "skipping, no POST request");
		return DECLINED;
	}
	ifs_config * config = ap_get_module_config(r->per_dir_config, &intercept_form_submit_module);
	if (!(config && config->login_name && config->password_name && config->pam_service)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "skipping, not configured");
		return DECLINED;
	}
	if (apr_table_get(r->subprocess_env, _REMOTE_USER_ENV_NAME)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "skipping, " _REMOTE_USER_ENV_NAME " already set");
		return DECLINED;
	}
	const char * content_type = apr_table_get(r->headers_in, "Content-Type");
	if (content_type) {
		char * content_type_pure = apr_pstrdup(r->pool, content_type);
		char * sep;
		if ((sep = strchr(content_type_pure, ';'))) {
			*sep = '\0';
		}
		apr_collapse_spaces(content_type_pure, content_type_pure);
		if (!apr_strnatcasecmp(content_type_pure, _INTERCEPT_CONTENT_TYPE)) {
			ap_filter_t * the_filter = ap_add_input_filter("intercept_form_submit_filter", NULL, r, r->connection);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "inserted filter intercept_form_submit_filter, starting intercept_form_submit_filter_prefetch");
			apr_status_t status = intercept_form_submit_filter_prefetch(r, config, the_filter);
			if (status == OK && config->success_to_get >= 0) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "intercept_form_submit_filter_prefetch returned OK, turning the method to GET");
				r->status_line = NULL;
				r->method = "GET";
				r->method_number = M_GET;
				apr_table_unset(r->headers_in, "Content-Length");
			}
			return DECLINED;
		}
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, SHOW_MODULE "skipping, no " _INTERCEPT_CONTENT_TYPE);
	return DECLINED;
}

static void * create_dir_conf(apr_pool_t * pool, char * dir) {
	ifs_config * cfg = apr_pcalloc(pool, sizeof(ifs_config));
	cfg->password_redact = -1;
	cfg->clear_blacklisted = -1;
	cfg->success_to_get = -1;
	return cfg;
}

static void * merge_dir_conf(apr_pool_t * pool, void * base_void, void * add_void) {
	ifs_config * base = (ifs_config *) base_void;
	ifs_config * add = (ifs_config *) add_void;
	ifs_config * cfg = (ifs_config *) create_dir_conf(pool, NULL);
	cfg->login_name = add->login_name ? add->login_name : base->login_name;
	cfg->password_name = add->password_name ? add->password_name : base->password_name;
	cfg->password_redact = add->password_redact >= 0 ? add->password_redact : base->password_redact;
	cfg->success_to_get = add->success_to_get >= 0 ? add->success_to_get : base->success_to_get;
	cfg->clear_blacklisted = add->clear_blacklisted >= 0 ? add->clear_blacklisted : base->clear_blacklisted;
	cfg->pam_service = add->pam_service ? add->pam_service : base->pam_service;
	if (add->login_blacklist) {
		if (base->login_blacklist) {
			cfg->login_blacklist = apr_hash_overlay(apr_hash_pool_get(add->login_blacklist), add->login_blacklist, base->login_blacklist);
		} else {
			cfg->login_blacklist = add->login_blacklist;
		}
	} else if (base->login_blacklist) {
		cfg->login_blacklist = base->login_blacklist;
	}
	cfg->realms = add->realms ? add->realms : base->realms;
	return cfg;
}

static void register_hooks(apr_pool_t * pool) {
	ap_hook_fixups(intercept_form_submit_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_register_input_filter("intercept_form_submit_filter", intercept_form_submit_filter, NULL, AP_FTYPE_RESOURCE);
	ap_hook_optional_fn_retrieve(register_pam_authenticate_with_login_password_fn, NULL, NULL, APR_HOOK_MIDDLE);
}

#ifdef AP_DECLARE_MODULE
AP_DECLARE_MODULE(intercept_form_submit)
#else
module AP_MODULE_DECLARE_DATA intercept_form_submit_module
#endif
	= {
	STANDARD20_MODULE_STUFF,
	create_dir_conf,		/* Per-directory configuration handler */
	merge_dir_conf,			/* Merge handler for per-directory configurations */
	NULL,				/* Per-server configuration handler */
	NULL,				/* Merge handler for per-server configurations */
	directives,			/* Any directives we may have for httpd */
	register_hooks			/* Our hook registering function */
};

