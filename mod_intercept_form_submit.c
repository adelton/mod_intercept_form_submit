
/*
 * Copyright 2013 Jan Pazdziora
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
#include "http_core.h"
#include "http_log.h"
#include "http_config.h"
#include "http_request.h"

#include <security/pam_appl.h>

typedef struct ifs_config {
	char * login_name;
	char * password_name;
	char * pam_service;
	apr_hash_t * login_blacklist;
} ifs_config;

typedef struct {
	int no_more_filtering;
	char * fragment;
	int fragment_length;
	char * login_value;
	char * password_value;
	ifs_config * config;
} ifs_filter_ctx_t;

module AP_MODULE_DECLARE_DATA intercept_form_submit_module;

const char * set_login_name(cmd_parms * cmd, void * conf_void, const char * arg) {
	ifs_config * cfg = (ifs_config *) conf_void;
	if (cfg) {
		cfg->login_name = apr_pstrdup(cmd->pool, arg);
	}
	return NULL;
}

const char * set_password_name(cmd_parms * cmd, void * conf_void, const char * arg) {
	ifs_config * cfg = (ifs_config *) conf_void;
	if (cfg) {
		cfg->password_name = apr_pstrdup(cmd->pool, arg);
	}
	return NULL;
}

const char * set_pam_service(cmd_parms * cmd, void * conf_void, const char * arg) {
	ifs_config * cfg = (ifs_config *) conf_void;
	if (cfg) {
		cfg->pam_service = apr_pstrdup(cmd->pool, arg);
	}
	return NULL;
}

const char * add_login_to_blacklist(cmd_parms * cmd, void * conf_void, const char * arg) {
	ifs_config * cfg = (ifs_config *) conf_void;
	if (cfg) {
		if (! cfg->login_blacklist) {
			cfg->login_blacklist = apr_hash_make(cmd->pool);
		}
		apr_hash_set(cfg->login_blacklist, apr_pstrdup(cmd->pool, arg), APR_HASH_KEY_STRING, "1");
	}
	return NULL;
}

static const command_rec directives[] = {
	AP_INIT_TAKE1("InterceptFormLogin", set_login_name, NULL, ACCESS_CONF, "Name of the login parameter in the POST request"),
	AP_INIT_TAKE1("InterceptFormPassword", set_password_name, NULL, ACCESS_CONF, "Name of the password parameter in the POST request"),
	AP_INIT_TAKE1("InterceptFormPAMService", set_pam_service, NULL, ACCESS_CONF, "PAM service to authenticate against"),
	AP_INIT_ITERATE("InterceptFormLoginSkip", add_login_to_blacklist, NULL, ACCESS_CONF, "Login name(s) for which no PAM authentication will be done"),
	{ NULL }
};

int pam_authenticate_conv(int num_msg, const struct pam_message ** msg, struct pam_response ** resp, void * appdata_ptr) {
	struct pam_response * response = NULL;
	if (!msg || !resp || !appdata_ptr)
		return PAM_CONV_ERR;
	if (!(response = malloc(num_msg * sizeof(struct pam_response))))
		return PAM_CONV_ERR;
	int i;
	for (i = 0; i < num_msg; i++) {
		response[i].resp = 0;
		response[i].resp_retcode = 0;
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
			response[i].resp = strdup(appdata_ptr);
		} else {
			free(response);
			return PAM_CONV_ERR;
		}
	}
	* resp = response;
	return PAM_SUCCESS;
}

int pam_authenticate_with_login_password(request_rec * r, ifs_config * config, char * login, char * password) {
	pam_handle_t * pamh = NULL;
	struct pam_conv pam_conversation = { &pam_authenticate_conv, (void *) password };
	int ret;
	if ((ret = pam_start(config->pam_service, login, &pam_conversation, &pamh)) != PAM_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
			"mod_intercept_form_submit: PAM transaction failed for service %s: %s", config->pam_service, pam_strerror(pamh, ret));
		pam_end(pamh, ret);
		return 0;
	}
	if ((ret = pam_authenticate(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
			"mod_intercept_form_submit: PAM authentication failed for user %s: %s", login, pam_strerror(pamh, ret));
		pam_end(pamh, ret);
		return 0;
	}
	apr_table_setn(r->subprocess_env, "REMOTE_USER", login);
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_intercept_form_submit: PAM authentication passed for user %s", login);
	pam_end(pamh, ret);
	return 1;
}

#define _INTERCEPT_CONTENT_TYPE "application/x-www-form-urlencoded"
void intercept_form_submit_init(request_rec * r) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_intercept_form_submit: intercept_form_submit_init invoked");
	if (r->method_number != M_POST) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_intercept_form_submit: skipping, no POST request");
		return;
	}
	ifs_config * config = ap_get_module_config(r->per_dir_config, &intercept_form_submit_module);
	if (!(config && config->login_name && config->password_name && config->pam_service)) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_intercept_form_submit: skipping, not configured");
		return;
	}
	const char * content_type = apr_table_get(r->headers_in, "Content-Type");
	if (content_type && !apr_strnatcasecmp(content_type, _INTERCEPT_CONTENT_TYPE)) {
		ap_add_input_filter("intercept_form_submit_filter", NULL, r, r->connection);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_intercept_form_submit: inserted filter intercept_form_submit_filter");
	} else {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mod_intercept_form_submit: skipping, no " _INTERCEPT_CONTENT_TYPE);
	}
}

int hex2char(int c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 10;
	return -1;
}

char * intercept_form_submit_process_keyval(apr_pool_t * pool, const char * name,
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

int intercept_form_submit_process_buffer(request_rec * r, ifs_filter_ctx_t * ctx, const char * buffer, int buffer_length) {
	char * sep = memchr(buffer, '=', buffer_length);
	if (! sep) {
		return 0;
	}
	int run_auth = 0;
	if (! ctx->login_value) {
		ctx->login_value = intercept_form_submit_process_keyval(r->pool, ctx->config->login_name,
			buffer, sep - buffer, sep + 1, buffer_length - (sep - buffer) - 1);
		if (ctx->login_value) {
			ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
				"mod_intercept_form_submit: login found in POST: %s=%s", ctx->config->login_name, ctx->login_value);
			if (ctx->config->login_blacklist && apr_hash_get(ctx->config->login_blacklist, ctx->login_value, APR_HASH_KEY_STRING)) {
				ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
					"mod_intercept_form_submit: login %s in blacklist, stopping", ctx->login_value);
				ctx->no_more_filtering = 1;
				return 1;
			}
			if (ctx->password_value) {
				run_auth = 1;
			}
		}
	}
	if (! ctx->password_value) {
		ctx->password_value = intercept_form_submit_process_keyval(r->pool, ctx->config->password_name,
			buffer, sep - buffer, sep + 1, buffer_length - (sep - buffer) - 1);
		if (ctx->password_value) {
			ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
				"mod_intercept_form_submit: password found in POST: %s=[REDACTED]", ctx->config->password_name);
			if (ctx->login_value) {
				run_auth = 1;
			}
		}
	}
	if (run_auth) {
		pam_authenticate_with_login_password(r, ctx->config, ctx->login_value, ctx->password_value);
		ctx->no_more_filtering = 1;
		return 1;
	}
	return 0;
}

static apr_status_t intercept_form_submit_filter(ap_filter_t * f, apr_bucket_brigade * bb,
	ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
	apr_status_t ret = ap_get_brigade(f->next, bb, mode, block, readbytes);
	if (ret != APR_SUCCESS) {
		return ret;
	}

	ifs_filter_ctx_t * ctx = f->ctx;
	if (! ctx) {
		ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(ifs_filter_ctx_t));
		ctx->config = ap_get_module_config(f->r->per_dir_config, &intercept_form_submit_module);
	}

	apr_bucket * b;
	for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
		if (ctx->no_more_filtering)
			break;
		if (APR_BUCKET_IS_EOS(b)) {
			if (ctx->fragment) {
				intercept_form_submit_process_buffer(f->r, ctx, ctx->fragment, ctx->fragment_length);
				ctx->no_more_filtering = 1;
			}
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "mod_intercept_form_submit: hit EOS");
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
			if (ctx->fragment) {
				int new_length = ctx->fragment_length + (e - p);
				ctx->fragment = realloc(ctx->fragment, new_length);
				memcpy(ctx->fragment + ctx->fragment_length, p, e - p);
				if (intercept_form_submit_process_buffer(f->r, ctx, ctx->fragment, new_length))
					break;
				free(ctx->fragment);
				ctx->fragment = NULL;
			} else {
				if (intercept_form_submit_process_buffer(f->r, ctx, p, e - p))
					break;
			}
			nbytes -= (e - p) + 1;
			p = e + 1;
		}
		if (ctx->no_more_filtering)
			break;
		if (nbytes > 0) {
			if (APR_BUCKET_NEXT(b) && APR_BUCKET_IS_EOS(APR_BUCKET_NEXT(b))) {
				/* shortcut if this is the last bucket, slurp the rest */
				intercept_form_submit_process_buffer(f->r, ctx, p, nbytes);
			} else {
				ctx->fragment = malloc(nbytes);
				memcpy(ctx->fragment, p, nbytes);
				ctx->fragment_length = nbytes;
			}
		}
	}
	if (ctx->no_more_filtering && ctx->fragment) {
		free(ctx->fragment);
		ctx->fragment = NULL;
	}
	return APR_SUCCESS;
}

void * create_dir_conf(apr_pool_t * pool, char * dir) {
	ifs_config * cfg = apr_pcalloc(pool, sizeof(ifs_config));
	if (cfg) {
		cfg->login_name = cfg->password_name = NULL;
	}
	return cfg;
}

void * merge_dir_conf(apr_pool_t * pool, void * base_void, void * add_void) {
	ifs_config * base = (ifs_config *) base_void;
	ifs_config * add = (ifs_config *) add_void;
	ifs_config * cfg = (ifs_config *) create_dir_conf(pool, NULL);
	cfg->login_name = add->login_name ? add->login_name : base->login_name;
	cfg->password_name = add->password_name ? add->password_name : base->password_name;
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
	return cfg;
}

static void register_hooks(apr_pool_t * pool) {
	ap_hook_insert_filter(intercept_form_submit_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_register_input_filter("intercept_form_submit_filter", intercept_form_submit_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA intercept_form_submit_module = {
	STANDARD20_MODULE_STUFF,
	create_dir_conf,		/* Per-directory configuration handler */
	merge_dir_conf,			/* Merge handler for per-directory configurations */
	NULL,				/* Per-server configuration handler */
	NULL,				/* Merge handler for per-server configurations */
	directives,			/* Any directives we may have for httpd */
	register_hooks			/* Our hook registering function */
};

