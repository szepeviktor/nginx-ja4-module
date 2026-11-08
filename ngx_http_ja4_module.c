/* JA4 for incoming HTTP TLS connections; shares the Apache module's parser. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>
#include <stdlib.h>
#include "ja4.h"

static int ngx_http_ja4_index = -1;

static void
ngx_http_ja4_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
    long argl, void *argp)
{
    ja4_result *result = ptr;
    (void) parent; (void) ad; (void) idx; (void) argl; (void) argp;
    if (result != NULL) {
        free(result->raw);
        free(result);
    }
}

static void
ngx_http_ja4_observe(int write_p, int version, int content_type,
    const void *buffer, size_t length, SSL *ssl, void *arg)
{
    const unsigned char *message = buffer;
    ja4_result *result;
    (void) version; (void) arg;

    if (write_p || content_type != SSL3_RT_HANDSHAKE || length == 0
        || message[0] != SSL3_MT_CLIENT_HELLO
        || SSL_get_ex_data(ssl, ngx_http_ja4_index) != NULL)
    {
        return;
    }

    result = calloc(1, sizeof(*result));
    if (result == NULL) {
        return;
    }
    if (!SSL_set_ex_data(ssl, ngx_http_ja4_index, result)) {
        free(result);
        return;
    }
    /* Even a failed parse marks the initial hello as seen. Keep it across HRR. */
    (void) ja4_compute(message, length, result);
}

static ngx_int_t
ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t raw)
{
    ja4_result *result;
    char *value;

    v->not_found = 1;
    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }
    result = SSL_get_ex_data(r->connection->ssl->connection,
                             ngx_http_ja4_index);
    if (result == NULL || result->raw == NULL) {
        return NGX_OK;
    }
    value = raw ? result->raw : result->fingerprint;
    v->data = (u_char *) value;
    v->len = ngx_strlen(value);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_ja4_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *variable;
    ngx_str_t names[] = { ngx_string("ja4"), ngx_string("ja4_raw") };
    ngx_uint_t i;

    for (i = 0; i < 2; i++) {
        variable = ngx_http_add_variable(cf, &names[i], 0);
        if (variable == NULL) {
            return NGX_ERROR;
        }
        variable->get_handler = ngx_http_ja4_variable;
        variable->data = i;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_ja4_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_core_srv_conf_t **servers;
    ngx_http_ssl_srv_conf_t *sslcf;
    ngx_uint_t i;

    if (ngx_http_ja4_index == -1) {
        ngx_http_ja4_index = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                ngx_http_ja4_free);
        if (ngx_http_ja4_index == -1) {
            return NGX_ERROR;
        }
    }
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    servers = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        sslcf = ngx_http_conf_get_module_srv_conf(servers[i],
                                                ngx_http_ssl_module);
        if (sslcf->ssl.ctx != NULL) {
            SSL_CTX_set_msg_callback(sslcf->ssl.ctx, ngx_http_ja4_observe);
            SSL_CTX_set_msg_callback_arg(sslcf->ssl.ctx, NULL);
        }
    }
    return NGX_OK;
}

static ngx_http_module_t ngx_http_ja4_context = {
    ngx_http_ja4_variables, ngx_http_ja4_init,
    NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ja4_context,
    NULL,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
