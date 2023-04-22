//
// Nginx http ipset black/whitelist access module by Vasfed
//
// Usage:
// place a "blacklist 'ipset_name';" config option in http or a virtual host context
// there can be only one list, its color is determined by cmd name.
//
// blacklist => deny request if ip is in list
// whitelist => deny everything except in list
//
//
// note: restart nginx if ipset is renamed/moved/deleted etc.
// no need for restart on ipset content change (that's what this module is for :) )
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/socket.h>

#include "ipset_test.h"




static char*     ngx_http_ipset_access_list_conf      (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void*     ngx_http_ipset_access_create_srv_conf(ngx_conf_t *cf);
static char*     ngx_http_ipset_access_merge_srv_conf (ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_ipset_access_init           (ngx_conf_t *cf);
static ngx_int_t ngx_http_ipset_on_init_process       (ngx_cycle_t *cycle);
//-------------------------------------------------------------------------------------------------------------
//NGINX module ABI:

static ngx_command_t  ngx_http_ipset_access_commands[] = {

    { ngx_string("blacklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF // configurable per virtual server
      | NGX_CONF_TAKE2,
      ngx_http_ipset_access_list_conf,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whitelist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF 
      | NGX_CONF_TAKE2,
      ngx_http_ipset_access_list_conf,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_ipset_blacklist_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ipset_access_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ipset_access_create_srv_conf, /* create server configuration */
    ngx_http_ipset_access_merge_srv_conf,  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ipset_blacklist = {
    NGX_MODULE_V1,
    &ngx_http_ipset_blacklist_module_ctx,  /* module context */
    ngx_http_ipset_access_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_ipset_on_init_process,        /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

//-------------------------------------------------------------------------------------------------------------
//Config-related:

typedef struct {
  enum {
    e_mode_not_configured = 0,
    e_mode_off,
    e_mode_blacklist,
    e_mode_whitelist
    } mode;
  char setname4[32];
  char setname6[32];
} ngx_http_ipset_access_server_conf_t;



static void* ngx_http_ipset_access_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ipset_access_server_conf_t  *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipset_access_server_conf_t));
    if (conf == NULL) {
        //indicate some error?
        return NULL;
    }

    return conf;
}

static char* ngx_http_ipset_access_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ipset_access_server_conf_t  *prev = parent;
    ngx_http_ipset_access_server_conf_t  *conf = child;

    if (!conf->mode) {
        conf->mode = prev->mode;
        strncpy(conf->setname4, prev->setname4, IP_SET_MAXNAMELEN);
        strncpy(conf->setname6, prev->setname6, IP_SET_MAXNAMELEN);
    }

    return NGX_CONF_OK;
}

static char* ngx_http_ipset_access_list_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *p_conf)
{
    //alcf= conf
    ngx_http_ipset_access_server_conf_t *conf = p_conf;
    ngx_str_t *value = cf->args->elts;

    if (value[1].len == 3 && !ngx_strcmp(value[1].data, "off")) {
      conf->mode = e_mode_off;
      return NGX_CONF_OK;
    }
    
    //check if cmd was 'whitelist' or 'blacklist'
    conf->mode = value[0].data[0] == 'b' ? e_mode_blacklist : e_mode_whitelist;
    strncpy(conf->setname4, (char *) value[1].data, IP_SET_MAXNAMELEN);
    strncpy(conf->setname6, (char *) value[2].data, IP_SET_MAXNAMELEN);

    return NGX_CONF_OK;
}

//-------------------------------------------------------------------------------------------------------------
static ngx_int_t ngx_http_ipset_on_init_process(ngx_cycle_t *cycle){  
  
  if (init_ipset_test_clnt()) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_int_t ngx_http_ipset_access_handler(ngx_http_request_t *r)
{
  ngx_http_ipset_access_server_conf_t  *conf = ngx_http_get_module_srv_conf(r, ngx_http_ipset_blacklist);
  if (conf->mode != e_mode_not_configured) {
    int res;
    res = test_ipaddr_in_ipset(
      r->connection->sockaddr->sa_family == AF_INET ? conf->setname4 : conf->setname6, 
      r->connection->sockaddr->sa_family, r->connection->sockaddr
    );

    if(res == 1){
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "failed to read white/blacklist");
    }
    // fprintf(stderr, "ipset res = %d\n", res);
    
    if((conf->mode == e_mode_whitelist && res == IPADDR_NOT_IN_IPSET) ||
        (conf->mode == e_mode_blacklist && res == IPADDR_IN_IPSET)) {
      r->keepalive = 0;
      return NGX_HTTP_FORBIDDEN;
    } else {
      return NGX_OK;
    }
  }

  return NGX_DECLINED; // we have nothing to do with this request => pass to next handler
}


#define checked_array_push(arr, elem) { h = ngx_array_push(&arr); if (h == NULL){ return NGX_ERROR;} *h = elem; }
//extern ngx_module_t  ngx_core_module;

static ngx_int_t ngx_http_ipset_access_init(ngx_conf_t *cf)
{
    //check conf:
    // ngx_core_conf_t* ccf;
    // ccf = (ngx_core_conf_t *) NULL; //ngx_get_conf(???, ngx_core_module);

    //install handler
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    checked_array_push(cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers, ngx_http_ipset_access_handler);

    return NGX_OK;
}
