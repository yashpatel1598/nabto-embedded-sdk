#include "nm_libevent.h"
#include <event2/dns.h>

#include <platform/np_ip_address.h>
#include <platform/interfaces/np_dns.h>
#include <platform/np_platform.h>
#include <platform/np_completion_event.h>

#include <stdlib.h>
#include <string.h>

#define DNS_RECORDS_SIZE 4

struct nm_dns_request {
    struct np_platform* pl;
    struct evdns_request* request;
    struct np_completion_event* completionEvent;
    struct np_ip_address* ips;
    struct evdns_getaddrinfo_request* req;
    struct evdns_base* dnsBase;
    size_t ipsSize;
    size_t* ipsResolved;
};

static void dns_cb(int result, struct evutil_addrinfo *res, void *arg);


static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

static struct np_dns_functions module = {
    &async_resolve_v4,
    &async_resolve_v6
};

struct np_dns nm_libevent_dns_get_impl(struct nm_libevent_context* ctx)
{
    struct np_dns obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_context* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->dnsBase = dnsBase;
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(struct evutil_addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_flags = 0; //AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;
    const char* service = "443";
    dnsRequest->req = evdns_getaddrinfo(dnsBase, host, service, &hints, dns_cb, dnsRequest);
}

static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_context* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->dnsBase = dnsBase;
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(struct evutil_addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_flags = 0; //AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;
    const char* service = "443";
    dnsRequest->req = evdns_getaddrinfo(dnsBase, host, service, &hints, dns_cb, dnsRequest);
}

void dns_cb(int result, struct evutil_addrinfo *res, void *arg)
{
    struct nm_dns_request* ctx = arg;

    if (result == EVUTIL_EAI_FAIL) {
        // maybe the system has changed nameservers, reload them
        struct evdns_base* base = ctx->dnsBase;
#ifdef _WIN32
        evdns_base_clear_host_addresses(base);
        evdns_base_config_windows_nameservers(base);
#else
        evdns_base_clear_host_addresses(base);
        evdns_base_resolv_conf_parse(base, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
#endif
    }

    if (result != 0) {
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_UNKNOWN);
        free(ctx);
        return;
    }

    size_t resolved = 0;
    while(res != NULL && resolved < ctx->ipsSize) {
        if (res->ai_family == AF_INET) {
            ctx->ips[resolved].type = NABTO_IPV4;
            struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
            memcpy(ctx->ips[resolved].ip.v4, (uint8_t*)(&addr->sin_addr.s_addr), 4);
            resolved++;
        } else if (res->ai_family == AF_INET6) {
            ctx->ips[resolved].type = NABTO_IPV6;
            struct sockaddr_in6* addr = (struct sockaddr_in6*)res->ai_addr;
            memcpy(ctx->ips[resolved].ip.v6, addr->sin6_addr.__in6_u.__u6_addr8, 16);
            resolved++;
        }
        res = res->ai_next;
    }

    if (resolved == 0) {
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_NO_DATA);
    } else {
        *ctx->ipsResolved = resolved;
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_OK);
    }
    free(ctx);
}
