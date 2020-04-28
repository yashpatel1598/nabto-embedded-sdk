#include "nc_udp_dispatch.h"

#include <platform/np_logging.h>
#include <platform/np_udp.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connection_dispatch.h>
#include <core/nc_stun.h>

#define LOG NABTO_LOG_MODULE_UDP_DISPATCH

void nc_udp_dispatch_sock_bound_cb(const np_error_code ec, void* data);
void nc_udp_dispatch_handle_packet(struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize, struct nc_udp_dispatch_context* ctx);

static void start_recv(struct nc_udp_dispatch_context* ctx);
static void async_recv_wait_complete(const np_error_code ec, void* userData);

np_error_code nc_udp_dispatch_init(struct nc_udp_dispatch_context* ctx, struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_udp_dispatch_context));
    ctx->pl = pl;
    ctx->recvBuffer = pl->buf.allocate();
    np_error_code ec = pl->udp.create(pl, &ctx->sock);
    return ec;
}

void nc_udp_dispatch_deinit(struct nc_udp_dispatch_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        struct np_platform* pl = ctx->pl;
        pl->udp.destroy(ctx->sock);
        pl->buf.free(ctx->recvBuffer);
    }
}


void nc_udp_dispatch_async_bind(struct nc_udp_dispatch_context* ctx, struct np_platform* pl, uint16_t port,
                                nc_udp_dispatch_bind_callback cb, void* data)
{
    ctx->bindCb = cb;
    ctx->bindCbData = data;
    np_completion_event_init(pl, &ctx->bindCompletionEvent, nc_udp_dispatch_sock_bound_cb, ctx);
    pl->udp.async_bind_port(ctx->sock, port, &ctx->bindCompletionEvent);
}

void nc_udp_dispatch_sock_bound_cb(const np_error_code ec, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    if (ec == NABTO_EC_OK) {
        start_recv(ctx);
    }
    ctx->bindCb(ec, ctx->bindCbData);
    ctx->bindCb = NULL;
}

np_error_code nc_udp_dispatch_abort(struct nc_udp_dispatch_context* ctx)
{
    ctx->pl->udp.abort(ctx->sock);
    return NABTO_EC_OK;
}

void nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx,struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize,
                                   struct np_completion_event* completionEvent)
{
    ctx->pl->udp.async_send_to(ctx->sock, ep, buffer, bufferSize, completionEvent);
}

uint16_t nc_udp_dispatch_get_local_port(struct nc_udp_dispatch_context* ctx)
{
    return ctx->pl->udp.get_local_port(ctx->sock);
}

void start_recv(struct nc_udp_dispatch_context* ctx)
{
    struct np_platform* pl = ctx->pl;

    np_completion_event_init(pl, &ctx->recvCompletionEvent, async_recv_wait_complete, ctx);
    ctx->pl->udp.async_recv_wait(ctx->sock, &ctx->recvCompletionEvent);

}

void async_recv_wait_complete(const np_error_code ec, void* userData)
{
    struct nc_udp_dispatch_context* ctx = userData;
    struct np_platform* pl = ctx->pl;
    if (ec) {
        return;
    }

    struct np_udp_endpoint ep;
    uint8_t* bufferStart = pl->buf.start(ctx->recvBuffer);
    size_t bufferLength = pl->buf.size(ctx->recvBuffer);
    size_t recvLength;
    np_error_code recvEc = ctx->pl->udp.recv_from(ctx->sock, &ep, bufferStart, bufferLength, &recvLength);
    if (recvEc == NABTO_EC_OK) {
        nc_udp_dispatch_handle_packet(&ep, bufferStart, recvLength, ctx);
    }

    if (recvEc == NABTO_EC_OK || recvEc == NABTO_EC_AGAIN) {
        start_recv(ctx);
    }

}

void nc_udp_dispatch_handle_packet(struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize, struct nc_udp_dispatch_context* ctx)
{
    uint8_t* start = buffer;

    // ec == OK
    if(ctx->stun != NULL && ((start[0] == 0) || (start[0] == 1))) {
        nc_stun_handle_packet(ctx->stun, ep, buffer, bufferSize);
    }  else if (ctx->dtls != NULL && ((start[0] >= 20)  && (start[0] <= 64))) {
        ctx->pl->dtlsC.handle_packet(ctx->dtls, buffer, bufferSize);
    } else if (ctx->cliConn != NULL && (start[0] >= 240)) {
        nc_client_connection_dispatch_handle_packet(ctx->cliConn, ctx, ep, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "Unable to dispatch packet with ID: %u", start[0]);
    }
}

void nc_udp_dispatch_set_client_connection_context(struct nc_udp_dispatch_context* ctx,
                                                   struct nc_client_connection_dispatch_context* cliConn)
{
    ctx->cliConn = cliConn;
}

void nc_udp_dispatch_set_dtls_cli_context(struct nc_udp_dispatch_context* ctx,
                                          struct np_dtls_cli_context* dtls)
{
    ctx->dtls = dtls;
}

void nc_udp_dispatch_set_stun_context(struct nc_udp_dispatch_context* ctx,
                                      struct nc_stun_context* stun)
{
    ctx->stun = stun;
}

void nc_udp_dispatch_clear_client_connection_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->cliConn = NULL;
}

void nc_udp_dispatch_clear_dtls_cli_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->dtls = NULL;
}

void nc_udp_dispatch_clear_stun_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->stun = NULL;
}
