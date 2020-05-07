#include "nm_select_unix_udp.h"

#include <platform/np_logging.h>
#include <platform/np_util.h>
#include <platform/np_completion_event.h>

#include <modules/unix/nm_unix_mdns.h>
#include <modules/unix/nm_unix_get_local_ip.h>
#include <modules/posix/nm_posix_udp.h>

#include <stdlib.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#define LOG NABTO_LOG_MODULE_UDP

/**
 * Helper function declarations
 */
static void nm_select_unix_udp_handle_event(struct np_udp_socket* sock);
static void nm_select_unix_udp_free_socket(struct np_udp_socket* sock);

/**
 * Api function declarations
 */
static np_error_code nm_select_unix_udp_create(struct np_platform* pl, struct np_udp_socket** sock);
static void nm_select_unix_udp_destroy(struct np_udp_socket* sock);
static void nm_select_unix_udp_abort(struct np_udp_socket* sock);
static void nm_select_unix_udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent);
static void nm_select_unix_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static void nm_select_unix_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent);
static void nm_select_unix_udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                             uint8_t* buffer, uint16_t bufferSize,
                                             struct np_completion_event* completionEvent);
static void nm_select_unix_udp_async_recv_wait(struct np_udp_socket* socket, struct np_completion_event* completionEvent);
static np_error_code nm_select_unix_udp_recv_from(struct np_udp_socket* socket, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength);
static uint16_t nm_select_unix_udp_get_local_port(struct np_udp_socket* socket);

np_error_code nm_select_unix_udp_init(struct nm_select_unix* ctx, struct np_platform *pl)
{
    struct nm_select_unix_udp_sockets* sockets = &ctx->udpSockets;
    pl->udp.create           = &nm_select_unix_udp_create;
    pl->udp.destroy          = &nm_select_unix_udp_destroy;
    pl->udp.abort            = &nm_select_unix_udp_abort;
    pl->udp.async_bind_port  = &nm_select_unix_udp_async_bind_port;
    pl->udp.async_bind_mdns_ipv4 = &nm_select_unix_async_bind_mdns_ipv4;
    pl->udp.async_bind_mdns_ipv6 = &nm_select_unix_async_bind_mdns_ipv6;
    pl->udp.async_send_to    = &nm_select_unix_udp_async_send_to;
    pl->udp.async_recv_wait  = &nm_select_unix_udp_async_recv_wait;
    pl->udp.recv_from        = &nm_select_unix_udp_recv_from;
    pl->udp.get_local_ip     = &nm_unix_get_local_ip;
    pl->udp.get_local_port   = &nm_select_unix_udp_get_local_port;
    pl->udpData = ctx;

    sockets->socketsSentinel.next = &sockets->socketsSentinel;
    sockets->socketsSentinel.prev = &sockets->socketsSentinel;
    return NABTO_EC_OK;
}

void nm_select_unix_udp_deinit(struct nm_select_unix* ctx)
{
}

bool nm_select_unix_udp_has_sockets(struct nm_select_unix* ctx)
{
    return ctx->udpSockets.socketsSentinel.next == &ctx->udpSockets.socketsSentinel;
}


np_error_code nm_select_unix_udp_create(struct np_platform* pl, struct np_udp_socket** sock)
{
    struct np_udp_socket* s = calloc(1, sizeof(struct np_udp_socket));
    if (!s) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    *sock = s;
    s->posixSocket.sock = -1;

    struct nm_select_unix* selectCtx = pl->udpData;
    struct nm_select_unix_udp_sockets* sockets = &selectCtx->udpSockets;

    s->pl = selectCtx->pl;
    s->selectCtx = pl->udpData;
    s->destroyed = false;
    s->aborted = false;

    struct np_udp_socket* before = sockets->socketsSentinel.prev;
    struct np_udp_socket* after = &sockets->socketsSentinel;
    before->next = s;
    s->next = after;
    after->prev = s;
    s->prev = before;

    s->posixSocket.pl = pl;

    // add fd to select fd set.
    nm_select_unix_notify(selectCtx);

    return NABTO_EC_OK;
}

np_error_code nm_select_unix_udp_async_bind_port_ec(struct np_udp_socket* sock, uint16_t port)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec;

    ec = nm_posix_udp_create_socket_any(&sock->posixSocket);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = nm_posix_bind_port(&sock->posixSocket, port);
    if (ec != NABTO_EC_OK) {
        close(sock->posixSocket.sock);
    }

    return NABTO_EC_OK;
}

void nm_select_unix_udp_async_bind_port(struct np_udp_socket* sock, uint16_t port, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_udp_async_bind_port_ec(sock, port);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code nm_select_unix_async_bind_mdns_ipv4_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec;
    ec = nm_posix_udp_create_socket_ipv4(&sock->posixSocket);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    if (!nm_unix_init_mdns_ipv4_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_unix_mdns_update_ipv4_socket_registration(sock->posixSocket.sock);

    return NABTO_EC_OK;
}

void nm_select_unix_async_bind_mdns_ipv4(struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_async_bind_mdns_ipv4_ec(sock);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code nm_select_unix_async_bind_mdns_ipv6_ec(struct np_udp_socket* sock)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "bind called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = nm_posix_udp_create_socket_ipv6(&sock->posixSocket);
    if (ec) {
        return ec;
    }

    int no = 0;
    int status = setsockopt(sock->posixSocket.sock, IPPROTO_IPV6, IPV6_V6ONLY, (void* ) &no, sizeof(no));
    if (status < 0)
    {
        NABTO_LOG_ERROR(LOG, "Cannot set IPV6_V6ONLY");
    }

    if (!nm_unix_init_mdns_ipv6_socket(sock->posixSocket.sock)) {
        close(sock->posixSocket.sock);
        return NABTO_EC_UDP_SOCKET_CREATION_ERROR;
    }

    nm_unix_mdns_update_ipv6_socket_registration(sock->posixSocket.sock);

    return NABTO_EC_OK;
}

void nm_select_unix_async_bind_mdns_ipv6(struct np_udp_socket* sock, struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_async_bind_mdns_ipv6_ec(sock);
    np_completion_event_resolve(completionEvent, ec);
}

np_error_code nm_select_unix_udp_async_send_to_ec(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                                  uint8_t* buffer, uint16_t bufferSize)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "send to called on aborted socket");
        return NABTO_EC_ABORTED;
    }

    np_error_code ec = nm_posix_udp_send_to(&sock->posixSocket, ep, buffer, bufferSize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return NABTO_EC_OK;
}

void nm_select_unix_udp_async_send_to(struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                      uint8_t* buffer, uint16_t bufferSize,
                                      struct np_completion_event* completionEvent)
{
    np_error_code ec = nm_select_unix_udp_async_send_to_ec(sock, ep, buffer, bufferSize);
    np_completion_event_resolve(completionEvent, ec);
}


void nm_select_unix_udp_async_recv_wait(struct np_udp_socket* sock,
                                        struct np_completion_event* completionEvent)
{
    if (sock->aborted) {
        NABTO_LOG_ERROR(LOG, "recv from called on aborted socket");
        np_completion_event_resolve(completionEvent, NABTO_EC_ABORTED);
        return;
    }

    if (sock->recv.completionEvent != NULL) {
        NABTO_LOG_ERROR(LOG, "operation already in progress");
        np_completion_event_resolve(completionEvent, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }

    sock->recv.completionEvent = completionEvent;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

np_error_code nm_select_unix_udp_recv_from(struct np_udp_socket* sock, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize, size_t* readLength)
{
    return nm_posix_udp_recv_from(&sock->posixSocket, ep, buffer, bufferSize, readLength);
}

uint16_t nm_select_unix_udp_get_local_port(struct np_udp_socket* socket)
{
    if (socket->aborted) {
        NABTO_LOG_ERROR(LOG, "get local port called on aborted socket");
        return 0;
    }
    struct sockaddr_in6 addr;
    addr.sin6_port = 0;

    socklen_t length = sizeof(struct sockaddr_in6);
    getsockname(socket->posixSocket.sock, (struct sockaddr*)(&addr), &length);
    return htons(addr.sin6_port);
}

void nm_select_unix_udp_abort(struct np_udp_socket* sock)
{
    if (!sock->aborted) {
        sock->aborted = true;
    }

    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_ABORTED);
    }
}

void nm_select_unix_udp_destroy(struct np_udp_socket* sock)
{
    if (sock == NULL) {
        return;
    }
    sock->destroyed = true;
    nm_select_unix_notify(sock->selectCtx);
    return;
}

void nm_select_unix_udp_handle_event(struct np_udp_socket* sock)
{
    if (sock->recv.completionEvent != NULL) {
        struct np_completion_event* ev = sock->recv.completionEvent;
        sock->recv.completionEvent = NULL;
        np_completion_event_resolve(ev, NABTO_EC_OK);
    }
}

void nm_select_unix_udp_free_socket(struct np_udp_socket* sock)
{
    struct np_udp_socket* before = sock->prev;
    struct np_udp_socket* after = sock->next;
    before->next = after;
    after->prev = before;

    nm_select_unix_udp_abort(sock);
    shutdown(sock->posixSocket.sock, SHUT_RDWR);
    close(sock->posixSocket.sock);
    free(sock);
}

void nm_select_unix_udp_build_fd_sets(struct nm_select_unix* ctx, struct nm_select_unix_udp_sockets* sockets)
{
    struct np_udp_socket* iterator = sockets->socketsSentinel.next;

    while(iterator != &sockets->socketsSentinel)
    {
        if (iterator->recv.completionEvent && iterator->posixSocket.sock != -1) {
            FD_SET(iterator->posixSocket.sock, &ctx->readFds);
            ctx->maxReadFd = NP_MAX(ctx->maxReadFd, iterator->posixSocket.sock);
        }
        iterator = iterator->next;
    }
}

void nm_select_unix_udp_handle_select(struct nm_select_unix* ctx, int nfds)
{
    struct nm_select_unix_udp_sockets* sockets = &ctx->udpSockets;
    struct np_udp_socket* iterator = sockets->socketsSentinel.next;
    while(iterator != &sockets->socketsSentinel)
    {
        if (iterator->destroyed) {
            struct np_udp_socket* current = iterator;
            iterator = iterator->next;
            nm_select_unix_udp_free_socket(current);
            continue;
        }
        if (iterator->posixSocket.sock != -1 && FD_ISSET(iterator->posixSocket.sock, &ctx->readFds)) {
            nm_select_unix_udp_handle_event(iterator);
        }
        iterator = iterator->next;
    }
}
