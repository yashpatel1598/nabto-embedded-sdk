#include "nm_select_win.h"

#include <modules/communication_buffer/nm_unix_communication_buffer.h>

#include <platform/np_platform.h>
#include <platform/np_timestamp.h>
#include <platform/np_udp.h>
#include <platform/np_logging.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>

struct np_platform pl;
np_udp_socket* sock;
np_udp_socket* sock2;
np_udp_socket* sock3;
struct np_udp_send_context sendCtx1;
struct np_udp_send_context sendCtx2;
uint32_t counter = 0;
void sockSendCtx1(np_udp_packet_sent_callback cb);
void sock3Created(const np_error_code ec, np_udp_socket* socket, void* data);

void sendCb1(const np_error_code ec, void* data)
{
    NABTO_LOG_ERROR(0, "    sendCb1");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "sock sendCb1 failed");
        return;
    }
    if (counter < 10) {
        sockSendCtx1(&sendCb1);
    }
//    sockSendCtx1(&sendCb1);
//    sockSendCtx1(NULL);
//    sockSendCtx1(NULL);
}
#define IPV4
void sockSendCtx1(np_udp_packet_sent_callback cb)
{
    sendCtx1.sock = sock;
    sendCtx1.ep.port = 4242;

#ifdef IPV4
    sendCtx1.ep.ip.type = NABTO_IPV4;
    sendCtx1.ep.ip.v4.addr[0] = 127;
    sendCtx1.ep.ip.v4.addr[1] = 0;
    sendCtx1.ep.ip.v4.addr[2] = 0;
    sendCtx1.ep.ip.v4.addr[3] = 1;
#else
    sendCtx1.ep.ip.type = NABTO_IPV6;
    memset(sendCtx1.ep.ip.v6.addr, 0, 16);
    sendCtx1.ep.ip.v6.addr[15] = 1;
#endif
    memcpy(pl.buf.start(sendCtx1.buffer), &counter, 4);
    sendCtx1.bufferSize = 4;
    sendCtx1.cb = cb;
    counter++;
    nm_select_win_async_send_to(&sendCtx1);
}

void sock2Recv(const np_error_code ec, struct np_udp_endpoint ep,
               np_communication_buffer* buffer, uint16_t bufferSize,
               void* data)
{
    NABTO_LOG_ERROR(0, "  recv from sock2: %u", *((uint32_t*)pl.buf.start(buffer)));
//    NABTO_LOG_BUF(0, pl.buf.start(buffer), bufferSize);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "sock2 recv failed");
        return;
    }
    nm_select_win_async_recv_from(sock2, &sock2Recv, NULL);
}

void sock2Created(const np_error_code ec, np_udp_socket* socket, void* data)
{
    NABTO_LOG_INFO(0, "socket2 created");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "sock2 creation failed");
        return;
    }
    sock2 = socket;
    nm_select_win_async_recv_from(sock2, &sock2Recv, NULL);
    sockSendCtx1(&sendCb1);
}

void sockCreated(const np_error_code ec, np_udp_socket* socket, void* data)
{
    NABTO_LOG_INFO(0, "socket created");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "sock creation failed");
        return;
    }
    sock = socket;
    nm_select_win_async_bind_port(4242, &sock2Created, NULL);
}

void sock3DestroyedCb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(0, "socket3 destroyed");
    if (counter >= 10) {
        return;
    }
    nm_select_win_async_create(&sock3Created, NULL);
}

void sock3Created(const np_error_code ec, np_udp_socket* socket, void* data)
{
    NABTO_LOG_INFO(0, "socket3 created");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(0, "sock3 creation failed");
        return;
    }
    sock3 = socket;
    nm_select_win_async_destroy(sock3, &sock3DestroyedCb, NULL);
}

int main()
{
    int nfds;
    struct np_ip_address *localIps = malloc(5*sizeof(struct np_ip_address));
    np_platform_init(&pl);
    np_log_init();
    np_communication_buffer_init(&pl);
    np_ts_init(&pl);
    np_udp_init(&pl);
    NABTO_LOG_INFO(0, "main");

    sendCtx1.buffer = pl.buf.allocate();
    sendCtx2.buffer = pl.buf.allocate();
    NABTO_LOG_ERROR(0, "buf1 start: %u", pl.buf.start(sendCtx1.buffer));

    nm_select_win_async_create(&sockCreated, NULL);
    nm_select_win_async_create(&sock3Created, NULL);

    size_t nIps = nm_select_win_get_local_ip(localIps, 5);
    NABTO_LOG_INFO(0, "Found %u local IP's", nIps);
    for (int i = 0; i < nIps; i++) {
        if (localIps[i].type == NABTO_IPV4) {
            NABTO_LOG_INFO(0, "%u.%u.%u.%u", localIps[i].v4.addr[0], localIps[i].v4.addr[1], localIps[i].v4.addr[2], localIps[i].v4.addr[3]);
        } else {
            NABTO_LOG_BUF(0, localIps[i].v6.addr, 16);
        }
    }

    while(true) {
        np_event_queue_execute_all(&pl);
        if (!np_event_queue_is_event_queue_empty(&pl)) {
            NABTO_LOG_ERROR(0, "Event queue not empty after emptying");
        }
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            if (ms == 0) {
                NABTO_LOG_ERROR(0, "ms was 0 ");
                ms = 1;
            }
            nfds = nm_select_win_timed_wait(ms);
        } else {
            nfds = nm_select_win_inf_wait();
        }
        nm_select_win_read(nfds);
    }
}
