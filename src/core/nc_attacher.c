
#include "nc_attacher.h"

#include <core/nc_packet.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

struct attach_context {
    struct np_platform* pl;
    nc_attached_callback cb;
    void* cbData;
    np_connection conn;
    np_connection anConn;
    struct np_udp_endpoint adEp;
    np_crypto_context* adDtls;
    struct np_udp_endpoint anEp;
    np_crypto_context* anDtls;
    np_communication_buffer* buffer;
    char dns[64]; // TODO: Hardcoded DNS length limit
    uint8_t token[1024]; // TODO: How to store token ?
    uint16_t tokenLen;
};

struct attach_context ctx;
void dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);

void dtls_an_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "dtls_an_send_cb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach device hello");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

void dtls_an_recv_cb(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    NABTO_LOG_TRACE(LOG, "dtls_an_recv_cb invoked");
    NABTO_LOG_BUF(LOG, ctx.pl->buf.start(buf), bufferSize);
    ctx.cb(ec, ctx.cbData);
}

void dtls_an_conn_cb(const np_error_code ec, np_crypto_context* crypCtx, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.anDtls = crypCtx;
    uint8_t* ptr = ctx.pl->buf.start(ctx.buffer);
    uint8_t* start = ptr;
    uint16_t len;
    ptr = init_packet_header(ptr, ATTACH);
    *(start+1) = ATTACH_DEVICE_HELLO;
    // TODO: only insert extensions which are supported
    insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV4_EP, NULL, 0);
    ptr = insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV6_EP, NULL, 0);
    ptr = writeUint16LengthData(ptr, ctx.token, ctx.tokenLen);
    uint16_write_forward(start + 2, ptr-start-NABTO_PACKET_HEADER_SIZE);  
    len = uint16_read(start + 2);
    NABTO_LOG_BUF(LOG, start, len+NABTO_PACKET_HEADER_SIZE);
    ctx.pl->cryp.async_send_to(ctx.pl, ctx.anDtls, start, len+NABTO_PACKET_HEADER_SIZE, &dtls_an_send_cb, &ctx);
    ctx.pl->cryp.async_recv_from(ctx.pl, ctx.anDtls, &dtls_an_recv_cb, &ctx);
}

void an_conn_created_cb(const np_error_code ec, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->cryp.async_connect(ctx.pl, &ctx.anConn, &dtls_an_conn_cb, &ctx);
}

void an_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    NABTO_LOG_INFO(LOG, "Attach node address resolved with status: %u", ec);
    if (ec != NABTO_EC_OK || recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach node host");
        ctx.cb(ec, ctx.cbData);
        return;
    }
    memcpy(&ctx.anEp.ip, &rec[0], sizeof(struct np_ip_address));
    ctx.pl->conn.async_create(ctx.pl, &ctx.anConn, &ctx.anEp, &an_conn_created_cb, &ctx);
}
void dtls_closed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "dtls connection closed callback");
}

void dtls_ad_recv_cb(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    uint8_t* start = ctx.pl->buf.start(buf);
    uint8_t* ptr = start;
    uint8_t* dns;
    uint16_t dnsLen;
    uint16_t extensionLen = uint16_read(start+4);
    uint16_t packetLen = uint16_read(start+2);
    uint8_t* token = start + NABTO_PACKET_HEADER_SIZE + extensionLen + 2;
    uint16_t tokenLen = uint16_read(start + NABTO_PACKET_HEADER_SIZE + extensionLen);

    if (bufferSize < NABTO_PACKET_HEADER_SIZE || *start != ATTACH_DISPATCH) {
        NABTO_LOG_ERROR(LOG, "Received malformed attach response packet");
        ctx.cb(NABTO_EC_FAILED, ctx.cbData);
        return;
    }
    NABTO_LOG_TRACE(LOG, "dtlsRecvCb invoked with response:");
    NABTO_LOG_BUF(LOG, start, bufferSize);
    if (*(start+1) == ATTACH_DISPATCH_RESPONSE) {
        NABTO_LOG_TRACE(LOG, "ATTACH_DISPATCH_RESPONSE");
        if (extensionLen < 4 || packetLen <= extensionLen) {
            NABTO_LOG_ERROR(LOG, "Received ATTACH_DISPATCH_RESPONSE either missing DNS extension or token");
            ctx.cb(NABTO_EC_FAILED, ctx.cbData);
            return;
        }
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        while (true) {
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == UDP_DNS_EP) {
                ctx.anEp.port = uint16_read(ptr+4);
                dns = ptr+8;
                dnsLen = uint16_read(ptr+6);
                NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, dns: %s", ctx.anEp.port, (char*)dns);
                break;
            }
            ptr = ptr + extLen + 4;
            if (ptr - start >= bufferSize) {
                NABTO_LOG_ERROR(LOG, "Failed to find DNS extension in ATTACH_DISPATCH_RESPONSE");
                ctx.cb(NABTO_EC_FAILED, ctx.cbData);
                return;
            }
        }
        memcpy(ctx.dns, dns, dnsLen);
        memcpy(ctx.token, token, tokenLen);
        ctx.tokenLen = tokenLen;
        ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &an_dns_cb, &ctx);
        ctx.pl->cryp.async_close(ctx.pl, ctx.adDtls, &dtls_closed_cb, &ctx);
        
    } else if (*(start+1) == ATTACH_DISPATCH_REDIRECT) {
        NABTO_LOG_TRACE(LOG, "ATTACH_DISPATCH_REDIRECT");
        if (extensionLen < 4) {
            NABTO_LOG_ERROR(LOG, "Received ATTACH_DISPATCH_REDIRECT missing DNS extension");
            ctx.cb(NABTO_EC_FAILED, ctx.cbData);
            return;
        }
        ptr = ptr + NABTO_PACKET_HEADER_SIZE; // skip header;
        while (true) {
            uint16_t extType = uint16_read(ptr);
            uint16_t extLen = uint16_read(ptr+2);
            if (extType == UDP_DNS_EP) {
                ctx.adEp.port = uint16_read(ptr+4);
                dns = ptr+8;
                dnsLen = uint16_read(ptr+6);
                NABTO_LOG_TRACE(LOG, "Found DNS extension with port: %u, dns: %s", ctx.adEp.port, (char*)dns);
                break;
            }
            ptr = ptr + extLen + 4;
            if (ptr - start >= bufferSize) {
                NABTO_LOG_ERROR(LOG, "Failed to find DNS extension in ATTACH_DISPATCH_RESPONSE");
                ctx.cb(NABTO_EC_FAILED, ctx.cbData);
                return;
            }
        }
        memcpy(ctx.dns, dns, dnsLen);
        ctx.pl->dns.async_resolve(ctx.pl, ctx.dns, &dns_cb, &ctx);
        
        return;

    } else {
        NABTO_LOG_ERROR(LOG, "Received ATTACH_DISPATCH packet with invalid content type");
        ctx.cb(NABTO_EC_FAILED, ctx.cbData);
        return;
    }
        
}

void dtls_ad_send_cb(const np_error_code ec, void* data) {
    NABTO_LOG_TRACE(LOG, "dtlsSendCb invoked");
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_TRACE(LOG, "Failed to send attach dispatcher request");
        ctx.cb(ec, ctx.cbData);
        return;
    }
}

void dtls_conn_cb(const np_error_code ec, np_crypto_context* crypCtx, void* data)
{
    uint8_t* ptr;
    uint8_t* start;
    uint16_t len;
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.adDtls = crypCtx;
    ctx.buffer = ctx.pl->buf.allocate();
    ptr = ctx.pl->buf.start(ctx.buffer);
    start = ptr;
    ptr = init_packet_header(ptr, ATTACH_DISPATCH);
    *(start+1) = ATTACH_DISPATCH_REQUEST;
    // TODO: only insert extensions which is supported
    insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV4_EP, NULL, 0);
    insert_packet_extension(ctx.pl, ctx.buffer, UDP_IPV6_EP, NULL, 0);
    len = uint16_read(start + 2);
    NABTO_LOG_BUF(LOG, start, len+NABTO_PACKET_HEADER_SIZE);
    ctx.pl->cryp.async_send_to(ctx.pl, ctx.adDtls, start, len+NABTO_PACKET_HEADER_SIZE, &dtls_ad_send_cb, &ctx);
    ctx.pl->cryp.async_recv_from(ctx.pl, ctx.adDtls, &dtls_ad_recv_cb, &ctx);
}

void conn_created_cb(const np_error_code ec, void* data)
{
    if( ec != NABTO_EC_OK ) {
        ctx.cb(ec, ctx.cbData);
        return;
    }
    ctx.pl->cryp.async_connect(ctx.pl, &ctx.conn, &dtls_conn_cb, &ctx);
}

void dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    if (ec != NABTO_EC_OK || recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach dispatcher host");
        ctx.cb(ec, ctx.cbData);
        return;
    }
    // TODO: get attach_dispatcher_port from somewhere
    ctx.adEp.port = ATTACH_DISPATCHER_PORT;
    // TODO: should there be a preference towards IPv4 or IPv6 instead of just taking rec[0]?
    memcpy(&ctx.adEp.ip, &rec[0], sizeof(struct np_ip_address));
    ctx.pl->conn.async_create(ctx.pl, &ctx.conn, &ctx.adEp, &conn_created_cb, &ctx);
}

np_error_code async_attach(struct np_platform* pl, nc_attached_callback cb, void* data)
{
    ctx.pl = pl;
    ctx.cb = cb;
    ctx.cbData = data;
    memcpy(ctx.dns, "localhost", 10);
    // TODO: resolve a attach dispatcher host from somewhere
    return pl->dns.async_resolve(pl, ctx.dns, &dns_cb, &ctx);
}
