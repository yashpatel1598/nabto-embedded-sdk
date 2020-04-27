#ifndef _NP_TCP_H_
#define _NP_TCP_H_

#include <platform/np_ip_address.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct np_completion_event;

typedef struct np_tcp_socket np_tcp_socket;

struct np_tcp_module {
    /**
     * Create a tcp socket.
     *
     * @param pl  The platform.
     * @param sock  The resulting socket resource.
     */
    np_error_code (*create)(struct np_platform* pl, np_tcp_socket** sock);

    /**
     * Destroy a socket. All outstanding completion events will be
     * resolved.
     *
     * @param sock  The socket resource.
     */
    void (*destroy)(np_tcp_socket* sock);

    /**
     * Connect a socket to the given addresa and port.
     *
     * @param sock  The socket resource.
     * @param address  The address to connect to.
     * @param port  The port to connect to.
     * @param completionEvent  The completion event.
     */
    void (*async_connect)(np_tcp_socket* sock, struct np_ip_address* address, uint16_t port, struct np_completion_event* completionEvent);

    /**
     * Write data to the tcp socket.
     *
     * @param sock  The socket resource.
     * @param data  The data to write.
     * @param dataLength  The length of the data to write.
     * @param completionEvent  The event to call when data has been writtem or the write failed.
     */
    void (*async_write)(np_tcp_socket* sock, const void* data, size_t dataLength, struct np_completion_event* completionEvent);
    /**
     * Read data from a socket.
     *
     * @param sock  The socket resource.
     * @param buffer  The buffer to write data to.
     * @param bufferLength  The length of the buffer.
     * @param readLength  The length of received data.
     * @param completionEvent  The completion event to resolve when data has been read.
     */
    void (*async_read)(np_tcp_socket* sock, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* completionEvent);

    /**
     * Shutdown further write to the socket.
     *
     * @param sock  The socket resource to shutdown.
     */
    np_error_code (*shutdown)(np_tcp_socket* sock);

    /**
     * Abort outstanding async operations on the socket, no further
     * reads or writes are possible.
     *
     * @param sock  The socket resource.
     */
    np_error_code (*abort)(np_tcp_socket* sock);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
