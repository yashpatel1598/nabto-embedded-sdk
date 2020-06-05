#include "nm_libevent_timestamp.h"
#include "nm_libevent.h"

#include <platform/np_platform.h>
#include <platform/interfaces/np_timestamp.h>

#include <event2/event.h>

#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif

#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif




static uint32_t ts_now_ms(struct np_timestamp* obj);

static const struct np_timestamp_functions vtable = {
    .now_ms = &ts_now_ms
};


const struct np_timestamp_functions* nm_libevent_timestamp_functions()
{
    return &vtable;
}

uint32_t ts_now_ms(struct np_timestamp* obj)
{
    struct nm_libevent_context* ctx = obj->data;
    struct event_base* eventBase = ctx->eventBase;
    struct timeval tv;
    event_base_gettimeofday_cached(eventBase, &tv);

    return ((((uint64_t)tv.tv_sec)*1000) + (((uint64_t)tv.tv_usec)/1000));
}
