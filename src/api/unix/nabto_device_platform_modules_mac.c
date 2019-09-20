#include <api/nabto_platform.h>

#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/udp/select_unix/nm_select_unix.h>

void nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_unix_udp_select_init(pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
}

int nabto_device_platform_inf_wait()
{
    return nm_select_unix_inf_wait();
}

void nabto_device_platform_read(int nfds)
{
    nm_select_unix_read(nfds);
}

void nabto_device_platform_close(struct np_platform* pl)
{
    nm_select_unix_close(pl);
}

void nabto_device_platform_signal(struct np_platform* pl)
{
    nm_select_unix_break_wait(pl);
}
