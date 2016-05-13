#ifndef TC_PACKETS_MODULE_INCLUDED
#define TC_PACKETS_MODULE_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>

int tc_packets_init(tc_event_loop_t *event_loop);
#if (TC_OFFLINE)
int tc_offline_init(tc_event_loop_t *event_loop, char *pcap_file);
#endif
int proc_api_request(tc_event_t *rev);

#endif /* TC_PACKETS_MODULE_INCLUDED */
