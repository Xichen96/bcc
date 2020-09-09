#ifndef __BALANCER_EVENT_H
#define __BALANCER_EVENT_H

#ifdef ENABLE_EVENT

#include "bpf_event.h"
#include "balancer_consts.h"
#include "balancer_structs.h"

DECLARE_EVENT(lru_maps_event);

__attribute__((__always_inline__))
static inline int new_conn_event(void *ctx, struct packet_description *pckt)
{
  if (pckt->flags & F_CTL_CONN_EVENT) {
    return lru_maps_event_report(ctx, &pckt->flow, sizeof(struct flow_key) + 1/*ipv6*/);
  }
  return 0;
}

#else /*!ENABLE_EVENT*/

__attribute__((__always_inline__))
static inline int new_conn_event(void *ctx, struct packet_description *pckt)
{
  return 0;
}

#endif /*ENABLE_EVENT*/

#endif /*__BALANCER_EVENT_H*/
