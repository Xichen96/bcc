#ifndef __BALANCER_STATS
#define __BALANCER_STATS

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "bpf.h"
#include "bpf_helpers.h"

#define CSTAT_INC(cstat, class, counter) do { \
  (cstat)->class->class.counter++; \
} while (0)

__attribute__((__always_inline__))
static inline int core_stats_init(struct core_stats_set *cstat)
{
  __u32 key = KATRAN_CORE_STAT_TOTAL;
  struct ctl_value *cval;
  if (!(cstat->total = bpf_map_lookup_elem(&core_stats, &key))) {
    goto drop;
  }
  key = KATRAN_CORE_STAT_L3;
  if (!(cstat->l3 = bpf_map_lookup_elem(&core_stats, &key))) {
    goto map_err;
  }
  key = KATRAN_CORE_STAT_L4;
  if (!(cstat->l4 = bpf_map_lookup_elem(&core_stats, &key))) {
    goto map_err;
  }
  key = CTL_MAP_POS_PKT_FLAGS;
  if (!(cval = bpf_map_lookup_elem(&ctl_array, &key))) {
    cstat->flags = 0;
  } else {
    cstat->flags = cval->value;
  }
  return FURTHER_PROCESSING;
map_err:
  CSTAT_INC(cstat, total, map_err);
  CSTAT_INC(cstat, total, drop);
drop:
  return XDP_DROP;
}

__attribute__((__always_inline__))
static inline void core_stats_calc(struct core_stats_set *cstat, 
        bool is_ipv6, __u8 protocol, int action) {
  if (action == XDP_PASS || action == XDP_TX) {
    if (is_ipv6) {
      CSTAT_INC(cstat, l3, ipv6);
    } else {
      CSTAT_INC(cstat, l3, ipv4);
    }
    switch (protocol) {
      case IPPROTO_TCP:
        CSTAT_INC(cstat, l4, tcp);
        break;
      case IPPROTO_UDP:
        CSTAT_INC(cstat, l4, udp);
        break;
      case IPPROTO_ICMP:
        CSTAT_INC(cstat, l4, icmp);
        break;
      case IPPROTO_ICMPV6:
        CSTAT_INC(cstat, l4, icmp6);
        break;
      default:
        CSTAT_INC(cstat, l4, other);
        break;
    }
    if (action == XDP_PASS) {
      CSTAT_INC(cstat, total, input);
    } else {
      CSTAT_INC(cstat, total, forward);
    }
  } else if (action == XDP_DROP) {
    CSTAT_INC(cstat, total, drop);
  }
}

#endif /*__BALANCER_STATS*/
