#ifndef __PCKT_DECAP_H
#define __PCKT_DECAP_H

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "balancer_helpers.h"
#include "balancer_maps.h"
#include "control_data_maps.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "encap_helpers.h"
#include "pckt_parsing.h"

__attribute__((__always_inline__))
static inline int check_decap_dst(void *map, struct packet_description *pckt,
                                  bool is_ipv6, bool *pass, void **dst_info) {
    struct address dst_addr = {};
    struct lb_stats *data_stats;

    if (is_ipv6) {
      memcpy(dst_addr.addrv6, pckt->flow.dstv6, 16);
    } else {
      dst_addr.addr = pckt->flow.dst;
    }
    *dst_info = bpf_map_lookup_elem(map, &dst_addr);

    if (*dst_info) {
      *pass = false;
      __u32 stats_key = MAX_VIPS * 2 + REMOTE_ENCAP_CNTRS;
      data_stats = bpf_map_lookup_elem(&stats, &stats_key);
      if (!data_stats) {
        return XDP_DROP;
      }
      data_stats->v1 += 1;
    }
    return FURTHER_PROCESSING;
}

#ifdef INLINE_DECAP

__attribute__((__always_inline__))
static inline int process_encaped_ipip_pckt(void **data, void **data_end,
                                            struct xdp_md *xdp, bool is_ipv6,
                                            __u8 protocol) {
  int action;

  if (protocol == IPPROTO_IPIP) {
    if (is_ipv6) {
      int offset = sizeof(struct ipv6hdr) + sizeof(struct eth_hdr);
      if ((*data + offset) > *data_end) {
        return XDP_DROP;
      }
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
    } else {
      int offset = sizeof(struct iphdr) + sizeof(struct eth_hdr);
      if ((*data + offset) > *data_end) {
        return XDP_DROP;
      }
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
      }
    }
  } else /*if (protocol == IPPROTO_IPV6)*/ {
    int offset = sizeof(struct ipv6hdr) + sizeof(struct eth_hdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    action = decrement_ttl(*data, *data_end, offset, true);
    if (!decap_v6(xdp, data, data_end, false)) {
      return XDP_DROP;
    }
  }
  return action;
}

__attribute__((__always_inline__)) 
static inline bool gue_decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;

  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(
          xdp, (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__)) 
static inline bool gue_decap_v6(struct xdp_md* xdp, void** data, void** data_end, bool inner_v4) {
  struct eth_hdr* new_eth;
  struct eth_hdr* old_eth;

  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  if (inner_v4) {
    new_eth->eth_proto = BE_ETH_P_IP;
  } else {
    new_eth->eth_proto = BE_ETH_P_IPV6;
  }
  if (bpf_xdp_adjust_head(
          xdp, (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr)))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__))
static inline int process_encaped_gue_pckt(void **data, void **data_end,
                                           struct xdp_md *xdp, bool is_ipv6) {
  int offset = 0;
  int action;

  if (is_ipv6) {
    __u8 v6 = 0;

    offset = sizeof(struct ipv6hdr) + sizeof(struct eth_hdr) +
      sizeof(struct udphdr);
    // 1 byte for gue v1 marker to figure out what is internal protocol
    if ((*data + offset + 1) > *data_end) {
      return XDP_DROP;
    }
    v6 = ((__u8*)(*data))[offset];
    v6 &= GUEV1_IPV6MASK;
    if (v6) {
      // inner packet is ipv6 as well
      action = decrement_ttl(*data, *data_end, offset, true);
      if (!gue_decap_v6(xdp, data, data_end, false)) {
        return XDP_DROP;
      }
    } else {
      // inner packet is ipv4
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!gue_decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
    }
  } else {
    offset = sizeof(struct iphdr) + sizeof(struct eth_hdr) +
      sizeof(struct udphdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    action = decrement_ttl(*data, *data_end, offset, false);
    if (!gue_decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
    }
  }
  return action;
}

#endif /*INLINE_DECAP*/

#endif
