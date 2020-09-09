/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PCKT_ENCAP_H
#define __PCKT_ENCAP_H

/*
 * This file contains routines which are responsible for encapsulation of the
 * packets, which will be sent out from load balancer. right now we are
 * using IPIP as our encap of choice
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <string.h>

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "balancer_helpers.h"
#include "control_data_maps.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "encap_helpers.h"
#include "pckt_parsing.h"
#include "balancer_fib.h"

__attribute__((__always_inline__))
static inline bool encap_v6(struct xdp_md *xdp, struct xlb_fib_args *args,
                            struct packet_description *pckt,
                            struct real_definition *dst) {
  void *data;
  void *data_end;
  struct ipv6hdr *ip6h;
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  __u32 ip_suffix;
  // ip(6)ip6 encap
  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  ip6h = data + sizeof(struct eth_hdr);
  old_eth = data + sizeof(struct ipv6hdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      ip6h + 1 > data_end) {
    return false;
  }

  args->smac = new_eth->eth_source;
  args->dmac = new_eth->eth_dest;
  args->pkt_dmac = old_eth->eth_dest;
  if (fib_store_mac(xdp, args, true)) {
    return false;
  }

  new_eth->eth_proto = BE_ETH_P_IPV6;
  ip6h->version = 6;
  // If needed, this could be changed to map from src pkt
  // (instead of 0 currently), or to anything else we may want.
  ip6h->priority = 0;
  memset(ip6h->flow_lbl, 0 , sizeof(ip6h->flow_lbl));

  if (pckt->is_ipv6) {
    ip6h->nexthdr = IPPROTO_IPV6;
    ip_suffix = pckt->flow.srcv6[3] ^ pckt->flow.port16[0];
    ip6h->payload_len = bpf_htons(pckt->pkt_bytes + sizeof(struct ipv6hdr));
  } else {
    ip6h->nexthdr = IPPROTO_IPIP;
    ip_suffix = pckt->flow.src ^ pckt->flow.port16[0];
    ip6h->payload_len = bpf_htons(pckt->pkt_bytes);
  }
  ip6h->hop_limit = DEFAULT_TTL;

  ip6h->saddr.s6_addr32[0] = IPIP_V6_PREFIX1;
  ip6h->saddr.s6_addr32[1] = IPIP_V6_PREFIX2;
  ip6h->saddr.s6_addr32[2] = IPIP_V6_PREFIX3;
  ip6h->saddr.s6_addr32[3] = ip_suffix;
  memcpy(ip6h->daddr.s6_addr32, dst->dstv6, 16);
  return true;
}

__attribute__((__always_inline__))
static inline void gen_v4_src(struct packet_description *pckt, struct iphdr *iph) {
  __u32 prefix = 0, mask = 0, 
	pos = CTL_MAP_POS_IPIP_PREFIX, 
	ip_suffix = bpf_htons(pckt->flow.port16[0]);
  struct ctl_value *prefix_mask;

  ip_suffix <<= 16;
  ip_suffix ^= pckt->flow.src;

  if ((prefix_mask = bpf_map_lookup_elem(&ctl_array, &pos))) {
      prefix = (__u32)(prefix_mask->value >> 32);
      mask = (__u32)(prefix_mask->value);
  }
  if (prefix || mask)
    iph->saddr = ((mask & ip_suffix) | prefix);
  else 
    iph->saddr = ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX);
}

__attribute__((__always_inline__))
static inline bool encap_v4(struct xdp_md *xdp, struct xlb_fib_args *args,
                            struct packet_description *pckt,
                            struct real_definition *dst) {

  void *data;
  void *data_end;
  struct iphdr *iph;
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  __u64 csum = 0;
  // ipip encap
  if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  iph = data + sizeof(struct eth_hdr);
  old_eth = data + sizeof(struct iphdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      iph + 1 > data_end) {
    return false;
  }

  args->smac = new_eth->eth_source;
  args->dmac = new_eth->eth_dest;
  args->pkt_dmac = old_eth->eth_dest;
  if (fib_store_mac(xdp, args, false)) {
    return false;
  }

  new_eth->eth_proto = BE_ETH_P_IP;

  iph->version = 4;
  iph->ihl = 5;
  iph->frag_off = 0;
  iph->protocol = IPPROTO_IPIP;
  iph->check = 0;
  // as w/ v6 we could configure tos to something else
  iph->tos = 0;
  iph->tot_len = bpf_htons(pckt->pkt_bytes + sizeof(struct iphdr));
  iph->daddr = dst->dst;
  gen_v4_src(pckt, iph);
  iph->ttl = DEFAULT_TTL;

  ipv4_csum_inline(iph, &csum);
  iph->check = csum;

  return true;
}

// before calling decap helper apropriate checks for data_end - data must be
// done. otherwise verifier wont like it
__attribute__((__always_inline__))
static inline bool decap_v6(
    struct xdp_md *xdp, void **data, void **data_end, bool inner_v4) {
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  if (inner_v4) {
    new_eth->eth_proto = BE_ETH_P_IP;
  } else {
    new_eth->eth_proto = BE_ETH_P_IPV6;
  }
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct ipv6hdr))) {
    return false;
  }
  *data = (void *)(long)xdp->data;
  *data_end = (void *)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__))
static inline bool decap_v4(
    struct xdp_md *xdp, void **data, void **data_end) {
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr);
  memcpy(new_eth->eth_source, old_eth->eth_source, 6);
  memcpy(new_eth->eth_dest, old_eth->eth_dest, 6);
  new_eth->eth_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
    return false;
  }
  *data = (void *)(long)xdp->data;
  *data_end = (void *)(long)xdp->data_end;
  return true;
}

#ifdef GUE_ENCAP

__attribute__((__always_inline__))
static inline bool gue_encap_v4(struct xdp_md *xdp, struct xlb_fib_args *args,
                            struct packet_description *pckt,
                            struct real_definition *dst) {
  void *data;
  void *data_end;
  struct iphdr *iph;
  struct udphdr *udph;
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;

  __u16 sport = bpf_htons(pckt->flow.port16[0]);

  sport ^= ((pckt->flow.src >> 16) & 0xFFFF);
  __u64 csum = 0;

  if (bpf_xdp_adjust_head(
      xdp, 0 - ((int)sizeof(struct iphdr) + (int)sizeof(struct udphdr)))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  iph = data + sizeof(struct eth_hdr);
  udph = (void *)iph + sizeof(struct iphdr);
  old_eth = data + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      iph + 1 > data_end ||
      udph + 1 > data_end) {
    return false;
  }

  args->smac = new_eth->eth_source;
  args->dmac = new_eth->eth_dest;
  args->pkt_dmac = old_eth->eth_dest;
  if (fib_store_mac(xdp, args, false)) {
    return false;
  }

  new_eth->eth_proto = BE_ETH_P_IP;

  create_udp_hdr(
    udph,
    sport,
    GUE_DPORT,
    pckt->pkt_bytes + sizeof(struct udphdr),
    GUE_CSUM);

  create_v4_hdr(
    iph,
    0,
    pckt->flow.src,
    dst->dst,
    pckt->pkt_bytes + sizeof(struct udphdr),
    IPPROTO_UDP);

  return true;
}

__attribute__((__always_inline__))
static inline bool gue_encap_v6(struct xdp_md *xdp, struct xlb_fib_args *args,
                            struct packet_description *pckt,
                            struct real_definition *dst) {
  void *data;
  void *data_end;
  struct ipv6hdr *ip6h;
  struct eth_hdr *new_eth;
  struct eth_hdr *old_eth;
  struct udphdr *udph;
  __u16 payload_len;
  __u16 sport;

  if (bpf_xdp_adjust_head(
    xdp, 0 - ((int)sizeof(struct ipv6hdr) + (int)sizeof(struct udphdr)))) {
    return false;
  }
  data = (void *)(long)xdp->data;
  data_end = (void *)(long)xdp->data_end;
  new_eth = data;
  ip6h = data + sizeof(struct eth_hdr);
  udph = (void *)ip6h + sizeof(struct ipv6hdr);
  old_eth = data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  if (new_eth + 1 > data_end ||
      old_eth + 1 > data_end ||
      ip6h + 1 > data_end ||
      udph + 1 > data_end) {
    return false;
  }

  args->smac = new_eth->eth_source;
  args->dmac = new_eth->eth_dest;
  args->pkt_dmac = old_eth->eth_dest;
  if (fib_store_mac(xdp, args, true)) {
    return false;
  }

  new_eth->eth_proto = BE_ETH_P_IPV6;

  if (pckt->is_ipv6) {
    sport = (pckt->flow.srcv6[3] & 0xFFFF) ^ pckt->flow.port16[0];
    pckt->pkt_bytes += (sizeof(struct ipv6hdr) + sizeof(struct udphdr));
  } else {
    sport = ((pckt->flow.src >> 16) & 0xFFFF) ^ pckt->flow.port16[0];
    pckt->pkt_bytes += sizeof(struct udphdr);
  }

  create_udp_hdr(
    udph,
    sport,
    GUE_DPORT,
    pckt->pkt_bytes,
    GUE_CSUM);

  create_v6_hdr(ip6h, 0, pckt->flow.srcv6, dst->dstv6, pckt->pkt_bytes, IPPROTO_UDP);

  return true;
}
#endif // of GUE_ENCAP

#endif // of __PCKT_ENCAP_H
