/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "balancer_helpers.h"
#include "balancer_maps.h"
#include "balancer_stats.h"
#include "balancer_acl.h"
#include "balancer_event.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "jhash.h"
#include "pckt_encap.h"
#include "pckt_decap.h"
#include "pckt_parsing.h"
#include "handle_icmp.h"

__attribute__((__always_inline__))
static inline __u32 get_packet_hash(struct packet_description *pckt,
                                    bool hash_16bytes) {
  if (hash_16bytes) {
    return jhash_2words(jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6),
                        pckt->flow.ports, INIT_JHASH_SEED);
  } else {
    return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
  }
}

__attribute__((__always_inline__))
static inline void conn_cnt_update(int active, struct core_stats_set *cstat) {
  struct lb_stats *conn_stats = cstat->conn;
  struct lb_stats *vip_conn_stats = cstat->vip_conn;

  switch (active) {
    case 1: /* active connection */
      conn_stats->v1++;
      vip_conn_stats->v1++;
      break;
    case 0: /* inactive connection */
      conn_stats->v1--;
      vip_conn_stats->v1--;
      break;
    default: /* new connection */
      conn_stats->v2++;
      vip_conn_stats->v2++;
      break;
  }
}

__attribute__((__always_inline__))
static inline void tcp_status_change(struct real_pos_lru * dst, struct core_stats_set *cstat,
                                     struct packet_description *pckt) {
  if (pckt->flags & F_TCP_NEW) {
    dst->status |= F_TCP_NEW;
  } else if (pckt->flags & F_TCP_ESTAB && !(dst->status & F_TCP_ESTAB)) {
    conn_cnt_update(1, cstat);
    dst->status |= F_TCP_ESTAB;
  } else if (pckt->flags & F_TCP_CLOSE && !(dst->status & F_TCP_CLOSE)) {
    conn_cnt_update(0, cstat);
    dst->status |= F_TCP_CLOSE;
  }
}

__attribute__((__always_inline__))
static inline bool is_under_flood(__u64 *cur_time) {
  __u32 conn_rate_key = MAX_VIPS * 2 + NEW_CONN_RATE_CNTR;
  struct lb_stats *conn_rate_stats = bpf_map_lookup_elem(
    &stats, &conn_rate_key);
  if (!conn_rate_stats) {
    return true;
  }
  *cur_time = bpf_ktime_get_ns();
  // we are going to check that new connections rate is less than predefined
  // value; conn_rate_stats.v1 contains number of new connections for the last
  // second, v2 - when last time quanta started.
  if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
    // new time quanta; reseting counters
    conn_rate_stats->v1 = 1;
    conn_rate_stats->v2 = *cur_time;
  } else {
    conn_rate_stats->v1 += 1;
    if (conn_rate_stats->v1 > MAX_CONN_RATE) {
      // we are exceding max connections rate. bypasing lru update and
      // source routing lookup
      return true;
    }
  }
  return false;
}

__attribute__((__always_inline__))
static inline bool get_packet_dst(struct real_definition **real,
                                  struct packet_description *pckt,
                                  struct vip_meta *vip_info,
                                  struct core_stats_set *cstat,
                                  void *lru_map) {

  // to update lru w/ new connection
  bool under_flood = false;
  bool src_found = false;
  __u32 *real_pos;
  __u64 cur_time = 0;
  __u32 hash;
  __u32 key;

  under_flood = is_under_flood(&cur_time);

  #ifdef LPM_SRC_LOOKUP
  if ((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
    __u32 *lpm_val;
    if (pckt->is_ipv6) {
      struct v6_lpm_key lpm_key_v6 = {};
      lpm_key_v6.prefixlen = 128;
      memcpy(lpm_key_v6.addr, pckt->flow.srcv6, 16);
      lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key_v6);
    } else {
      struct v4_lpm_key lpm_key_v4 = {};
      lpm_key_v4.addr = pckt->flow.src;
      lpm_key_v4.prefixlen = 32;
      lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
    }
    if (lpm_val) {
      src_found = true;
      key = *lpm_val;
    }
    __u32 stats_key = MAX_VIPS * 2 + LPM_SRC_CNTRS;
    struct lb_stats *data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (data_stats) {
      if (src_found) {
        data_stats->v2 += 1;
      } else {
        data_stats->v1 += 1;
      }
    }
  }
  #endif
  if (!src_found) {
    bool hash_16bytes = pckt->is_ipv6;

    if (vip_info->flags & F_HASH_DPORT_ONLY) {
      // service which only use dst port for hash calculation
      // e.g. if packets has same dst port -> they will go to the same real.
      // usually VoIP related services.
      pckt->flow.port16[0] = pckt->flow.port16[1];
      memset(pckt->flow.srcv6, 0, 16);
    }
    hash = get_packet_hash(pckt, hash_16bytes) % RING_SIZE;
    key = RING_SIZE * (vip_info->vip_num) + hash;

    real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if(!real_pos) {
      return false;
    }
    key = *real_pos;
  }
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
    return false;
  }
  if (!(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
    struct real_pos_lru new_dst_lru = {};
    struct flow_key flow = pckt->flow;
    if (pckt->flow.proto == IPPROTO_UDP) {
      new_dst_lru.atime = cur_time;
    } else if (pckt->flow.proto == IPPROTO_TCP) {
      conn_cnt_update(-1, cstat);
      tcp_status_change(&new_dst_lru, cstat, pckt);
    }
    new_dst_lru.pos = key;
    bpf_map_update_elem(lru_map, &flow, &new_dst_lru, BPF_ANY);
  }
  return true;
}

__attribute__((__always_inline__))
static inline struct real_pos_lru *connection_table_lookup(struct real_definition **real,
                                           struct packet_description *pckt, 
					   struct core_stats_set *cstat,
                                           void *lru_map) {
  struct real_pos_lru *dst_lru;
  struct flow_key flow = pckt->flow;
  __u32 key;
  dst_lru = bpf_map_lookup_elem(lru_map, &flow);
  if (!dst_lru) {
    return NULL;
  }
  if (pckt->flow.proto == IPPROTO_UDP) {
    __u64 cur_time = bpf_ktime_get_ns();
    if (cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {
      return NULL;
    }
    dst_lru->atime = cur_time;
  } else if (pckt->flow.proto == IPPROTO_TCP) {
    tcp_status_change(dst_lru, cstat, pckt);
  }
  key = dst_lru->pos;
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  return dst_lru;
}

__attribute__((__always_inline__))
static inline int process_l3_headers(struct packet_description *pckt,
                                     __u8 *protocol, __u64 off,
                                     void *data,
                                     void *data_end, bool is_ipv6,
                                     bool decrement_ttl, 
                                     struct core_stats_set *cstat) {
  int action;
  struct iphdr *iph;
  struct ipv6hdr *ip6h;
  if (is_ipv6) {
    ip6h = data + off;
    if (ip6h + 1 > data_end) {
      goto hdr_err;
    }

    *protocol = ip6h->nexthdr;
    pckt->flow.proto = *protocol;

    if (decrement_ttl) {
      if(!--ip6h->hop_limit) {
        // ttl 0
        goto hdr_err;
      }
    }

    pckt->pkt_bytes = bpf_ntohs(ip6h->payload_len);
    off += sizeof(struct ipv6hdr);
    if (*protocol == IPPROTO_FRAGMENT) {
      // we drop fragmented packets
      if (cstat->flags & F_CTL_DROP_FRAGMENT) {
        CSTAT_INC(cstat, l3, drop_fragment);
        goto drop;
      }
      goto pass;
    } else if (*protocol == IPPROTO_ICMPV6) {
      action = parse_icmpv6(data, data_end, off, pckt);
      if (action >= 0) {
        return action;
      }
      // protocol may changes by icmpv6
      *protocol = pckt->flow.proto;
    } else {
      memcpy(pckt->flow.srcv6, ip6h->saddr.s6_addr32, 16);
      memcpy(pckt->flow.dstv6, ip6h->daddr.s6_addr32, 16);
    }
  } else {
    iph = data + off;
    if (iph + 1 > data_end) {
      goto hdr_err;
    }

    *protocol = iph->protocol;
    pckt->flow.proto = *protocol;

    //ihl contains len of ipv4 header in 32bit words
    if (iph->ihl != 5) {
      // if len of ipv4 hdr is not equal to 20bytes that means that header
      // contains ip options, and we dont support em
      if (cstat->flags & F_CTL_DROP_IP_OPTION) {
        goto hdr_err;
      }
      goto pass;
    }

    if (decrement_ttl) {
      u32 csum;
      if (!--iph->ttl) {
        // ttl 0
        goto hdr_err;
      }
      csum = iph->check + 0x0001;
      iph->check = (csum & 0xffff) + (csum >> 16);
    }

    pckt->pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    if (iph->frag_off & PCKT_FRAGMENTED) {
      // we drop fragmented packets.
      if (cstat->flags & F_CTL_DROP_FRAGMENT) {
        CSTAT_INC(cstat, l3, drop_fragment);
        goto drop;
      }
      goto pass;
    }
    if (*protocol == IPPROTO_ICMP) {
      action = parse_icmp(data, data_end, off, pckt);
      if (action >= 0) {
        return action;
      }
      // protocol may changes by icmp
      *protocol = pckt->flow.proto;
    } else {
      pckt->flow.src = iph->saddr;
      pckt->flow.dst = iph->daddr;
    }
  }
  return FURTHER_PROCESSING;
hdr_err:
  if (is_ipv6) {
    CSTAT_INC(cstat, l3, ipv6_hdr_err);
  } else {
    CSTAT_INC(cstat, l3, ipv4_hdr_err);
  }
drop:
  return XDP_DROP;
pass:
  return XDP_PASS;
}

__attribute__((__always_inline__))
static inline int do_redirect(int ifindex, bool ingress) {
  if (ingress) {
    __u32 pos = 0, ifindex2 = (__u32)ifindex;

    // just set redirect info and return
    if (bpf_map_update_elem(&redirect_desc, &pos, &ifindex2, BPF_ANY)) {
      return XDP_DROP;
    }
    return XDP_PASS;
  }
  return bpf_redirect(ifindex, 0);
}

__attribute__((__always_inline__))
static inline int redirect_packet(struct xdp_md *ctx, void *smac, 
		void *dmac, int ifindex, bool ingress) {
  struct eth_hdr *eth;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (data + sizeof(struct eth_hdr) > data_end) {
    return XDP_DROP;
  }

  eth = data;

  if (smac)
    memcpy(eth->eth_source, smac, 6);

  if (dmac)
    memcpy(eth->eth_dest, dmac, 6);

  return do_redirect(ifindex, ingress);
}

__attribute__((__always_inline__))
static inline int local_redirect(struct xdp_md *ctx, struct packet_description *pckt, 
		bool is_ipv6, bool ingress) {
  int action;
  bool decap_and_pass;
  struct real_info *real_inf;

  // fast path, we can directly redirect to other interface
  action = check_decap_dst(&reals_info, pckt, is_ipv6, &decap_and_pass, (void **)&real_inf);
  if (action >= 0) {
    return action;
  }
  if (real_inf && real_inf->ifindex) {
    return redirect_packet(ctx, NULL, real_inf->mac, real_inf->ifindex, ingress);
  }
  return FURTHER_PROCESSING;
}

__attribute__((__always_inline__))
static inline int forward_packet(void *data, void *data_end,
                                 struct xdp_md *xdp,
                                 struct packet_description *pckt, 
                                 struct core_stats_set *cstat) {
  struct ctl_value *cval;
  struct real_definition *dst = NULL;
  struct vip_definition vip = {};
  struct xlb_fib_args args = {};
  struct vip_meta *vip_info;
  struct lb_stats *data_stats;
  __u32 vip_num, key, oif;
  void *omap;
  int action;
  __u8 proto = pckt->flow.proto;
  bool is_ipv6 = pckt->is_ipv6;
  int real_index;

  if (is_ipv6) {
    memcpy(vip.vipv6, pckt->flow.dstv6, 16);
  } else {
    vip.vip = pckt->flow.dst;
  }

  vip.port = pckt->flow.port16[1];
  vip.proto = proto;
  vip_info = bpf_map_lookup_elem(&vip_map, &vip);
  if (!vip_info) {
    vip.port = 0;
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if (!vip_info) {
      CSTAT_INC(cstat, total, no_vip);
      goto pass;
    }

    if (!(vip_info->flags & F_HASH_DPORT_ONLY)) {
      // VIP, which doesnt care about dst port (all packets to this VIP w/ diff
      // dst port but from the same src port/ip must go to the same real
      pckt->flow.port16[1] = 0;
    }
  }

  // source addr filter
  if (acl_process(pckt, (cstat->flags & F_CTL_ACL_DEF_DROP) ? 
			  XDP_DROP : XDP_PASS) == XDP_DROP) {
      goto drop;
  }

  if (data_end - data > MAX_PCKT_SIZE) {
#ifdef ICMP_TOOBIG_GENERATION
    __u32 stats_key = MAX_VIPS * 2 + ICMP_TOOBIG_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (!data_stats) {
      goto map_err;
    }
    if (is_ipv6) {
      data_stats->v2 += 1;
    } else {
      data_stats->v1 += 1;
    }
    CSTAT_INC(cstat, total, pkt2big);
    CSTAT_INC(cstat, total, drop);
    return send_icmp_too_big(xdp, is_ipv6, data_end - data);
#else
    CSTAT_INC(cstat, total, pkt2big);
    goto drop;
#endif
  }

  __u32 stats_key = MAX_VIPS * 2 + LRU_CNTRS;
  data_stats = bpf_map_lookup_elem(&stats, &stats_key);
  if (!data_stats) {
    goto map_err;
  }

  // totall packets
  data_stats->v1 += 1;

  if ((vip_info->flags & F_QUIC_VIP)) {
    real_index = parse_quic(data, data_end, pckt);
    if (real_index > 0) {
      key = real_index;
      __u32 *real_pos = bpf_map_lookup_elem(&quic_mapping, &key);
      if (real_pos) {
        key = *real_pos;
        pckt->real_index = key;
        dst = bpf_map_lookup_elem(&reals, &key);
        if (!dst) {
          goto map_err;
        }
      }
    }
  }

  // conn stat init
  stats_key = MAX_VIPS * 2 + CONN_CNTR;
  if (!(cstat->conn = bpf_map_lookup_elem(&stats, &stats_key))) {
    goto map_err;
  }
  vip_num = vip_info->vip_num;
  if (!(cstat->vip_conn = bpf_map_lookup_elem(&conn_stats, &vip_num))) {
    goto map_err;
  }

  if (!dst) {
    if ((vip_info->flags & F_HASH_NO_SRC_PORT)) {
      // service, where diff src port, but same ip must go to the same real,
      // e.g. gfs
      pckt->flow.port16[0] = 0;
    }
    __u32 cpu_num = bpf_get_smp_processor_id();
    void *lru_map = bpf_map_lookup_elem(&lru_maps_mapping, &cpu_num);
    if (!lru_map) {
      lru_map = &fallback_lru_cache;
      __u32 lru_stats_key = MAX_VIPS * 2 + FALLBACK_LRU_CNTR;
      struct lb_stats *lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
      if (!lru_stats) {
        goto map_err;
      }
      // we weren't able to retrieve per cpu/core lru and falling back to
      // default one. this counter should never be anything except 0 in prod.
      // we are going to use it for monitoring.
      lru_stats->v1 += 1;
    }
    if (!(pckt->flags & F_TCP_NEW) &&
        !(vip_info->flags & F_LRU_BYPASS)) {
#ifndef SESSION_SYNC
      // lookup connection table which contains node wide connections
      connection_table_lookup(&dst, pckt, cstat, lru_map);
#else /*SESSION_SYNC*/
      // lookup connection table which contains cluster wide connections
      struct real_pos_lru *dst_lru = connection_table_lookup(&dst, pckt, cstat, lru_map);

      __u32 back_stats_key = MAX_VIPS * 2 + BACKUP_LRU_CNTR;
      struct lb_stats *back_stats = bpf_map_lookup_elem(&stats, &back_stats_key);
      if (!back_stats) {
        goto map_err;
      }
      if (!dst) {
          void *lru_map_back;

          if ((lru_map_back = bpf_map_lookup_elem(&backup_lru_maps_mapping, &cpu_num))) {
            dst_lru = connection_table_lookup(&dst, pckt, cstat, lru_map_back);
            if (dst && dst_lru) {
              struct real_pos_lru dst_lru2 = *dst_lru;
              struct flow_key flow = pckt->flow;
              back_stats->v2 += 1;
              // backup connection table has the connection,
              // we should copy it to main table which can trigger connection sync by xlb daemon.
              bpf_map_update_elem(lru_map, &flow, &dst_lru2, BPF_ANY);
            }
          }
      } else {
          // dst_lru must not be null here.
          if (dst_lru && (dst_lru->flag & F_SESSION_FROM_OTHER)) {
              // lru from other node of the cluster
              back_stats->v2 += 1;
          } else {
              // lru from main table or fallback table
              back_stats->v1 += 1;
          }
      }
#endif /*!SESSION_SYNC*/
    }
    // no lru cache in both main and backup table
    if (!dst) {
      if (pckt->flow.proto == IPPROTO_TCP) {
        __u32 lru_stats_key = MAX_VIPS * 2 + LRU_MISS_CNTR;
        struct lb_stats *lru_stats = bpf_map_lookup_elem(
          &stats, &lru_stats_key);
        if (!lru_stats) {
          goto map_err;
        }
        if (pckt->flags & F_TCP_NEW) {
          // miss because of new tcp session
          lru_stats->v1 += 1;
        } else {
          // miss of non-syn tcp packet. could be either because of LRU trashing
          // or because another katran is restarting and all the sessions
          // have been reshuffled
          lru_stats->v2 += 1;
        }
      }
      if (!get_packet_dst(&dst, pckt, vip_info, cstat, lru_map)) {
        CSTAT_INC(cstat, total, no_dst);
        goto drop;
      }
      // lru misses (either new connection or lru is full and starts to trash)
      data_stats->v2 += 1;
      // report new conn event
      new_conn_event(xdp, pckt);
    }
  }

  // don't forward local packets
  if (dst->flags & F_LOCAL && !(cstat->flags & F_CTL_LOCAL_ENCAP)) {
    action = XDP_PASS;
  } else {
    // init fib args
    action = fib_args_init(&args, &oif, dst);
    if (action >= 0) {
      goto map_err;
    }

    // encap packet
    if (dst->flags & F_IPV6) {
      if (!PCKT_ENCAP_V6(xdp, &args, pckt, dst)) {
        CSTAT_INC(cstat, l3, ipv6_encap_err);
        goto drop;
      }
    } else {
      if (!PCKT_ENCAP_V4(xdp, &args, pckt, dst)) {
        CSTAT_INC(cstat, l3, ipv4_encap_err);
        goto drop;
      }
    }
    action = XDP_TX;
  }

  // per vip statistics
  data_stats = bpf_map_lookup_elem(&stats, &vip_num);
  if (!data_stats) {
    goto map_err;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pckt->pkt_bytes;

  // per vip and real statistics
  omap = bpf_map_lookup_elem(&vip_rip_stats, &vip_num);
  if (!omap) {
    goto map_err;
  }
  real_index = pckt->real_index;
  data_stats = bpf_map_lookup_elem(omap, &real_index);
  if (!data_stats) {
    goto map_err;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pckt->pkt_bytes;

  // per core statistics
  core_stats_calc(cstat, is_ipv6, proto, action);
  if (action == XDP_TX) {
    // fib_lookup indicates other interface(NOT iif/oif), just pass to kernel.
    if (fib_indicate_local_deliver(&args, oif)) {
      goto pass_no_cnt;
    }
    // redirect to other nic
    if (args.iif != oif) {
      return redirect_packet(xdp, NULL, NULL, oif, false);
    }
    goto proc_action;
  }

  #ifdef INLINE_REDIRECT
  // action is XDP_PASS here
  if (dst->flags & F_REDIRECT) {
    // directly redirect to local pods
    action = local_redirect(xdp, pckt, is_ipv6, true);
    if (action >= 0) {
      // DROP counters
      if (action == XDP_DROP) {
        goto drop;
      }
      goto proc_action;
    }
    goto pass_no_cnt;
  }
  #endif // of INLINE_REDIRECT
proc_action:
  return action;
pass:
  core_stats_calc(cstat, is_ipv6, proto, XDP_PASS);
pass_no_cnt:
  return XDP_PASS;
map_err:
  CSTAT_INC(cstat, total, map_err);
drop:
  CSTAT_INC(cstat, total, drop);
  return XDP_DROP;
}

__attribute__((__always_inline__))
static inline int process_packet(void *data, __u64 off, void *data_end,
                                 bool is_ipv6, bool decap_and_pass, struct xdp_md *xdp,
                                 struct core_stats_set *cstat,
                                 void *root_array)  {
  struct packet_description pckt = {};
  __u8 protocol = 0;
  int action;

  pckt.is_ipv6 = is_ipv6;
  action = process_l3_headers(
    &pckt, &protocol, off, data, data_end, is_ipv6, false, cstat);
  if (action >= 0) {
    goto proc_action;
  }

  #ifdef INLINE_DECAP
  if (!(cstat->flags & F_CTL_DECAP_BYPASS) && 
		  (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6)) {
    __u32 *decap_flags;

    action = check_decap_dst(&decap_dst, &pckt, is_ipv6, &decap_and_pass, (void **)&decap_flags);
    if (action >= 0) {
      goto proc_action;
    }
    action = process_encaped_ipip_pckt(&data, &data_end, xdp, is_ipv6, protocol);
    if (action >= 0) {
      goto proc_action;
    }
    goto proc_decap;
  }
  #endif

  if (protocol == IPPROTO_TCP) {
    if (!parse_tcp(data, data_end, &pckt)) {
      CSTAT_INC(cstat, l4, tcp_hdr_err);
      goto drop;
    }
  } else if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, &pckt)) {
      CSTAT_INC(cstat, l4, udp_hdr_err);
      goto drop;
    }
  #ifdef INLINE_DECAP
    if (!(cstat->flags & F_CTL_DECAP_BYPASS) && 
		    pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) {
      __u32 *decap_flags;
      
      action = check_decap_dst(&decap_dst, &pckt, is_ipv6, &decap_and_pass, (void **)&decap_flags);
      if (action >= 0) {
        goto proc_action;
      }
      action = process_encaped_gue_pckt(&data, &data_end, xdp, is_ipv6);
      if (action >= 0) {
        goto proc_action;
      }
      goto proc_decap;
    }
  #endif // of INLINE_DECAP
  } else {
    // send to tcp/ip stack
    goto pass;
  }

  // store packet desc for later bpf-prog
  __u32 key = 0;
  if (bpf_map_update_elem(&packet_desc, &key, &pckt, BPF_ANY)) {
    goto map_err;
  }
  return root_tail_call_balancer(xdp, root_array);

  #ifdef INLINE_DECAP
proc_decap:
  // it's ipip encapsulated packet but not to decap dst. 
  // so just pass decapsulated packet to the kernel.
  if (!decap_and_pass) {
    struct packet_description *pckt_ptr;

    #ifdef INLINE_REDIRECT
    // directly redirect to local pods
    action = local_redirect(xdp, &pckt, is_ipv6, true);
    if (action >= 0) {
      goto proc_action;
    }
    #endif // of INLINE_REDIRECT

    key = 0;
    if (!(pckt_ptr = bpf_map_lookup_elem(&packet_desc, &key))) {
      goto map_err;
    }
    // mitigate ipip loop attack
    if (pckt_ptr->flags & F_INLINE_DECAP) {
      goto drop;
    }
    pckt_ptr->flags |= F_INLINE_DECAP;
    return root_tail_call_parse(xdp, root_array);
  }
  #endif // of INLINE_DECAP
pass:
  action = XDP_PASS;
proc_action:
  core_stats_calc(cstat, is_ipv6, protocol, action);
  return action;
map_err:
  CSTAT_INC(cstat, total, map_err);
drop:
  CSTAT_INC(cstat, total, drop);
  return XDP_DROP;
}

__attribute__((__always_inline__))
static inline int balancer_prepare(struct core_stats_set *cstat, 
        struct packet_description **pckt)  {
  int action;
  __u32 key;

  if ((action = core_stats_init(cstat)) != FURTHER_PROCESSING)
    return action;

  key = 0;
  if (!(*pckt = bpf_map_lookup_elem(&packet_desc, &key))) {
    CSTAT_INC(cstat, total, map_err);
    return XDP_DROP;
  }
  return FURTHER_PROCESSING;
}

__attribute__((__always_inline__))
static inline int do_parse(struct xdp_md *ctx, void *root_array, int decap_and_proc) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off = sizeof(struct eth_hdr);
  struct core_stats_set cstat;
  int action;

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    return XDP_DROP;
  }

  if ((action = core_stats_init(&cstat)) != FURTHER_PROCESSING) {
    return action;
  }

  if (decap_and_proc == -1) {
    decap_and_proc = cstat.flags & F_CTL_DECAP_PROC;
  }

  eth_proto = eth->eth_proto;

  if (eth_proto == BE_ETH_P_IP) {
    return process_packet(data, nh_off, data_end, false, !decap_and_proc, ctx, &cstat, root_array);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    return process_packet(data, nh_off, data_end, true, !decap_and_proc, ctx, &cstat, root_array);
  } else {
    CSTAT_INC(&cstat, l3, other);
    CSTAT_INC(&cstat, total, input);
    // pass to tcp/ip stack
    return XDP_PASS;
  }
}

SEC("xdp-balancer")
int balancer_ingress(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct core_stats_set cstat;
  struct packet_description *pckt;
  int action;

  if ((action = balancer_prepare(&cstat, &pckt)) != FURTHER_PROCESSING)
    return action;

  return forward_packet(data, data_end, ctx, pckt, &cstat);
}

SEC("xdp-redirect")
int balancer_redirect(struct xdp_md *ctx) {
  struct core_stats_set cstat;
  struct address local = {};
  struct vip_definition vip = {};
  struct vip_meta *vip_info;
  struct lb_stats *data_stats;
  struct packet_description *pckt;
  struct ctl_value *cval, *smac, *dmac;
  int ifindex, action;
  bool is_ipv6;
  __u8 proto;
  __u32 key, vip_num;

  if (balancer_prepare(&cstat, &pckt) != FURTHER_PROCESSING)
    goto pass_no_cnt;

  // looking for packet comming from vip
  proto = pckt->flow.proto;
  is_ipv6 = pckt->is_ipv6;

  if (is_ipv6) {
    memcpy(vip.vipv6, pckt->flow.srcv6, 16);
    memcpy(local.addrv6, pckt->flow.dstv6, 16);
  } else {
    vip.vip = pckt->flow.src;
    local.addr = pckt->flow.dst;
  }

  vip.port = pckt->flow.port16[0];
  vip.proto = proto;
  if (!(vip_info = bpf_map_lookup_elem(&vip_map, &vip))) {
    vip.port = 0;
    if (!(vip_info = bpf_map_lookup_elem(&vip_map, &vip))) {
      goto pass;
    }
  }

  // deliver to local
  if (bpf_map_lookup_elem(&local_map, &local)) {
      goto pass;
  }
  
  // iif mac
  key = CTL_MAP_POS_IIFMAC;
  smac = bpf_map_lookup_elem(&ctl_array, &key);
  if (!smac) {
    goto pass;
  }

  // iif gateway
  key = CTL_MAP_POS_MAC_ADDR2;
  dmac = bpf_map_lookup_elem(&ctl_array, &key);
  if (!dmac) {
    goto pass;
  }
  
  // iif index
  key = CTL_MAP_POS_IN_IF;
  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto pass;
  }
  ifindex = cval->ifindex;

  // per vip statistics
  vip_num = vip_info->vip_num + MAX_VIPS;
  if ((data_stats = bpf_map_lookup_elem(&stats, &vip_num))) {
    data_stats->v1 += 1;
    data_stats->v2 += pckt->pkt_bytes;
  }

  // do redirect
  return redirect_packet(ctx, smac->mac, dmac->mac, ifindex, false);
pass:
  CSTAT_INC(&cstat, total, input);
pass_no_cnt:
  return XDP_PASS;
}

SEC("cls-redirect")
int balancer_ingress_redirect(struct __sk_buff *skb) {
  __u32 pos = 0, *ifindex;

  if ((ifindex = bpf_map_lookup_elem(&redirect_desc, &pos)) && (*ifindex)) {
    __u32 key = KATRAN_CORE_STAT_TOTAL;
    union core_stats *total;

    if ((total = bpf_map_lookup_elem(&core_stats, &key))) {
      total->total.redirect++;
      // clean redirect info
      bpf_map_update_elem(&redirect_desc, &pos, &pos, BPF_ANY);
      return bpf_redirect(*ifindex, REDIRECT_INGRESS);
    }
  }
  return TC_ACT_UNSPEC;
}

SEC("xdp-parse")
int balancer_parse(struct xdp_md *ctx) {
    return do_parse(ctx, &root_array, -1);
}

SEC("xdp-parse2")
int balancer_parse2(struct xdp_md *ctx) {
    return do_parse(ctx, &root_array2, 1);
}

SEC("xdp-root")
int xdp_root(struct xdp_md *ctx) {
    return root_tail_call(ctx, &root_array);
}

SEC("xdp-root2")
int xdp_root2(struct xdp_md *ctx) {
    return root_tail_call(ctx, &root_array2);
}
char _license[] SEC("license") = "GPL";
