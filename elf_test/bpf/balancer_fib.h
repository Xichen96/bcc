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

#ifndef __BALANCER_FIB_H
#define __BALANCER_FIB_H

#ifdef ENABLE_FIB_LOOKUP

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

// map which contains opaque real's cache
struct bpf_map_def SEC("maps") reals_cache = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct address),
  .value_size = sizeof(struct bpf_fib_lookup),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(reals_cache, struct address, struct bpf_fib_lookup);

struct xlb_fib_args {
  struct real_definition *dst;
  __u32 iif;
  __u32 oif;
  __u8  *smac;
  __u8  *dmac;
  __u8  *pkt_dmac;
};

__attribute__ ((__always_inline__))
static inline int fib_args_init(struct xlb_fib_args *args, __u32 *oif, struct real_definition *dst)
{
  struct ctl_value *cval;
  __u32 key = CTL_MAP_POS_OUT_IF;

  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto map_err;
  }
  *oif = args->oif = cval->ifindex;

  key = CTL_MAP_POS_IN_IF;
  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto map_err;
  }
  args->iif = cval->ifindex;
  args->dst = dst;

  return FURTHER_PROCESSING;
map_err:
  return XDP_DROP;
}

__attribute__ ((__always_inline__))
static inline bool fib_indicate_local_deliver(struct xlb_fib_args *args, __u32 oif)
{
  return args->oif && args->oif != oif && args->oif != args->iif;
}

__attribute__ ((__always_inline__))
static inline int __fib_store_mac(struct xdp_md *ctx, struct bpf_fib_lookup *fib_params, 
		struct xlb_fib_args *args, bool update_cache)
{
  if (fib_params->ifindex == args->iif || fib_params->ifindex == args->oif) {
    memcpy(args->smac, fib_params->smac, 6);
    memcpy(args->dmac, fib_params->dmac, 6);
  } else {
    memcpy(args->smac, args->pkt_dmac, 6);
    // keep dmac and we got PACKET_HOST skb type
    memcpy(args->dmac, args->pkt_dmac, 6);
  }

  args->oif = fib_params->ifindex;

  if (update_cache && fib_params->ifindex) {
    bpf_map_update_elem(&reals_cache, args->dst, fib_params, BPF_NOEXIST);
  }
  return 0;
}

__attribute__ ((__always_inline__))
static inline int __fib4_store_mac(struct xdp_md *ctx, struct xlb_fib_args *args)
{
  struct bpf_fib_lookup fib_params = { };

  fib_params.family = AF_INET;
  fib_params.ifindex = args->iif;
  fib_params.ipv4_dst = args->dst->dst;

  if (bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),
           BPF_FIB_LOOKUP_DIRECT)) {
    return -1;
  }

  return __fib_store_mac(ctx, &fib_params, args, true);
}

__attribute__ ((__always_inline__))
static inline int __fib6_store_mac(struct xdp_md *ctx, struct xlb_fib_args *args)
{
  struct bpf_fib_lookup fib_params = { };

  fib_params.family = AF_INET6;
  fib_params.ifindex = args->iif;
  memcpy(fib_params.ipv6_dst, args->dst->dstv6, 16);

  if (bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),
           BPF_FIB_LOOKUP_DIRECT)) {
    return -1;
  }
  return __fib_store_mac(ctx, &fib_params, args, true);
}

__attribute__ ((__always_inline__))
static inline int fib_store_mac(struct xdp_md *ctx, struct xlb_fib_args *args, bool is_ipv6)
{
  struct bpf_fib_lookup *fib_params;

  if ((fib_params = bpf_map_lookup_elem(&reals_cache, args->dst)) && 
      fib_params->ifindex) {
    // fastpath
    return __fib_store_mac(ctx, fib_params, args, false);
  }
  if (is_ipv6) {
    return __fib6_store_mac(ctx, args);
  }
  return __fib4_store_mac(ctx, args);
}

#else /*!ENABLE_FIB_LOOKUP */

struct xlb_fib_args {
  __u32 iif;
  __u32 oif;
  __u8  *smac;
  __u8  *dmac;
  __u8  *pkt_dmac;
  __u8  *oif_mac;
  __u8  *gw_mac;
};

__attribute__ ((__always_inline__))
static inline int fib_args_init(struct xlb_fib_args *args, __u32 *oif, struct real_definition *dst)
{
  struct ctl_value *cval;
  __u32 key = CTL_MAP_POS_OUT_IF;

  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto map_err;
  }
  *oif = args->oif = cval->ifindex;

  key = CTL_MAP_POS_IN_IF;
  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto map_err;
  }
  args->iif = cval->ifindex;

  key = CTL_MAP_POS_MAC_ADDR;
  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto map_err;
  }
  args->gw_mac = cval->mac;

  key = CTL_MAP_POS_OIFMAC;
  cval = bpf_map_lookup_elem(&ctl_array, &key);
  if (!cval) {
    goto map_err;
  }
  args->oif_mac = cval->mac;

  return FURTHER_PROCESSING;
map_err:
  return XDP_DROP;
}

__attribute__ ((__always_inline__))
static inline bool fib_indicate_local_deliver(struct xlb_fib_args *args, __u32 oif)
{
  return false;
}

__attribute__ ((__always_inline__))
static inline int fib_store_mac(struct xdp_md *ctx, struct xlb_fib_args *args, bool is_ipv6)
{
  memcpy(args->dmac, args->gw_mac, 6);

  if (args->iif == args->oif) {
    memcpy(args->smac, args->pkt_dmac, 6);
  } else {
    memcpy(args->smac, args->oif_mac, 6);
  }

  args->oif = 0;

  return 0;
}

#endif /*ENABLE_FIB_LOOKUP */

#endif // of __BALANCER_FIB_H
