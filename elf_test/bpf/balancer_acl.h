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

#ifndef __BALANCER_ACL_H
#define __BALANCER_ACL_H

#ifdef ENABLE_ACL

struct bpf_map_def SEC("maps") acl_src_v4 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v4_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_ACL_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
BPF_ANNOTATE_KV_PAIR(acl_src_v4, struct v4_lpm_key, __u32);

struct bpf_map_def SEC("maps") acl_src_v6 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v6_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_ACL_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
BPF_ANNOTATE_KV_PAIR(acl_src_v6, struct v6_lpm_key, __u32);

__attribute__((__always_inline__))
static inline int acl_process(struct packet_description *pckt, int default_action) {
  __u32 *lpm_val;

  if (pckt->is_ipv6) {
    struct v6_lpm_key lpm_key_v6 = {};
    lpm_key_v6.prefixlen = 128;
    memcpy(lpm_key_v6.addr, pckt->flow.srcv6, 16);
    lpm_val = bpf_map_lookup_elem(&acl_src_v6, &lpm_key_v6);
  } else {
    struct v4_lpm_key lpm_key_v4 = {};
    lpm_key_v4.addr = pckt->flow.src;
    lpm_key_v4.prefixlen = 32;
    lpm_val = bpf_map_lookup_elem(&acl_src_v4, &lpm_key_v4);
  }

  __u32 stats_key = MAX_VIPS * 2 + ACL_CNTR;
  struct lb_stats *data_stats = bpf_map_lookup_elem(&stats, &stats_key);
  if (data_stats) {
    if (lpm_val) {
      default_action = *lpm_val;
    }
    if (default_action == XDP_PASS) {
      data_stats->v2 += 1;
    } else {
      data_stats->v1 += 1;
    }
  }
  return default_action;
}

#else  /*!ENABLE_ACL*/

__attribute__((__always_inline__))
static inline int acl_process(struct packet_description *pckt, int default_action) {
  return XDP_PASS;
}

#endif /*ENABLE_ACL*/

#endif // of __BALANCER_ACL_H
