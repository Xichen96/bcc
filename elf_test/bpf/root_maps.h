#ifndef __ROOT_MAPS_H
#define __ROOT_MAPS_H

#include "bpf.h"
#include "bpf_helpers.h"

#define ROOT_ARRAY_SIZE 4

BPF_PROG_ARRAY(root_array, ROOT_ARRAY_SIZE);
//BPF_ANNOTATE_KV_PAIR(root_array, __u32, __u32);

BPF_PROG_ARRAY(root_array2, ROOT_ARRAY_SIZE);
//BPF_ANNOTATE_KV_PAIR(root_array2, __u32, __u32);

__attribute__((__always_inline__))
static inline int root_tail_call(struct xdp_md *ctx, void *root_array)
{
  #pragma clang loop unroll(full)
  for (__u32 i = 0; i < ROOT_ARRAY_SIZE; i++) {
    bpf_tail_call(ctx, root_array, i);
  }
  return XDP_PASS;
}

__attribute__((__always_inline__))
static inline int root_tail_call_parse(struct xdp_md *ctx, void *root_array)
{
  #pragma clang loop unroll(full)
  for (__u32 i = 1; i < ROOT_ARRAY_SIZE; i++) {
    bpf_tail_call(ctx, root_array, i);
  }
  return XDP_PASS;
}

__attribute__((__always_inline__))
static inline int root_tail_call_balancer(struct xdp_md *ctx, void *root_array)
{
  #pragma clang loop unroll(full)
  for (__u32 i = 2; i < ROOT_ARRAY_SIZE; i++) {
    bpf_tail_call(ctx, root_array, i);
  }
  return XDP_PASS;
}

#endif /*__ROOT_MAPS_H*/
