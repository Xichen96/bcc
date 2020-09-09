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

#include "bpf.h"
#include "bpf_helpers.h"
#include "root_maps.h"

//SEC("xdp-root")
int xdp_root(struct xdp_md *ctx) {
  return root_tail_call(ctx, &root_array);
}

//SEC("xdp-root2")
int xdp_root2(struct xdp_md *ctx) {
  return root_tail_call(ctx, &root_array2);
}

//char _license[] SEC("license") = "GPL";
