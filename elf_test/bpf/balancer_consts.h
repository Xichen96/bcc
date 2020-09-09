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

#ifndef __BALANCER_CONSTS_H
#define __BALANCER_CONSTS_H
/*
 * This file contains definition of all balancer specific constants
 */

// we dont want to do htons for each packet, so this is ETH_P_IPV6 and
// ETH_P_IP in be format
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

// GUE variant 1 using first four bits of inner packet as a pseudo header
// we are using last two of this four bits to distinct v4 vs v6. see RFC for
// more details
#define GUEV1_IPV6MASK 0x30

// functions could return ether drop, pass, tx or we need to further
// process a packet to figure out what to do with it
#define FURTHER_PROCESSING -1

// 3FFF mask covers more fragments flag and fragment offset field.
// 65343 = 3FFF in BigEndian
#define PCKT_FRAGMENTED 65343

#define IPV4_HDR_LEN_NO_OPT 20
#define IPV4_PLUS_ICMP_HDR 28
#define IPV6_PLUS_ICMP_HDR 48

//consistent hashing ring size
#ifndef RING_SIZE
#define RING_SIZE 65537
#endif

#ifndef MAX_VIPS
#define MAX_VIPS 512
#endif

// 1 real is equal to 1 ip address. so server w/ v4 and v6 would most likely
// consume 2 spots
#ifndef MAX_REALS
#define MAX_REALS 2048
#endif

// maximum number of prefixes in lpm map for src based routing.
#ifndef MAX_LPM_SRC
#define MAX_LPM_SRC 3000000
#endif

#ifndef MAX_ACL_SRC
#define MAX_ACL_SRC 3000000
#endif

#ifndef MAX_DECAP_DST
#define MAX_DECAP_DST 6
#endif

// use 16 bits in quic's connection id to store real's index
#define MAX_QUIC_REALS 65535 // 2^16-1

#define CTL_MAP_SIZE 16

// size of internal prog array
#define SUBPROGRAMS_ARRAY_SIZE 1
// position where katran would register itself in prog array
// for recirculation
#define RECIRCULATION_INDEX 0

#define CH_RINGS_SIZE (MAX_VIPS * RING_SIZE)

// offset of the lru cache hit related counters
#define LRU_CNTRS                     0
#define LRU_MISS_CNTR                 1
#define NEW_CONN_RATE_CNTR            2
#define FALLBACK_LRU_CNTR             3
// offset of icmp related counters
#define ICMP_TOOBIG_CNTRS             4
// offset of src routing lookup counters
#define LPM_SRC_CNTRS                 5
// offset of remote encaped packets counters
#define REMOTE_ENCAP_CNTRS            6
// offset of the backup lru cache hit related counters
#define BACKUP_LRU_CNTR               7
// offset of ACL DROP related counters
#define ACL_CNTR                      8
// offset of active/inactive counter
#define CONN_CNTR                     9
// offset of the max counters
#define MAX_STATS_CNTR                10

#define STATS_MAP_SIZE (MAX_VIPS * 2 + MAX_STATS_CNTR)

// ctrl array pos
#define CTL_MAP_POS_MAC_ADDR    0      /* oif gateway */
#define CTL_MAP_POS_TUN4        1
#define CTL_MAP_POS_TUN6        2
#define CTL_MAP_POS_IN_IF       3
#define CTL_MAP_POS_OUT_IF      4
#define CTL_MAP_POS_OIFMAC      5
#define CTL_MAP_POS_IIFMAC      6
#define CTL_MAP_POS_MAC_ADDR2   7      /* iif gateway */
#define CTL_MAP_POS_IPIP_PREFIX 8
#define CTL_MAP_POS_PKT_FLAGS   9

// for LRU's map in map we will support up to this number of cpus
#ifndef MAX_SUPPORTED_CPUS
#define MAX_SUPPORTED_CPUS 128
#endif

// default lru is a fallback lru, which will be used when forwarding cpu/core
// cannot find per core lru in lrus map-in-map.
// we should only have a hit in this default lru while running unittests.
// thats why by default the value of this lru is this small
#define DEFAULT_LRU_SIZE 1000

#define ONE_SEC 1000000000U // 1 sec in nanosec

// how long we will keep udp's connection as active in lru map. in nanosec
#ifndef LRU_UDP_TIMEOUT
#define LRU_UDP_TIMEOUT 30000000000U // 30 sec in nanosec
#endif

// FLAGS:
// real_definition flags:
// address is ipv6
#define F_IPV6 (1 << 0)
// local packets
#define F_LOCAL (1 << 1)
// redirect packets
#define F_REDIRECT (1 << 2)

// vip_meta flags
// dont use client's port for hash calculation
#define F_HASH_NO_SRC_PORT (1 << 0)
// dont try to find existing connection in lru map and don't update it
#define F_LRU_BYPASS (1 << 1)
// use quic's connection id for the hash calculation
#define F_QUIC_VIP (1 << 2)
// use only dst port for the hash calculation
#define F_HASH_DPORT_ONLY (1 << 3)
// check if src based routing should be used
#define F_SRC_ROUTING (1 << 4)
// session need to sync
#define F_SESSION_SYN (1 << 9)
// session from other node
#define F_SESSION_FROM_OTHER (1 << 10)

// packet_description flags:
// the description has been created from icmp msg
#define F_ICMP (1 << 0)
// packet was decapsulated inline
#define F_INLINE_DECAP (1 << 2)
// tcp new
#define F_TCP_NEW    (1 << 1)
//tcp estab
#define F_TCP_ESTAB  (1 << 5)
//tcp close
#define F_TCP_CLOSE  (1 << 6)

// ctrl flags:
#define F_CTL_DROP_FRAGMENT  (1<<0)
#define F_CTL_DROP_IP_OPTION (1<<1)
#define F_CTL_DECAP_BYPASS   (1<<2)
#define F_CTL_DECAP_PROC     (1<<3)
#define F_CTL_LOCAL_ENCAP    (1<<4)
#define F_CTL_ACL_DEF_DROP   (1<<5)
#define F_CTL_CONN_EVENT     (1<<6)

// ttl for outer ipip packet
#ifndef DEFAULT_TTL
#define DEFAULT_TTL 64
#endif

// QUIC invariants from draft-ietf-quic-transport-17
#define QUIC_LONG_HEADER 0x80
#define QUIC_SHORT_HEADER 0x00
// Long header packet types (with alignment of 8-bits for packet-type)
#define QUIC_CLIENT_INITIAL 0x00
#define QUIC_0RTT 0x10
#define QUIC_HANDSHAKE 0x20
#define QUIC_RETRY 0x30
#define QUIC_PACKET_TYPE_MASK 0x30

// Implementation specific constants:
// Require connection id to be of minimum length
#ifndef QUIC_MIN_CONNID_LEN
#define QUIC_MIN_CONNID_LEN 8
#endif
// explicitly version the connection id
#ifndef QUIC_CONNID_VERSION
#define QUIC_CONNID_VERSION 0x1
#endif


// max ethernet packet's size which destination is a vip
// we need to inforce it because if origin_packet + encap_hdr > MTU
// then, depends on the dirver, it could either panic or drop the packet
// for default value: 1500 ip size + 14 ether hdr size
#ifndef MAX_PCKT_SIZE
#define MAX_PCKT_SIZE 1514
#endif

// for v4 and v6: initial packet would be truncated to the size of eth header
// plus ipv4/ipv6 header and few bytes of payload
#define ICMP_TOOBIG_SIZE 98
#define ICMP6_TOOBIG_SIZE 262


#define ICMP6_TOOBIG_PAYLOAD_SIZE (ICMP6_TOOBIG_SIZE - 6)
#define ICMP_TOOBIG_PAYLOAD_SIZE (ICMP_TOOBIG_SIZE - 6)

#define NO_FLAGS 0

// max ammount of new connections per seconda per core for lru update
// if we go beyond this value - we will bypass lru update.
#ifndef MAX_CONN_RATE
#define MAX_CONN_RATE 125000
#endif

#ifndef IPIP_V4_PREFIX
// RFC1918: we are going to use 198.18/16 as our src (4806 is 198.18 in BE)
// for ipip header
#define IPIP_V4_PREFIX 4806
#endif

// for default values:
// RFC 6666: we are going to use 0100::/64 discard prefix as our src
// for ip(6)ip6 header

#ifndef IPIP_V6_PREFIX1
#define IPIP_V6_PREFIX1 1
#endif

#ifndef IPIP_V6_PREFIX2
#define IPIP_V6_PREFIX2 0
#endif

#ifndef IPIP_V6_PREFIX3
#define IPIP_V6_PREFIX3 0
#endif

// default tos/tclass value
#ifndef DEFAULT_TOS
#define DEFAULT_TOS 0
#endif

// specify whether to copy inner packets dscp value to outer encapped packet
#ifndef COPY_INNER_PACKET_TOS
#define COPY_INNER_PACKET_TOS 1
#endif

// defaut GUE dst port
#ifndef GUE_DPORT
#define GUE_DPORT 6080
#endif

#define GUE_CSUM 0

// initial value for jhash hashing function, used to pick up a real server
#ifndef INIT_JHASH_SEED
#define INIT_JHASH_SEED CH_RINGS_SIZE
#endif

// initial value for jhash hashing function, used to pick up a real server
// w/ ipv6 address
#ifndef INIT_JHASH_SEED_V6
#define INIT_JHASH_SEED_V6 MAX_VIPS
#endif



/*
 * optional features (requires kernel support. turned off by default)
 * to be able to enable them, you need to define them in compile time
 * (pass them with -D flag):
 *
 * ICMP_TOOBIG_GENERATION - allow to generate icmp's "packet to big"
 * if packet's size > MAX_PCKT_SIZE
 *
 * LPM_SRC_LOOKUP - allow to do src based routing/dst decision override
 *
 * INLINE_DECAP_GENERIC - enables features to allow pckt specific inline
 */
#ifdef LPM_SRC_LOOKUP
#ifndef INLINE_DECAP
#ifndef INLINE_DECAP_GUE
#define INLINE_DECAP
#endif // of INLINE_DECAP_GUE
#endif // of INLINE_DECAP
#endif // of LPM_SRC_LOOKUP

#ifdef INLINE_DECAP
#define INLINE_DECAP_IPIP
#endif

#ifdef INLINE_DECAP_IPIP
#ifndef INLINE_DECAP_GENERIC
#define INLINE_DECAP_GENERIC
#endif // of INLINE_DECAP_GENERIC
#endif // of INLINE_DECAP_IPIP

#ifdef INLINE_DECAP_GUE
#ifndef INLINE_DECAP_GENERIC
#define INLINE_DECAP_GENERIC
#endif // of INLINE_DECAP_GENERIC
#endif // of INLINE_DECAP_GUE

#ifdef GUE_ENCAP
#define PCKT_ENCAP_V4 gue_encap_v4
#define PCKT_ENCAP_V6 gue_encap_v6
#define HC_ENCAP hc_encap_gue
#else
#define PCKT_ENCAP_V4 encap_v4
#define PCKT_ENCAP_V6 encap_v6
#define HC_ENCAP hc_encap_ipip
#endif

// per core statistics
#define KATRAN_CORE_MAX_STAT  32
#define KATRAN_CORE_STAT_TOTAL 0
#define KATRAN_CORE_STAT_L3    1
#define KATRAN_CORE_STAT_L4    2

#ifndef REDIRECT_EGRESS 
#define REDIRECT_EGRESS 0
#endif  /*REDIRECT_EGRESS*/

#ifndef REDIRECT_INGRESS 
#define REDIRECT_INGRESS (1ULL << 0)
#endif  /*REDIRECT_INGRESS*/

#endif // of __BALANCER_CONSTS_H
