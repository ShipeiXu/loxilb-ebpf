/*
 *  llb_kern_dns.c: LoxiLB Kernel eBPF DNS DPI Implementation
 *  Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#ifndef __LLB_KERN_DNS_C__
#define __LLB_KERN_DNS_C__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "llb_kern_cdefs.h"

#define DNS_POLICY_CONTINUE 0
#define DNS_POLICY_DROP     1
#define DNS_POLICY_TRAP     2

static __always_inline int
dp_parse_dns_qname(void *data, void *data_end, __u16 off, struct dp_dns_key *key)
{
  __u8 *pos = data + off;
  __u16 label_off[32] = { 0 };
  __u8 label_len[32] = { 0 };
  __u16 out = 0;
  int labels = 0;
  int terminated = 0;
  int i, j;
  __u8 len;

  /* First validate QNAME and remember each label's location. */
  #pragma unroll
  for (i = 0; i < 32; i++) {
    if (pos + 1 > data_end) return -1;
    len = *pos;
    if (len == 0) {
      terminated = 1;
      break;
    }
    if (len > 63) return -1;
    pos++;

    if (pos + len > data_end) return -1;
    label_off[i] = (__u16)(pos - (__u8 *)data);
    label_len[i] = len;
    labels = i + 1;
    pos += len;
  }

  if (!terminated || labels == 0) return -1;

  /* Reverse labels so an LPM prefix represents a DNS suffix. */
  #pragma unroll
  for (i = 0; i < 32; i++) {
    int label_idx;
    __u8 *label;

    if (i >= labels) break;
    label_idx = labels - i - 1;
    if (label_idx < 0 || label_idx >= 32) return -1;
    len = label_len[label_idx];
    label = (__u8 *)data + label_off[label_idx];

    #pragma unroll
    for (j = 0; j < 64; j++) {
      if (j < len) {
        __u8 c;
        if (label + j + 1 > data_end || out >= sizeof(key->domain) - 1)
          return -1;
        c = *(label + j);
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        key->domain[out++] = c;
      }
    }
    if (out >= sizeof(key->domain) - 1) return -1;
    key->domain[out++] = '.';
  }

  /* Prefix length for LPM Trie is in bits */
  key->l.prefixlen = out * 8;
  return 0;
}

static __always_inline int
dp_check_dns_policy(void *ctx, struct xfi *xf)
{
  struct dp_dns_key key;
  struct dp_fw_tact *act;
  void *data = DP_TC_PTR(DP_PDATA(ctx));
  void *data_end = DP_TC_PTR(DP_PDATA_END(ctx));
  __u16 off = xf->pm.l4_off + sizeof(struct udphdr) + 12;

  if (xf->l34m.nw_proto != IPPROTO_UDP ||
      bpf_htons(xf->l34m.dest) != 53) {
    return DNS_POLICY_CONTINUE;
  }

  memset(&key, 0, sizeof(key));
  if (dp_parse_dns_qname(data, data_end, off, &key) < 0) {
    return DNS_POLICY_CONTINUE;
  }

  act = bpf_map_lookup_elem(&dns_trie_map, &key);
  if (act) {
    dp_do_map_stats(ctx, xf, LL_DP_DNS_STATS_MAP, act->ca.cidx);
    if (act->ca.act_type == DP_SET_DROP) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_FW_DRP);
      return DNS_POLICY_DROP;
    }
    if (act->ca.act_type == DP_SET_TOCP) {
      LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACL_TRAP);
      return DNS_POLICY_TRAP;
    }
  }

  return DNS_POLICY_CONTINUE;
}

#endif
