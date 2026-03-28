/* SPDX-License-Identifier: GPL-2.0 */
/* Wicket sockmap BPF common definitions (stripped from volt) */

#ifndef __WICKET_SOCKMAP_COMMON_H__
#define __WICKET_SOCKMAP_COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_CONNECTIONS 500000

#define DEFINE_BPF_MAP_PERCPU(name, key_type, val_type, max_sz) \
    struct {                                                     \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                 \
        __type(key, key_type);                                   \
        __type(value, val_type);                                 \
        __uint(max_entries, max_sz);                             \
    } name SEC(".maps")

#endif /* __WICKET_SOCKMAP_COMMON_H__ */
