// SPDX-License-Identifier: MulanPSL-2.0
#if !defined(BPF_MAKE_HEADERS)

#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/bpf.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/tcp.h>

#include <net/sch_generic.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>

#define bpf_tail_call dummy____bpf_tail_call
#define bpf_get_stackid dummy____bpf_get_stackid
#include <net/tcp.h>
#undef bpf_tail_call
#undef bpf_get_stackid

#if defined(CONFIG_NF_TABLES) || defined(CONFIG_NF_TABLES_MODULE)
#include <net/netfilter/nf_tables.h>
#else
#define NT_DISABLE_NFT
#endif

#else
#define NT_DISABLE_NFT 1
#if defined(__TARGET_ARCH_x86)
#include "./progs/kheaders/x86/kheaders_x86.h"
#elif defined(__TARGET_ARCH_arm)
#include "./progs/kheaders/arm/kheaders_arm.h"
#elif defined(__TARGET_ARCH_arm64)
#include "./progs/vmlinux_arm64.h"
#elif defined(__TARGET_ARCH_loongarch)
#include "./progs/vmlinux_loongarch64.h"
#endif
#endif
