#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __bpf_fastcall
#if __has_attribute(bpf_fastcall)
#define __bpf_fastcall __attribute__((bpf_fastcall))
#else
#define __bpf_fastcall
#endif
#endif

typedef unsigned char __u8;

typedef __u8 u8;

typedef short unsigned int __u16;

typedef __u16 Elf32_Half;

typedef __u16 Elf64_Half;

typedef __u16 __be16;

typedef __u16 __sum16;

typedef __u16 u16;

typedef unsigned int __u32;

typedef __u32 Elf32_Addr;

typedef __u32 Elf32_Off;

typedef __u32 Elf32_Word;

typedef __u32 Elf64_Word;

typedef __u32 __be32;

typedef __u32 u32;

typedef __u32 __portpair;

typedef __u32 __wsum;

typedef int __s32;

typedef __s32 s32;

typedef long long unsigned int __u64;

typedef __u64 Elf64_Addr;

typedef __u64 Elf64_Off;

typedef __u64 Elf64_Xword;

typedef __u64 __addrpair;

typedef __u64 __be64;

typedef __u64 __le64;

typedef __u64 u64;

typedef long long int __s64;

typedef __s64 s64;


enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_AGGFRAG = 144,
	IPPROTO_RAW = 255,
	IPPROTO_SMC = 256,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

struct iphdr
{
    __u8 ihl : 4;
    __u8 version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    union
    {
        struct
        {
            __be32 saddr;
            __be32 daddr;
        };
        struct
        {
            __be32 saddr;
            __be32 daddr;
        } addrs;
    };
} __attribute__((__packed__));

struct tcphdr
{
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4;
    __u16 doff : 4;
    __u16 fin : 1;
    __u16 syn : 1;
    __u16 rst : 1;
    __u16 psh : 1;
    __u16 ack : 1;
    __u16 urg : 1;
    __u16 ece : 1;
    __u16 cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((__packed__));

struct udphdr
{
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((__packed__));

struct icmphdr
{
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union
    {
        struct
        {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct
        {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
} __attribute__((__packed__));

struct in6_addr
{
    union
    {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((__packed__));

struct ipv6hdr
{
    __u8 priority : 4;
    __u8 version : 4;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    union
    {
        struct
        {
            struct in6_addr saddr;
            struct in6_addr daddr;
        };
        struct
        {
            struct in6_addr saddr;
            struct in6_addr daddr;
        } addrs;
    };
} __attribute__((__packed__));

struct tcp_sock
{
    char fill_1[1008];
    u32 rcv_nxt; // dtwdebug /*  1008     4 */
    char fill_2[40];
    u32 snd_una; // dtwdebug /*  1052     4 */
    char fill_3[196];
    u32 packets_out; // dtwdebug /*  1252     4 */
    char fill_4[0];
    u32 retrans_out; // dtwdebug /*  1256     4 */
    char fill_5[468];
} __attribute__((__packed__));

struct timer_list
{
    char fill_1[8];
    unsigned long		expires; // offset =    8, size =    4
    char fill_2[8];
} __attribute__((__packed__));

struct inet_connection_sock
{
    char fill_1[740];
    unsigned long icsk_timeout;             /*  offset =  740, size =    4 */
    struct timer_list icsk_retransmit_timer; /*  offset =  744, size =   20 */
    char fill_2[61];
    __u8 icsk_retransmits; /*  offset =  825, size =    1 */
    __u8 icsk_pending;     /*  offset =  826, size =    1 */
    char fill_3[157];
} __attribute__((__packed__));

struct sock_common
{
    union
    {
        __addrpair skc_addrpair; /*     0     4 */
        struct
        {
            __be32 skc_daddr;     /*     0     4 */
            __be32 skc_rcv_saddr; /*     4     4 */
        };
    };
    char fill_1[4];
    union
    {
        __portpair skc_portpair; /*    12     2 */
        struct
        {
            __be16 skc_dport; /*    12     2 */
            __u16 skc_num;    /*    14     2 */
        };
    };
    short unsigned int skc_family;    /*    16     2 */
    volatile unsigned char skc_state; /*    18     1 */
    char fill_2[61];
    // struct in6_addr skc_v6_daddr;     /*    56    16 */
    // struct in6_addr skc_v6_rcv_saddr; /*    72    16 */
    // char fill_3[48];
} __attribute__((__packed__));

struct ip_esp_hdr
{
    __be32 spi;
    __be32 seq_no;
    __u8 enc_data[0];
};


struct tcp_skb_cb
{
    __u32 seq; /*     0     4 */
    char fill_1[8];
    __u8 tcp_flags; /*    12     1 */
    char fill_2[35];
} __attribute__((__packed__));

struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((__packed__));

struct __sk_buff
{
    char fill_1[76];
    __u32 data;     /*    76     4 */
    __u32 data_end; /*    80     4 */
    char fill_2[108];
} __attribute__((__packed__));

struct netdev_queue
{
    char fill_1[72];
    unsigned long trans_start; /*   72     4 */
    unsigned long state;       /*   76     4 */
    char fill_2[176];
} __attribute__((__packed__));

struct net_device
{
    char name[16]; /*   0    16 */
    char fill_1[112];
    int ifindex; /*   128     4 */
    char fill_2[1276];
} __attribute__((__packed__));

struct nf_hook_state
{
    u8 hook; /*     0     1 */
    u8 pf;   /*     1     1 */
} __attribute__((__packed__));

struct qdisc_skb_head
{
    char fill_1[8];
    __u32 qlen; /*    8     4 */
    char fill_2[4];
} __attribute__((__packed__));

struct Qdisc
{
    char fill_1[8];
    unsigned int flags; /*    8     4 */
    char fill_2[28];
    struct netdev_queue *dev_queue; /*    40     4 */
    char fill_3[36];
    struct qdisc_skb_head q; /*   80    16 */
    char fill_4[160];
} __attribute__((__packed__));

typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);

struct nf_hook_entry {
	nf_hookfn			*hook;
	void				*priv;
};

struct nf_hook_entries
{
    u16 num_hook_entries;
    struct nf_hook_entry hooks[0];
} ;

struct pt_regs {
	unsigned long uregs[18];
};

struct sk_buff
{
    union
    {
        struct
        {
            struct sk_buff *next;
            struct sk_buff *prev;
            union
            {
                struct net_device *dev; /*    8     4 */
            };
        };
    };
    struct sock *sk; /*    12     4 */
    char fill_0[8];
    char cb[48]; /*    24    48 */
    char fill_1[40];
    union
    {
        struct
        {
            // char fill_2[20];
            int skb_iif; /*   112     4 */
            char fill_3[24];
            __be16 protocol;        /*   140     2 */
            __u16 transport_header; /*   142     2 */
            __u16 network_header;   /*   144     2 */
            __u16 mac_header;       /*   146     2 */
        };
        struct
        {
            // char fill_2[20];
            int skb_iif; /*   112     4 */
            char fill_3[24];
            __be16 protocol;        /*   140     2 */
            __u16 transport_header; /*   142     2 */
            __u16 network_header;   /*   144     2 */
            __u16 mac_header;       /*   146     2 */
        } headers;
    };
    char fill_4[8];
    unsigned char *head; /*   156     4 */
    char fill_5[16];
} __attribute__((__packed__));

struct sk_buff_head
{
    char fill_1[8];
    __u32 qlen; /*    8     4 */
    char fill_2[4];
} __attribute__((__packed__));

struct sock;

struct socket
{
    char fill_1[16];
    struct sock *sk; /*    16     4 */
    char fill_2[108];
} __attribute__((__packed__));

struct sock_common;

struct sock
{
    struct sock_common __sk_common; /*     0   80 */
    char fill_1[56];
    struct sk_buff_head sk_receive_queue; /*   136    16 */
    char fill_2[76];
    struct sk_buff_head sk_write_queue; /*   228    16 */
    char fill_3[96];
    u16 sk_protocol; /*   340    2 */
    char fill_4[154];
} __attribute__((__packed__));

#endif