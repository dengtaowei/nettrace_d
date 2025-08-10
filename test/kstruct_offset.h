struct my_iphdr
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

struct my_tcphdr
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

struct my_udphdr
{
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((__packed__));

struct my_icmphdr
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

struct my_in6_addr
{
    union
    {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((__packed__));

struct my_ipv6hdr
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
            struct my_in6_addr saddr;
            struct my_in6_addr daddr;
        };
        struct
        {
            struct my_in6_addr saddr;
            struct my_in6_addr daddr;
        } addrs;
    };
} __attribute__((__packed__));

struct my_tcp_sock
{
    char fill_1[1476];
    u32 retrans_out; // dtwdebug /*  1476     4 */
    char fill_2[176];
    u32 rcv_nxt; // dtwdebug /*  1656     4 */
    char fill_3[4];
    u32 snd_una; // dtwdebug /*  1664     4 */
    char fill_4[8];
    u32 packets_out; // dtwdebug /*  1676     4 */
    char fill_5[624];
} __attribute__((__packed__));

struct my_timer_list
{
    char fill_1[16];
    long unsigned int expires; // dtwdebug /*    16     8 */
    char fill_2[16];
} __attribute__((__packed__));

struct my_inet_connection_sock
{
    char fill_1[1072];
    long unsigned int icsk_timeout;             /*  1072     8 */
    struct my_timer_list icsk_retransmit_timer; /*  1080    40 */
    char fill_2[105];
    __u8 icsk_retransmits; /*  1225     1 */
    __u8 icsk_pending;     /*  1226     1 */
    char fill_3[157];
} __attribute__((__packed__));

struct my_sock_common
{
    union
    {
        __addrpair skc_addrpair; /*     0     8 */
        struct
        {
            __be32 skc_daddr;     /*     0     4 */
            __be32 skc_rcv_saddr; /*     4     4 */
        };
    };
    char fill_1[4];
    union
    {
        __portpair skc_portpair; /*    12     4 */
        struct
        {
            __be16 skc_dport; /*    12     2 */
            __u16 skc_num;    /*    14     2 */
        };
    };
    short unsigned int skc_family;    /*    16     2 */
    volatile unsigned char skc_state; /*    18     1 */
    char fill_2[37];
    struct my_in6_addr skc_v6_daddr;     /*    56    16 */
    struct my_in6_addr skc_v6_rcv_saddr; /*    72    16 */
    char fill_3[48];
} __attribute__((__packed__));

struct my_ip_esp_hdr
{
    __be32 spi;
    __be32 seq_no;
    __u8 enc_data[0];
} __attribute__((__packed__));

struct my_tcp_skb_cb
{
    __u32 seq; /*     0     4 */
    char fill_1[8];
    __u8 tcp_flags; /*    12     1 */
    char fill_2[32];
} __attribute__((__packed__));

struct my_ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((__packed__));

struct my___sk_buff
{
    char fill_1[76];
    __u32 data;     /*    76     4 */
    __u32 data_end; /*    80     4 */
    char fill_2[108];
} __attribute__((__packed__));

struct my_netdev_queue
{
    char fill_1[200];
    long unsigned int trans_start; /*   200     8 */
    long unsigned int state;       /*   208     8 */
    char fill_2[168];
} __attribute__((__packed__));

struct my_net_device
{
    char fill_1[224];
    int ifindex; /*   224     4 */
    char fill_2[76];
    char name[16]; /*   304    16 */
    char fill_3[2192];
} __attribute__((__packed__));

struct my_nf_hook_state
{
    u8 hook; /*     0     1 */
    u8 pf;   /*     1     1 */
} __attribute__((__packed__));

struct my_qdisc_skb_head
{
    char fill_1[16];
    __u32 qlen; /*    16     4 */
    char fill_2[4];
} __attribute__((__packed__));

struct my_Qdisc
{
    char fill_1[16];
    unsigned int flags; /*    16     4 */
    char fill_2[44];
    struct my_netdev_queue *dev_queue; /*    64     8 */
    char fill_3[80];
    struct my_qdisc_skb_head q; /*   152    24 */
    char fill_4[208];
} __attribute__((__packed__));

typedef unsigned int my_nf_hookfn(void *, struct my_sk_buff *, const struct my_nf_hook_state *);

struct my_nf_hook_entry
{
    my_nf_hookfn *hook;
    void *priv;
} __attribute__((__packed__));

struct my_nf_hook_entries
{
    u16 num_hook_entries;
    struct my_nf_hook_entry hooks[0];
} __attribute__((__packed__));

struct my_pt_regs
{
    long unsigned int r15;
    long unsigned int r14;
    long unsigned int r13;
    long unsigned int r12;
    long unsigned int bp;
    long unsigned int bx;
    long unsigned int r11;
    long unsigned int r10;
    long unsigned int r9;
    long unsigned int r8;
    long unsigned int ax;
    long unsigned int cx;
    long unsigned int dx;
    long unsigned int si;
    long unsigned int di;
    long unsigned int orig_ax;
    long unsigned int ip;
} __attribute__((__packed__));

struct my_sk_buff
{
    union
    {
        struct
        {
            struct my_sk_buff *next;
            struct my_sk_buff *prev;
            union
            {
                struct my_net_device *dev; /*    16     8 */
            };
        };
    };
    struct my_sock *sk; /*    24     8 */
    char fill_0[8];
    char cb[48]; /*    40    48 */
    char fill_1[40];
    union
    {
        struct
        {
            char fill_2[20];
            int skb_iif; /*   148     4 */
            char fill_3[28];
            __be16 protocol;        /*   180     2 */
            __u16 transport_header; /*   182     2 */
            __u16 network_header;   /*   184     2 */
            __u16 mac_header;       /*   186     2 */
        };
        struct
        {
            char fill_2[20];
            int skb_iif; /*   148     4 */
            char fill_3[28];
            __be16 protocol;        /*   180     2 */
            __u16 transport_header; /*   182     2 */
            __u16 network_header;   /*   184     2 */
            __u16 mac_header;       /*   186     2 */
        } headers;
    };
    char fill_4[12];
    unsigned char *head; /*   200     8 */
    char fill_5[24];
} __attribute__((__packed__));

struct my_sk_buff_head
{
    char fill_1[16];
    __u32 qlen; /*    16     4 */
    char fill_2[4];
} __attribute__((__packed__));

struct my_sock;

struct my_socket
{
    char fill_1[24];
    struct my_sock *sk; /*    24     8 */
    char fill_2[96];
} __attribute__((__packed__));

struct my_sock_common;

struct my_sock
{
    struct my_sock_common __sk_common; /*     0   136 */
    char fill_1[80];
    struct my_sk_buff_head sk_receive_queue; /*   216    24 */
    char fill_2[120];
    struct my_sk_buff_head sk_write_queue; /*   360    24 */
    char fill_3[128];
    unsigned int __sk_flags_offset[0]; /*   512    0 */
    char fill_4[248];
} __attribute__((__packed__));