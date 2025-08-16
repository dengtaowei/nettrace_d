
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <net/inet_connection_sock.h>
#include <net/sock.h>
#include <uapi/linux/bpf.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <net/sch_generic.h>
#include <net/tcp.h>

static void print_skb_offsets(void)
{
    printk("=============\nstruct tcp_sock: %zu\n", sizeof(struct tcp_sock));
    printk("struct tcp_sock.retrans_out: %zu\n", offsetof(struct tcp_sock, retrans_out));
    printk("struct tcp_sock.rcv_nxt: %zu\n", offsetof(struct tcp_sock, rcv_nxt));
    printk("struct tcp_sock.snd_una: %zu\n", offsetof(struct tcp_sock, snd_una));
    printk("struct tcp_sock.packets_out: %zu\n", offsetof(struct tcp_sock, packets_out));

    printk("=============\nstruct timer_list: %zu\n", sizeof(struct timer_list));
    printk("struct timer_list.expires: %zu\n", offsetof(struct timer_list, expires));

    printk("=============\nstruct inet_connection_sock: %zu\n", sizeof(struct inet_connection_sock));
    printk("struct inet_connection_sock.icsk_timeout: %zu\n", offsetof(struct inet_connection_sock, icsk_timeout));
    printk("struct inet_connection_sock.icsk_retransmit_timer: %zu\n", offsetof(struct inet_connection_sock, icsk_retransmit_timer));
    printk("struct inet_connection_sock.icsk_retransmits: %zu\n", offsetof(struct inet_connection_sock, icsk_retransmits));
    printk("struct inet_connection_sock.icsk_pending: %zu\n", offsetof(struct inet_connection_sock, icsk_pending));

    printk("=============\nstruct sock_common: %zu\n", sizeof(struct sock_common));
    printk("struct sock_common.skc_daddr: %zu\n", offsetof(struct sock_common, skc_daddr));
    printk("struct sock_common.skc_rcv_saddr: %zu\n", offsetof(struct sock_common, skc_rcv_saddr));
    printk("struct sock_common.skc_dport: %zu\n", offsetof(struct sock_common, skc_dport));
    printk("struct sock_common.skc_num: %zu\n", offsetof(struct sock_common, skc_num));
    printk("struct sock_common.skc_family: %zu\n", offsetof(struct sock_common, skc_family));
    printk("struct sock_common.skc_state: %zu\n", offsetof(struct sock_common, skc_state));
#if IS_ENABLED(CONFIG_IPV6)
    printk("struct sock_common.skc_v6_daddr: %zu\n", offsetof(struct sock_common, skc_v6_daddr));
    printk("struct sock_common.skc_v6_rcv_saddr: %zu\n", offsetof(struct sock_common, skc_v6_rcv_saddr));
#endif

    printk("=============\nstruct tcp_skb_cb: %zu\n", sizeof(struct tcp_skb_cb));
    printk("struct tcp_skb_cb.seq: %zu\n", offsetof(struct tcp_skb_cb, seq));
    printk("struct tcp_skb_cb.tcp_flags: %zu\n", offsetof(struct tcp_skb_cb, tcp_flags));

    printk("=============\nstruct __sk_buff: %zu\n", sizeof(struct __sk_buff));
    printk("struct __sk_buff.data: %zu\n", offsetof(struct __sk_buff, data));
    printk("struct __sk_buff.data_end: %zu\n", offsetof(struct __sk_buff, data_end));

    printk("=============\nstruct netdev_queue: %zu\n", sizeof(struct netdev_queue));
    printk("struct netdev_queue.trans_start: %zu\n", offsetof(struct netdev_queue, trans_start));
    printk("struct netdev_queue.state: %zu\n", offsetof(struct netdev_queue, state));

    printk("=============\nstruct net_device: %zu\n", sizeof(struct net_device));
    printk("struct net_device.ifindex: %zu\n", offsetof(struct net_device, ifindex));
    printk("struct net_device.name: %zu\n", offsetof(struct net_device, name));

    printk("=============\nstruct qdisc_skb_head: %zu\n", sizeof(struct qdisc_skb_head));
    printk("struct qdisc_skb_head.qlen: %zu\n", offsetof(struct qdisc_skb_head, qlen));

    printk("=============\nstruct Qdisc: %zu\n", sizeof(struct Qdisc));
    printk("struct Qdisc.flags: %zu\n", offsetof(struct Qdisc, flags));
    printk("struct Qdisc.dev_queue: %zu\n", offsetof(struct Qdisc, dev_queue));
    printk("struct Qdisc.q: %zu\n", offsetof(struct Qdisc, q));

    printk("=============\nstruct sk_buff: %zu\n", sizeof(struct sk_buff));
    printk("struct sk_buff.dev: %zu\n", offsetof(struct sk_buff, dev));
    printk("struct sk_buff.sk: %zu\n", offsetof(struct sk_buff, sk));
    printk("struct sk_buff.cb: %zu\n", offsetof(struct sk_buff, cb));
    printk("struct sk_buff.skb_iif: %zu\n", offsetof(struct sk_buff, skb_iif));
    printk("struct sk_buff.protocol: %zu\n", offsetof(struct sk_buff, protocol));
    printk("struct sk_buff.transport_header: %zu\n", offsetof(struct sk_buff, transport_header));
    printk("struct sk_buff.network_header: %zu\n", offsetof(struct sk_buff, network_header));
    printk("struct sk_buff.mac_header: %zu\n", offsetof(struct sk_buff, mac_header));
    printk("struct sk_buff.head: %zu\n", offsetof(struct sk_buff, head));

    printk("=============\nstruct sk_buff_head: %zu\n", sizeof(struct sk_buff_head));
    printk("struct sk_buff_head.qlen: %zu\n", offsetof(struct sk_buff_head, qlen));

    printk("=============\nstruct socket: %zu\n", sizeof(struct socket));
    printk("struct socket.sk: %zu\n", offsetof(struct socket, sk));

    printk("=============\nstruct sock: %zu\n", sizeof(struct sock));
    printk("struct sock.__sk_common: %zu\n", offsetof(struct sock, __sk_common));
    printk("struct sock.sk_receive_queue: %zu\n", offsetof(struct sock, sk_receive_queue));
    printk("struct sock.sk_write_queue: %zu\n", offsetof(struct sock, sk_write_queue));
    printk("struct sock.sk_protocol: %zu\n", offsetof(struct sock, sk_protocol));
}

static int __init skb_offset_init(void)
{
    print_skb_offsets();
    return 0;
}

static void __exit skb_offset_exit(void)
{
    pr_info("Module unloaded\n");
}

module_init(skb_offset_init);
module_exit(skb_offset_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Print sk_buff structure offsets");