
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

#define PRINT_MEMBER_OFFSET(struct_type, member)     \
    printk("%s::%-15s offset = %4zu, size = %4zu\n", \
           #struct_type, #member,                    \
           offsetof(struct_type, member),            \
           sizeof(((struct_type *)0)->member))

#define PRINT_STRUCT_SIZE(struct_type) \
    printk("=============\n%s: %zu\n", #struct_type, sizeof(struct_type));

static void print_skb_offsets(void)
{
    PRINT_STRUCT_SIZE(struct tcp_sock);
    PRINT_MEMBER_OFFSET(struct tcp_sock, retrans_out);
    PRINT_MEMBER_OFFSET(struct tcp_sock, rcv_nxt);
    PRINT_MEMBER_OFFSET(struct tcp_sock, snd_una);
    PRINT_MEMBER_OFFSET(struct tcp_sock, packets_out);

    PRINT_STRUCT_SIZE(struct timer_list);
    PRINT_MEMBER_OFFSET(struct timer_list, expires);

    PRINT_STRUCT_SIZE(struct inet_connection_sock);
    PRINT_MEMBER_OFFSET(struct inet_connection_sock, icsk_timeout);
    PRINT_MEMBER_OFFSET(struct inet_connection_sock, icsk_retransmit_timer);
    PRINT_MEMBER_OFFSET(struct inet_connection_sock, icsk_retransmits);
    PRINT_MEMBER_OFFSET(struct inet_connection_sock, icsk_pending);

    PRINT_STRUCT_SIZE(struct sock_common);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_daddr);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_rcv_saddr);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_dport);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_num);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_family);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_state);
#if IS_ENABLED(CONFIG_IPV6)
    PRINT_MEMBER_OFFSET(struct sock_common, skc_v6_daddr);
    PRINT_MEMBER_OFFSET(struct sock_common, skc_v6_rcv_saddr);
#endif

    PRINT_STRUCT_SIZE(struct tcp_skb_cb);
    PRINT_MEMBER_OFFSET(struct tcp_skb_cb, seq);
    PRINT_MEMBER_OFFSET(struct tcp_skb_cb, tcp_flags);

    PRINT_STRUCT_SIZE(struct __sk_buff);
    PRINT_MEMBER_OFFSET(struct __sk_buff, data);
    PRINT_MEMBER_OFFSET(struct __sk_buff, data_end);

    PRINT_STRUCT_SIZE(struct netdev_queue);
    PRINT_MEMBER_OFFSET(struct netdev_queue, trans_start);
    PRINT_MEMBER_OFFSET(struct netdev_queue, state);

    PRINT_STRUCT_SIZE(struct net_device);
    PRINT_MEMBER_OFFSET(struct net_device, ifindex);
    PRINT_MEMBER_OFFSET(struct net_device, name);

    PRINT_STRUCT_SIZE(struct qdisc_skb_head);
    PRINT_MEMBER_OFFSET(struct qdisc_skb_head, qlen);

    PRINT_STRUCT_SIZE(struct Qdisc);
    PRINT_MEMBER_OFFSET(struct Qdisc, flags);
    PRINT_MEMBER_OFFSET(struct Qdisc, dev_queue);
    PRINT_MEMBER_OFFSET(struct Qdisc, q);

    PRINT_STRUCT_SIZE(struct sk_buff);
    PRINT_MEMBER_OFFSET(struct sk_buff, dev);
    PRINT_MEMBER_OFFSET(struct sk_buff, sk);
    PRINT_MEMBER_OFFSET(struct sk_buff, cb);
    PRINT_MEMBER_OFFSET(struct sk_buff, skb_iif);
    PRINT_MEMBER_OFFSET(struct sk_buff, protocol);
    PRINT_MEMBER_OFFSET(struct sk_buff, transport_header);
    PRINT_MEMBER_OFFSET(struct sk_buff, network_header);
    PRINT_MEMBER_OFFSET(struct sk_buff, mac_header);
    PRINT_MEMBER_OFFSET(struct sk_buff, head);


    PRINT_STRUCT_SIZE(struct sk_buff_head);
    PRINT_MEMBER_OFFSET(struct sk_buff_head, qlen);


    PRINT_STRUCT_SIZE(struct socket);
    PRINT_MEMBER_OFFSET(struct socket, sk);

    PRINT_STRUCT_SIZE(struct sock);
    PRINT_MEMBER_OFFSET(struct sock, __sk_common);
    PRINT_MEMBER_OFFSET(struct sock, sk_receive_queue);
    PRINT_MEMBER_OFFSET(struct sock, sk_write_queue);
    PRINT_MEMBER_OFFSET(struct sock, sk_protocol);
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