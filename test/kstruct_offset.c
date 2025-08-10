
#include "../src/progs/kheaders/x86/kheaders_x86.h"
#include <stdio.h>
#include "kstruct_offset.h"
#define offsetof(type, member) ((size_t)&(((type *)0)->member))

int main(int argc, char *argv[])
{
    printf("=============\nstruct tcp_sock: %ld\n", sizeof(struct tcp_sock));
    printf("struct tcp_sock.retrans_out: %ld\n", offsetof(struct tcp_sock, retrans_out));
    printf("struct tcp_sock.rcv_nxt: %ld\n", offsetof(struct tcp_sock, rcv_nxt));
    printf("struct tcp_sock.snd_una: %ld\n", offsetof(struct tcp_sock, snd_una));
    printf("struct tcp_sock.packets_out: %ld\n", offsetof(struct tcp_sock, packets_out));
    
    printf("=============\nstruct timer_list: %ld\n", sizeof(struct timer_list));
    printf("struct timer_list.expires: %ld\n", offsetof(struct timer_list, expires));

    printf("=============\nstruct inet_connection_sock: %ld\n", sizeof(struct inet_connection_sock));
    printf("struct inet_connection_sock.icsk_timeout: %ld\n", offsetof(struct inet_connection_sock, icsk_timeout));
    printf("struct inet_connection_sock.icsk_retransmit_timer: %ld\n", offsetof(struct inet_connection_sock, icsk_retransmit_timer));
    printf("struct inet_connection_sock.icsk_retransmits: %ld\n", offsetof(struct inet_connection_sock, icsk_retransmits));
    printf("struct inet_connection_sock.icsk_pending: %ld\n", offsetof(struct inet_connection_sock, icsk_pending));

    printf("=============\nstruct sock_common: %ld\n", sizeof(struct sock_common));
    printf("struct sock_common.skc_daddr: %ld\n", offsetof(struct sock_common, skc_daddr));
    printf("struct sock_common.skc_rcv_saddr: %ld\n", offsetof(struct sock_common, skc_rcv_saddr));
    printf("struct sock_common.skc_dport: %ld\n", offsetof(struct sock_common, skc_dport));
    printf("struct sock_common.skc_num: %ld\n", offsetof(struct sock_common, skc_num));
    printf("struct sock_common.skc_family: %ld\n", offsetof(struct sock_common, skc_family));
    printf("struct sock_common.skc_state: %ld\n", offsetof(struct sock_common, skc_state));
    printf("struct sock_common.skc_v6_daddr: %ld\n", offsetof(struct sock_common, skc_v6_daddr));
    printf("struct sock_common.skc_v6_rcv_saddr: %ld\n", offsetof(struct sock_common, skc_v6_rcv_saddr));

    printf("=============\nstruct tcp_skb_cb: %ld\n", sizeof(struct tcp_skb_cb));
    printf("struct tcp_skb_cb.seq: %ld\n", offsetof(struct tcp_skb_cb, seq));
    printf("struct tcp_skb_cb.tcp_flags: %ld\n", offsetof(struct tcp_skb_cb, tcp_flags));

    printf("=============\nstruct __sk_buff: %ld\n", sizeof(struct __sk_buff));
    printf("struct __sk_buff.data: %ld\n", offsetof(struct __sk_buff, data));
    printf("struct __sk_buff.data_end: %ld\n", offsetof(struct __sk_buff, data_end));

    printf("=============\nstruct netdev_queue: %ld\n", sizeof(struct netdev_queue));
    printf("struct netdev_queue.trans_start: %ld\n", offsetof(struct netdev_queue, trans_start));
    printf("struct netdev_queue.state: %ld\n", offsetof(struct netdev_queue, state));


    printf("=============\nstruct net_device: %ld\n", sizeof(struct net_device));
    printf("struct net_device.ifindex: %ld\n", offsetof(struct net_device, ifindex));
    printf("struct net_device.name: %ld\n", offsetof(struct net_device, name));

    printf("=============\nstruct qdisc_skb_head: %ld\n", sizeof(struct qdisc_skb_head));
    printf("struct qdisc_skb_head.qlen: %ld\n", offsetof(struct qdisc_skb_head, qlen));

    printf("=============\nstruct Qdisc: %ld\n", sizeof(struct Qdisc));
    printf("struct Qdisc.flags: %ld\n", offsetof(struct Qdisc, flags));
    printf("struct Qdisc.dev_queue: %ld\n", offsetof(struct Qdisc, dev_queue));
    printf("struct Qdisc.q: %ld\n", offsetof(struct Qdisc, q));

    printf("=============\nstruct sk_buff: %ld\n", sizeof(struct sk_buff));
    printf("struct sk_buff.dev: %ld\n", offsetof(struct sk_buff, dev));
    printf("struct sk_buff.sk: %ld\n", offsetof(struct sk_buff, sk));
    printf("struct sk_buff.cb: %ld\n", offsetof(struct sk_buff, cb));
    printf("struct sk_buff.skb_iif: %ld\n", offsetof(struct sk_buff, skb_iif));
    printf("struct sk_buff.protocol: %ld\n", offsetof(struct sk_buff, protocol));
    printf("struct sk_buff.transport_header: %ld\n", offsetof(struct sk_buff, transport_header));
    printf("struct sk_buff.network_header: %ld\n", offsetof(struct sk_buff, network_header));
    printf("struct sk_buff.mac_header: %ld\n", offsetof(struct sk_buff, mac_header));
    printf("struct sk_buff.head: %ld\n", offsetof(struct sk_buff, head));

    printf("=============\nstruct sk_buff_head: %ld\n", sizeof(struct sk_buff_head));
    printf("struct sk_buff_head.qlen: %ld\n", offsetof(struct sk_buff_head, qlen));

    printf("=============\nstruct socket: %ld\n", sizeof(struct socket));
    printf("struct socket.sk: %ld\n", offsetof(struct socket, sk));


    printf("=============\nstruct sock: %ld\n", sizeof(struct sock));
    printf("struct sock.__sk_common: %ld\n", offsetof(struct sock, __sk_common));
    printf("struct sock.sk_receive_queue: %ld\n", offsetof(struct sock, sk_receive_queue));
    printf("struct sock.sk_write_queue: %ld\n", offsetof(struct sock, sk_write_queue));
    printf("struct sock.__sk_flags_offset: %ld\n", offsetof(struct sock, __sk_flags_offset));

    /////////////////////////////////////////////////
    printf("=========================== my struct =================================\n");
    printf("=============\n struct my_tcp_sock: %ld\n", sizeof(struct my_tcp_sock));
    printf("struct my_tcp_sock.retrans_out: %ld\n", offsetof(struct my_tcp_sock, retrans_out));
    printf("struct my_tcp_sock.rcv_nxt: %ld\n", offsetof(struct my_tcp_sock, rcv_nxt));
    printf("struct my_tcp_sock.snd_una: %ld\n", offsetof(struct my_tcp_sock, snd_una));
    printf("struct my_tcp_sock.packets_out: %ld\n", offsetof(struct my_tcp_sock, packets_out));
    
    printf("=============\n struct my_timer_list: %ld\n", sizeof(struct my_timer_list));
    printf("struct my_timer_list.expires: %ld\n", offsetof(struct my_timer_list, expires));

    printf("=============\n struct my_inet_connection_sock: %ld\n", sizeof(struct my_inet_connection_sock));
    printf("struct my_inet_connection_sock.icsk_timeout: %ld\n", offsetof(struct my_inet_connection_sock, icsk_timeout));
    printf("struct my_inet_connection_sock.icsk_retransmit_timer: %ld\n", offsetof(struct my_inet_connection_sock, icsk_retransmit_timer));
    printf("struct my_inet_connection_sock.icsk_retransmits: %ld\n", offsetof(struct my_inet_connection_sock, icsk_retransmits));
    printf("struct my_inet_connection_sock.icsk_pending: %ld\n", offsetof(struct my_inet_connection_sock, icsk_pending));

    printf("=============\n struct my_sock_common: %ld\n", sizeof(struct my_sock_common));
    printf("struct my_sock_common.skc_daddr: %ld\n", offsetof(struct my_sock_common, skc_daddr));
    printf("struct my_sock_common.skc_rcv_saddr: %ld\n", offsetof(struct my_sock_common, skc_rcv_saddr));
    printf("struct my_sock_common.skc_dport: %ld\n", offsetof(struct my_sock_common, skc_dport));
    printf("struct my_sock_common.skc_num: %ld\n", offsetof(struct my_sock_common, skc_num));
    printf("struct my_sock_common.skc_family: %ld\n", offsetof(struct my_sock_common, skc_family));
    printf("struct my_sock_common.skc_state: %ld\n", offsetof(struct my_sock_common, skc_state));
    printf("struct my_sock_common.skc_v6_daddr: %ld\n", offsetof(struct my_sock_common, skc_v6_daddr));
    printf("struct my_sock_common.skc_v6_rcv_saddr: %ld\n", offsetof(struct my_sock_common, skc_v6_rcv_saddr));

    printf("=============\n struct my_tcp_skb_cb: %ld\n", sizeof(struct my_tcp_skb_cb));
    printf("struct my_tcp_skb_cb.seq: %ld\n", offsetof(struct my_tcp_skb_cb, seq));
    printf("struct my_tcp_skb_cb.tcp_flags: %ld\n", offsetof(struct my_tcp_skb_cb, tcp_flags));

    printf("=============\n struct my___sk_buff: %ld\n", sizeof(struct my___sk_buff));
    printf("struct my___sk_buff.data: %ld\n", offsetof(struct my___sk_buff, data));
    printf("struct my___sk_buff.data_end: %ld\n", offsetof(struct my___sk_buff, data_end));

    printf("=============\n struct my_netdev_queue: %ld\n", sizeof(struct my_netdev_queue));
    printf("struct my_netdev_queue.trans_start: %ld\n", offsetof(struct my_netdev_queue, trans_start));
    printf("struct my_netdev_queue.state: %ld\n", offsetof(struct my_netdev_queue, state));


    printf("=============\n struct my_net_device: %ld\n", sizeof(struct my_net_device));
    printf("struct my_net_device.ifindex: %ld\n", offsetof(struct my_net_device, ifindex));
    printf("struct my_net_device.name: %ld\n", offsetof(struct my_net_device, name));

    printf("=============\n struct my_qdisc_skb_head: %ld\n", sizeof(struct my_qdisc_skb_head));
    printf("struct my_qdisc_skb_head.qlen: %ld\n", offsetof(struct my_qdisc_skb_head, qlen));

    printf("=============\n struct my_Qdisc: %ld\n", sizeof(struct my_Qdisc));
    printf("struct my_Qdisc.flags: %ld\n", offsetof(struct my_Qdisc, flags));
    printf("struct my_Qdisc.dev_queue: %ld\n", offsetof(struct my_Qdisc, dev_queue));
    printf("struct my_Qdisc.q: %ld\n", offsetof(struct my_Qdisc, q));

    printf("=============\n struct my_sk_buff: %ld\n", sizeof(struct my_sk_buff));
    printf("struct my_sk_buff.dev: %ld\n", offsetof(struct my_sk_buff, dev));
    printf("struct my_sk_buff.sk: %ld\n", offsetof(struct my_sk_buff, sk));
    printf("struct my_sk_buff.cb: %ld\n", offsetof(struct my_sk_buff, cb));
    printf("struct my_sk_buff.skb_iif: %ld\n", offsetof(struct my_sk_buff, skb_iif));
    printf("struct my_sk_buff.protocol: %ld\n", offsetof(struct my_sk_buff, protocol));
    printf("struct my_sk_buff.transport_header: %ld\n", offsetof(struct my_sk_buff, transport_header));
    printf("struct my_sk_buff.network_header: %ld\n", offsetof(struct my_sk_buff, network_header));
    printf("struct my_sk_buff.mac_header: %ld\n", offsetof(struct my_sk_buff, mac_header));
    printf("struct my_sk_buff.head: %ld\n", offsetof(struct my_sk_buff, head));

    printf("=============\n struct my_sk_buff_head: %ld\n", sizeof(struct my_sk_buff_head));
    printf("struct my_sk_buff_head.qlen: %ld\n", offsetof(struct my_sk_buff_head, qlen));

    printf("=============\n struct my_socket: %ld\n", sizeof(struct my_socket));
    printf("struct my_socket.sk: %ld\n", offsetof(struct my_socket, sk));


    printf("=============\n struct my_sock: %ld\n", sizeof(struct my_sock));
    printf("struct my_sock.__sk_common: %ld\n", offsetof(struct my_sock, __sk_common));
    printf("struct my_sock.sk_receive_queue: %ld\n", offsetof(struct my_sock, sk_receive_queue));
    printf("struct my_sock.sk_write_queue: %ld\n", offsetof(struct my_sock, sk_write_queue));
    printf("struct my_sock.__sk_flags_offset: %ld\n", offsetof(struct my_sock, __sk_flags_offset));
    
    
    printf("test\n");
}