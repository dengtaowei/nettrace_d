// #include "vmlinux.h"
#include "/home/anlan/Desktop/nettrace_d/src/progs/kheaders/x86/kheaders_x86.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "hello.h"

// clang -E -target bpf -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -Wall -g hello.bpf.c -o hello.i

const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "do_execve";
const char fentry_msg[16] = "fentry_execve";
const char tp_msg[16] = "tp_execve";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
struct
{
   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
   __uint(key_size, sizeof(u32));
   __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, 10240);
   __type(key, u32);
   __type(value, struct msg_t);
} my_config SEC(".maps");


typedef struct {
	void *data;
	u16 mac_header;
	u16 network_header;
} parse_ctx_t;

static inline bool skb_l2_check(u16 header)
{
	return !header || header == (u16)~0U;
}

#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/

SEC("kprobe/dev_hard_start_xmit")
int __trace_dev_hard_start_xmit(struct pt_regs *ctx)
{
   struct sk_buff *skb = (struct sk_buff *)(((struct pt_regs*)ctx)->di);
   struct data_t data = {
       .command = "xmit"};

   parse_ctx_t __ctx, *lctx = &__ctx;
	u16 l3_proto;
	void *l3;
   struct sock *sk = NULL;

	lctx->network_header = BPF_PROBE_READ(skb, network_header);
   // lctx->network_header = (
   //    {
   //       typeof((skb)->network_header) __r;
   //       (
   //          {
   //             bpf_probe_read((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->network_header); 
   //          }
   //       ); __r; });

   // bpf_probe_read_kernel(&lctx->network_header, sizeof(lctx->network_header), &skb->network_header);
	lctx->mac_header = BPF_PROBE_READ(skb, mac_header);
	lctx->data = BPF_PROBE_READ(skb, head);
   l3_proto = bpf_ntohs(BPF_PROBE_READ(skb, protocol));

   if (skb_l2_check(lctx->mac_header)) {
		int family;

		sk = sk ?: BPF_PROBE_READ(skb, sk);
		/**
		 * try to parse skb for send path, which means that
		 * ether header doesn't exist in skb.
		 *
		 * 1. check the existing of network header. If any, parse
		 *    the header normally. Or, goto 2.
		 * 2. check the existing of transport If any, parse TCP
		 *    with data, and parse IP with the socket. Or, goto 3.
		 * 3. parse it with tcp_cb() and the socket.
		 */

		if (!lctx->network_header) {
			if (!sk)
				return -1;
			return 0;
		}

		if (!l3_proto) {
			/* try to parse l3 protocol from the socket */
			if (!sk)
				return -1;
			family = BPF_PROBE_READ((struct sock_common *)sk, skc_family);
			if (family == AF_INET)
				l3_proto = ETH_P_IP;
			else if (family == AF_INET6)
				l3_proto = ETH_P_IPV6;
			else
				return -1;
		}
		l3 = lctx->data + lctx->network_header;
	}

   bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_msg);
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.l3_proto = l3_proto;

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

SEC("tp/net/netif_receive_skb")
int __trace___netif_receive_skb_core(void *ctx)
{
   struct sk_buff * skb = (struct sk_buff *)*(void **)(ctx + 8);
   struct data_t data = {
       .command = "recv"};

   parse_ctx_t __ctx, *lctx = &__ctx;
	u16 l3_proto;
	void *l3;
   struct sock *sk = NULL;

	lctx->network_header = BPF_PROBE_READ(skb, network_header);
   // lctx->network_header = (
   //    {
   //       typeof((skb)->network_header) __r;
   //       (
   //          {
   //             bpf_probe_read((void *)(&__r), sizeof(*(&__r)), &((typeof(((skb))))(((skb))))->network_header); 
   //          }
   //       ); __r; });

   // bpf_probe_read_kernel(&lctx->network_header, sizeof(lctx->network_header), &skb->network_header);
	lctx->mac_header = BPF_PROBE_READ(skb, mac_header);
	lctx->data = BPF_PROBE_READ(skb, head);
   l3_proto = bpf_ntohs(BPF_PROBE_READ(skb, protocol));

   if (skb_l2_check(lctx->mac_header)) {
		int family;

		sk = sk ?: BPF_PROBE_READ(skb, sk);
		/**
		 * try to parse skb for send path, which means that
		 * ether header doesn't exist in skb.
		 *
		 * 1. check the existing of network header. If any, parse
		 *    the header normally. Or, goto 2.
		 * 2. check the existing of transport If any, parse TCP
		 *    with data, and parse IP with the socket. Or, goto 3.
		 * 3. parse it with tcp_cb() and the socket.
		 */

		if (!lctx->network_header) {
			if (!sk)
				return -1;
			return 0;
		}

		if (!l3_proto) {
			/* try to parse l3 protocol from the socket */
			if (!sk)
				return -1;
			family = BPF_PROBE_READ((struct sock_common *)sk, skc_family);
			if (family == AF_INET)
				l3_proto = ETH_P_IP;
			else if (family == AF_INET6)
				l3_proto = ETH_P_IPV6;
			else
				return -1;
		}
		l3 = lctx->data + lctx->network_header;
	}


   bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_msg);
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.l3_proto = l3_proto;

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
