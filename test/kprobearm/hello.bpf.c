#include "/home/anlan/Desktop/nettrace_d/src/progs/kheaders/arm/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "hello.h"

#define CONFIG_MAP_SIZE	1024
#define MAX_ENTRIES 256

#ifdef INLINE_MODE
#undef inline
#define inline inline __attribute__((always_inline))
#define auto_inline inline
#else
#define auto_inline
#endif

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 512);
} m_stats SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1024);
} m_ret SEC(".maps");

typedef struct {
	u16 func1;
	u16 func2;
	u32 ts1;
	u32 ts2;
} match_val_t;

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(match_val_t));
} m_matched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_ENTRIES);
} m_event SEC(".maps");


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

#define TRACE_MAX 160

typedef struct {
	u32	saddr;
	u32	daddr;
	u32	addr;
	u32	pkt_len_1;
	u32	pkt_len_2;
	u32	pad0;
	u32	saddr_v6[4];
	u32	daddr_v6[4];
	u32	addr_v6[4];
	u16	sport;
	u16	dport;
	u16	port;
	u16	l3_proto;
	u8	l4_proto;
	u8	tcp_flags;
	u8	saddr_v6_enable:1,
		daddr_v6_enable:1,
		addr_v6_enable:1;

#ifdef BPF_DEBUG
	bool	bpf_debug;
#endif
} pkt_args_t;

typedef struct {
	pkt_args_t pkt;
	u32  trace_mode;
	u32  pid;
	u32  netns;
	u32  max_event;
	bool drop_reason;
	bool detail;
	bool hooks;
	bool ready;
	bool stack;
	bool tiny_output;
	bool has_filter;
	bool latency_summary;
	bool func_stats;
	bool match_mode;
	bool latency_free;
	u32  first_rtt;
	u32  last_rtt;
	u32  rate_limit;
	u32  latency_min;
	int  __rate_limit;
	u64  __last_update;
	u8   trace_status[TRACE_MAX];
	u64  event_count;
} bpf_args_t;

#define be16 u16
#define be32 u32

#define ETH_ALEN	6


typedef struct {
	u16	sport;
	u16	dport;
} l4_min_t;

typedef struct {
	u64	ts;
	union {
		struct {
			u32	saddr;
			u32	daddr;
		} ipv4;
#ifndef NT_DISABLE_IPV6
		struct {
			u8	saddr[16];
			u8	daddr[16];
		} ipv6;
#endif
	} l3;
	union {
		struct {
			be16	sport;
			be16	dport;
			u32	seq;
			u32	ack;
			u8	flags;
		} tcp;
		struct {
			be16	sport;
			be16	dport;
		} udp;
		l4_min_t min;
		struct {
			u8	type;
			u8	code;
			u16	seq;
			u16	id;
		} icmp;
		struct {
			u16	op;
			u8	source[ETH_ALEN];
			u8	dest[ETH_ALEN];
		} arp_ext;
		struct
		{
			u32 spi;
			u32 seq;
		} espheader;
#define field_udp l4.udp
	} l4;
	u16 proto_l3;
	u8 proto_l4;
	u8 pad;
} packet_t;

typedef struct {
	u64	ts;
	union {
		struct {
			u32	saddr;
			u32	daddr;
		} ipv4;
#if 0
		struct {
			u8	saddr[16];
			u8	daddr[16];
		} ipv6;
#endif
	} l3;
	union {
		struct {
			be16	sport;
			be16	dport;
			u32	packets_out;
			u32	retrans_out;
			u32	snd_una;
		} tcp;
		struct {
			be16	sport;
			be16	dport;
		} udp;
		l4_min_t min;
	} l4;
	u32 timer_out;
	u32 wqlen;
	u32 rqlen;
	u16 proto_l3;
	u8 proto_l4;
	u8 timer_pending;
	u8 state;
	u8 ca_state;
} sock_t;


typedef struct {
	u16		meta;
	u16		func;
	u32		key;
	union {
		packet_t	pkt;
		sock_t		ske;
	};
	union {
		/* For FEXIT program only for now */
		u64	retval;
		struct {
			u16 latency_func1;
			u16 latency_func2;
			u32 latency;
		};
	};
#ifdef __F_STACK_TRACE
	u32		stack_id;
#endif
	u32		pid;
	int		__event_filed[0];
} event_t;

typedef struct {
	/* the bpf context args */
	void *ctx;
	struct sk_buff *skb;
	struct sock *sk;
	event_t *e;
	/* the filter condition stored in map */
	bpf_args_t *args;
	union {
		/* used by fexit to pass the retval to event */
		u64 retval;
		/* match only used in context mode, no conflict with retval */
		match_val_t match_val;
		u32 matched;
	};
	u16 func;
	u8  func_status;
	/* don't output the event for this skb */
	u8  no_event:1;
} context_info_t;


static __always_inline int check_rate_limit(bpf_args_t *args)
{
	u64 last_ts = args->__last_update, ts = 0;
	int budget = args->__rate_limit;
	int limit = args->rate_limit;

	if (!limit)
		return 0;

	if (!last_ts) {
		last_ts = bpf_ktime_get_ns();
		args->__last_update = last_ts;
	}

	if (budget <= 0) {
		ts = bpf_ktime_get_ns();
		budget = (((ts - last_ts) / 1000000) * limit) / 1000;  // 不知道为什么，有这一行arm32加载失败
		budget = budget < limit ? budget : limit;
		if (budget <= 0)
			return -1;
		args->__last_update = ts;
	}

	budget--;
	args->__rate_limit = budget;

	return 0;
}



static __always_inline u8 get_func_status(bpf_args_t *args, u16 func)
{
	if (func >= TRACE_MAX)
		return 0;

	return args->trace_status[func];
}

typedef enum trace_mode {
	TRACE_MODE_BASIC,
	TRACE_MODE_DROP,
	TRACE_MODE_TIMELINE,
	TRACE_MODE_DIAG,
	TRACE_MODE_SOCK,
	TRACE_MODE_MONITOR,
	TRACE_MODE_RTT,
	TRACE_MODE_LATENCY,
	/* following is some fake mode */
	TRACE_MODE_TINY = 16,
} trace_mode_t;

#define TRACE_MODE_BASIC_MASK		(1 << TRACE_MODE_BASIC)
#define TRACE_MODE_TIMELINE_MASK	(1 << TRACE_MODE_TIMELINE)
#define TRACE_MODE_DIAG_MASK		(1 << TRACE_MODE_DIAG)
#define TRACE_MODE_DROP_MASK		(1 << TRACE_MODE_DROP)
#define TRACE_MODE_SOCK_MASK		(1 << TRACE_MODE_SOCK)
#define TRACE_MODE_MONITOR_MASK		(1 << TRACE_MODE_MONITOR)
#define TRACE_MODE_RTT_MASK		(1 << TRACE_MODE_RTT)
#define TRACE_MODE_LATENCY_MASK		(1 << TRACE_MODE_LATENCY)
#define TRACE_MODE_TINY_MASK		(1 << TRACE_MODE_TINY)

#define TRACE_MODE_BPF_CTX_MASK		\
	(TRACE_MODE_DIAG_MASK | TRACE_MODE_TIMELINE_MASK |	\
	 TRACE_MODE_LATENCY_MASK)
#define TRACE_MODE_CTX_MASK		\
	(TRACE_MODE_DIAG_MASK | TRACE_MODE_TIMELINE_MASK)

static inline bool mode_has_context(bpf_args_t *args)
{
	return args->trace_mode & TRACE_MODE_BPF_CTX_MASK;
}

static __always_inline void update_stats_key(u32 key)
{
	u64 *stats = bpf_map_lookup_elem(&m_stats, &key);

	if (stats)
		(*stats)++;
}

#define FUNC_STATUS_FREE	(1 << 0)
#define FUNC_STATUS_SK		(1 << 1)
#define FUNC_STATUS_MATCHER	(1 << 3)
#define FUNC_STATUS_STACK	(1 << 4)
#define FUNC_STATUS_RET		(1 << 5)
#define FUNC_STATUS_CFREE	(1 << 6) /* custom skb free function */


static inline bool func_is_free(u8 status)
{
	return status & (FUNC_STATUS_FREE | FUNC_STATUS_CFREE);
}

static inline void consume_map_ctx(bpf_args_t *args, void *key)
{
	bpf_map_delete_elem(&m_matched, key);
	args->event_count++;
}


typedef struct {
	u16 meta;
	u16 func;
	u32 key;
	u64 ts;
} tiny_event_t;

#define EVENT_OUTPUT_PTR(ctx, data, size)			\
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,	\
			      data, size)
#define EVENT_OUTPUT(ctx, data)					\
	EVENT_OUTPUT_PTR(ctx, &data, sizeof(data))

enum {
	FUNC_TYPE_FUNC,
	FUNC_TYPE_RET,
	FUNC_TYPE_TINY,
	FUNC_TYPE_TRACING_RET,
	FUNC_TYPE_MAX,
};

#define _L(dst, src) bpf_probe_read_kernel(dst, sizeof(*src), src)
#define _(src)							\
({								\
	typeof(src) ____tmp;					\
	_L(&____tmp, &src);					\
	____tmp;						\
})

static inline void handle_tiny_output(context_info_t *info)
{
	tiny_event_t e = {
		.func = info->func,
		.meta = FUNC_TYPE_TINY,
#ifdef __PROG_TYPE_TRACING
		.key = (u64)(void *)_(info->skb),
#else
		.key = (u64)(void *)info->skb,
#endif
		.ts = bpf_ktime_get_ns(),
	};

	EVENT_OUTPUT(info->ctx, e);
}

static __always_inline u64 get_ret_key(int func)
{
	return (bpf_get_current_pid_tgid() << 32) + func;
}

static inline void get_ret(context_info_t *info)
{
	int *ref;
	u64 key;

	if (!(info->func_status & FUNC_STATUS_RET))
		return;

	key = get_ret_key(info->func);
	ref = bpf_map_lookup_elem(&m_ret, &key);
	if (!ref) {
		int v = 1;

		bpf_map_update_elem(&m_ret, &key, &v, 0);
		return;
	}
	(*ref)++;
}

static inline int pre_tiny_output(context_info_t *info)
{
	handle_tiny_output(info);
	if (func_is_free(info->func_status))
		consume_map_ctx(info->args, &info->skb);
	else
		get_ret(info);
	return 1;
}

static inline bool trace_mode_latency(bpf_args_t *args)
{
	return args->trace_mode & TRACE_MODE_LATENCY_MASK;
}

static inline bool func_is_cfree(u8 status)
{
	return status & FUNC_STATUS_CFREE;
}

static inline void free_map_ctx(bpf_args_t *args, void *key)
{
	bpf_map_delete_elem(&m_matched, key);
}

static __always_inline void update_stats_log(u32 val)
{
	u32 key = 0, i = 0, tmp = 2;

	#pragma clang loop unroll_count(16)
	for (; i < 16; i++) {
		if (val < tmp)
			break;
		tmp <<= 1;
		key++;
	}

	update_stats_key(key);
}

static inline void init_ctx_match(void *skb, u16 func, bool ts)
{
	match_val_t matched = {
		.ts1 = ts ? bpf_ktime_get_ns() / 1000 : 0,
		.func1 = func,
	};

	bpf_map_update_elem(&m_matched, &skb, &matched, 0);
}

static inline int pre_handle_latency(context_info_t *info,
				     match_val_t *match_val)
{
	bpf_args_t *args = (void *)info->args;
	u32 delta;

	if (match_val) {
		if (args->latency_free || !func_is_free(info->func_status) ||
		    func_is_cfree(info->func_status)) {
			match_val->ts2 = bpf_ktime_get_ns() / 1000;
			match_val->func2 = info->func;
		}

		/* reentry the matcher, or the free of skb is not traced. */
		if (info->func_status & FUNC_STATUS_MATCHER &&
		    match_val->func1 == info->func)
			match_val->ts1 = bpf_ktime_get_ns() / 1000;  // dtwdebug

		if (func_is_free(info->func_status)) {
			delta = match_val->ts2 - match_val->ts1;
			/* skip a single match function */
			if (!match_val->func2 || delta < args->latency_min) {
				free_map_ctx(info->args, &info->skb);
				return 1;
			}
			if (args->latency_summary) {
				update_stats_log(delta);
				consume_map_ctx(info->args, &info->skb);
				return 1;
			}
			info->match_val = *match_val;
			return 0;
		}
		return 1;
	} else {
		/* skip single free function for latency total mode */
		if (func_is_free(info->func_status))
			return 1;
		/* if there isn't any filter, skip handle_entry() */
		if (!args->has_filter) {
			init_ctx_match(info->skb, info->func, true);
			return 1;
		}
	}
	info->no_event = true;
	return 0;
}

static inline int pre_handle_entry(context_info_t *info, u16 func)
{
	bpf_args_t *args = (void *)info->args;
	int ret = 0;

	if (!args->ready || check_rate_limit(args)){
		bpf_printk("dtwdebug111 ret=%d !ready %d\n", ret, !args->ready);
		return -1;
	}

	if (args->max_event && args->event_count >= args->max_event){
		bpf_printk("dtwdebug222 ret=%d\n", ret);
		return -1;
	}

	info->func_status = get_func_status(info->args, func);
	if (mode_has_context(args)) {
		match_val_t *match_val = bpf_map_lookup_elem(&m_matched,
							     &info->skb);

		if (!match_val) {
			/* skip no-matcher function in match mode if it is not
			 * matched.
			 */
			if (args->match_mode &&
			    !(info->func_status & FUNC_STATUS_MATCHER))
				return -1;
			/* If the first function is a free, just ignore it. */
			if (func_is_free(info->func_status))
				return -1;
		}

		/* skip handle_entry() for tiny case */
		if (match_val && args->tiny_output) {
			ret = pre_tiny_output(info);
			bpf_printk("dtwdebug2 ret=%d\n", ret);
		}
		else if (trace_mode_latency(args)) {
			ret = pre_handle_latency(info, match_val);
			bpf_printk("dtwdebug3 ret=%d\n", ret);
		}
		else if (match_val) {
			info->match_val = *match_val;
		}
	}

	if (args->func_stats) {
		if (ret) {
			update_stats_key(func);
		} else if (!args->has_filter) {
			update_stats_key(func);
			args->event_count++;
			ret = 1;
			bpf_printk("dtwdebug4 ret=%d\n", ret);
		} else {
			info->no_event = true;
		}
	}
	bpf_printk("dtwdebug4 ret=%d\n", ret);
	return ret;
}


typedef struct {
	u16		meta;
	u16		func;
	u32		key;
	union {
		packet_t	pkt;
		sock_t		ske;
	};
	u64		retval;
#ifdef __F_STACK_TRACE
	u32		stack_id;
#endif
	u32		pid;
	/* fields above are exactly the same as event_t's, and the below
	 * fields are what we need to add for detail event.
	 */
	char		task[16];
	char		ifname[16];
	u32		ifindex;
	u32		netns;
	int		__event_filed[0];
} detail_event_t;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, CONFIG_MAP_SIZE);
	__uint(max_entries, 1);
} m_config SEC(".maps");


#define CONFIG() ({						\
	int _key = 0;						\
	void * _v = bpf_map_lookup_elem(&m_config, &_key);	\
	if (!_v)						\
		return 0; /* this can't happen */		\
	(pkt_args_t *)_v;					\
})

#ifdef BPF_DEBUG
#define pr_bpf_debug(fmt, args...) {				\
	if (CONFIG()->bpf_debug)				\
		bpf_printk("nettrace: "fmt"\n", ##args);	\
}
#else
#define pr_bpf_debug(fmt, ...)
#endif
#define pr_debug_skb(fmt, ...)	\
	pr_bpf_debug("skb=%llx, "fmt, (u64)(void *)skb, ##__VA_ARGS__)


#define args_check(args, attr, value) (args->attr && args->attr != value)


#undef _C
#ifdef NO_BTF
#define _C(src, f, ...)		BPF_PROBE_READ(src, f, ##__VA_ARGS__)
#define _LC(dst, src, f, ...)	BPF_PROBE_READ_INTO(dst, src, f, ##__VA_ARGS__)
#else
#define _C(src, f, ...)		BPF_CORE_READ(src, f, ##__VA_ARGS__)
#define _LC(dst, src, f, ...)	BPF_CORE_READ_INTO(dst, src, f, ##__VA_ARGS__)
#endif

#ifndef __F_DISABLE_SOCK

#if (!defined(NO_BTF) || defined(__F_SK_PRPTOCOL_LEGACY))
static __always_inline u8 sk_get_protocol(struct sock *sk)
{
	u32 flags = _(((u32 *)(&sk->__sk_flags_offset))[0]);
	u8 l4_proto;

#ifdef CONFIG_CPU_BIG_ENDIAN
	l4_proto = (flags << 8) >> 24;
#else
	l4_proto = (flags << 16) >> 24;
#endif
	return l4_proto;
}
#endif

static inline int filter_ipv4_check(pkt_args_t *args, u32 saddr,
					u32 daddr)
{
	if (!args)
		return 0;

	return (args->saddr && args->saddr != saddr) ||
	       (args->daddr && args->daddr != daddr) ||
	       (args->addr && args->addr != daddr && args->addr != saddr);
}

static inline bool is_ipv6_equal(void *addr1, void *addr2)
{
	return *(u64 *)addr1 == *(u64 *)addr2 &&
	       *(u64 *)(addr1 + 8) == *(u64 *)(addr2 + 8);
}

static inline int filter_ipv6_check(pkt_args_t *args, void *saddr, void *daddr)
{
	if (!args)
		return 0;

	return (args->saddr_v6_enable && !is_ipv6_equal(args->saddr_v6, saddr)) ||
	       (args->daddr_v6_enable && !is_ipv6_equal(args->daddr_v6, daddr)) ||
	       (args->addr_v6_enable && !is_ipv6_equal(args->addr_v6, daddr) &&
				 !is_ipv6_equal(args->addr_v6, saddr));
}

/* used to do basic filter */
#define filter_enabled(args, attr)					\
	(args && args->attr)
#define filter_check(args, attr, value)					\
	(filter_enabled(args, attr) && args->attr != value)
#define filter_any_enabled(args, attr)					\
	(args && (args->attr || args->s##attr ||	\
		       args->d##attr))

static inline int filter_port(pkt_args_t *args, u32 sport, u32 dport)
{
	if (!args)
		return 0;

	return (args->sport && args->sport != sport) ||
	       (args->dport && args->dport != dport) ||
	       (args->port && args->port != dport && args->port != sport);
}

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif
typedef __u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

#define BPF_LOCAL_FUNC_MAPPER(FN, args...)	\
	FN(jiffies64, ##args)			\
	FN(get_func_ret, ##args)

#define FN(name) BPF_LOCAL_FUNC_##name,
enum {
	BPF_LOCAL_FUNC_MAPPER(FN)
	BPF_LOCAL_FUNC_MAX,
};
#undef FN

#ifndef BPF_NO_GLOBAL_DATA
const volatile bool bpf_func_exist[BPF_LOCAL_FUNC_MAX] = {0};

/* TRACING is not supported by libbpf_probe_bpf_helper, so fallback with the
 * CO-RE checking.
 */

#ifndef BPF_NO_GLOBAL_DATA
#ifdef __PROG_TYPE_TRACING
#define bpf_core_helper_exist(name) \
	bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_##name)
#else
#define bpf_core_helper_exist(name) bpf_func_exist[BPF_LOCAL_FUNC_##name]
#endif
#else
#define bpf_core_helper_exist(name) false
#endif

#ifdef __PROG_TYPE_TRACING
#define bpf_core_helper_exist(name) \
	bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_##name)
#else
#define bpf_core_helper_exist(name) bpf_func_exist[BPF_LOCAL_FUNC_##name]
#endif
#else
#define bpf_core_helper_exist(name) false
#endif

#ifndef BPF_NO_GLOBAL_DATA
#ifdef __PROG_TYPE_TRACING
#define bpf_core_helper_exist(name) \
	bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_##name)
#else
#define bpf_core_helper_exist(name) bpf_func_exist[BPF_LOCAL_FUNC_##name]
#endif
#else
#define bpf_core_helper_exist(name) false
#endif

#ifndef BPF_NO_GLOBAL_DATA
#ifdef __PROG_TYPE_TRACING
#define bpf_core_helper_exist(name) \
	bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_##name)
#else
#define bpf_core_helper_exist(name) bpf_func_exist[BPF_LOCAL_FUNC_##name]
#endif
#else
#define bpf_core_helper_exist(name) false
#endif

static inline int probe_parse_sk(struct sock *sk, sock_t *ske,
				 pkt_args_t *args)
{
	struct inet_connection_sock *icsk;
	struct sock_common *skc;
	u8 saddr[16], daddr[16];
	unsigned long tmo;
	u16 l3_proto;
	u8 l4_proto;

	skc = (struct sock_common *)sk;
	switch (_C(skc, skc_family)) {
	case AF_INET:
		l3_proto = ETH_P_IP;
		ske->l3.ipv4.saddr = _C(skc, skc_rcv_saddr);
		ske->l3.ipv4.daddr = _C(skc, skc_daddr);
		if (filter_ipv4_check(args, ske->l3.ipv4.saddr,
				      ske->l3.ipv4.daddr))
			goto err;
		break;
	case AF_INET6:
		bpf_probe_read_kernel(saddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(daddr, 16, &skc->skc_v6_daddr);
		if (filter_ipv6_check(args, saddr, daddr))
			goto err;
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and 
		 * IPv6
		 */
		goto err;
	}
	if (filter_check(args, l3_proto, l3_proto))
		goto err;

#ifdef NO_BTF
#ifdef __F_SK_PRPTOCOL_LEGACY
	l4_proto = sk_get_protocol(sk);
#else
	l4_proto = _C(sk, sk_protocol);
#endif
#else
	if (bpf_core_field_size(sk->sk_protocol) == 2)
		l4_proto = _C(sk, sk_protocol);
	else
		l4_proto = sk_get_protocol(sk);
#endif

	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (filter_check(args, l4_proto, l4_proto))
		goto err;

	switch (l4_proto) {
	case IPPROTO_TCP: {
		struct tcp_sock *tp = (void *)sk;

		if (bpf_core_type_exists(struct tcp_sock)) {
			// ske->l4.tcp.packets_out = _C(tp, packets_out);  // dtwdebug
		// 	ske->l4.tcp.retrans_out = _C(tp, retrans_out);
		// 	ske->l4.tcp.snd_una = _C(tp, snd_una);
		} else {
		// 	ske->l4.tcp.packets_out = _(tp->packets_out);
		// 	ske->l4.tcp.retrans_out = _(tp->retrans_out);
		// 	ske->l4.tcp.snd_una = _(tp->snd_una);
		}
	}
	case IPPROTO_UDP:
		ske->l4.min.sport = bpf_htons(_C(skc, skc_num));
		ske->l4.min.dport = _C(skc, skc_dport);
		break;
	default:
		break;
	}

	if (filter_port(args, ske->l4.tcp.sport, ske->l4.tcp.dport))
		goto err;

	ske->rqlen = _C(sk, sk_receive_queue.qlen);
	ske->wqlen = _C(sk, sk_write_queue.qlen);

	ske->proto_l3 = l3_proto;
	ske->proto_l4 = l4_proto;
	ske->state = _C(skc, skc_state);

	if (!bpf_core_type_exists(struct inet_connection_sock))
		return 0;

	icsk = (void *)sk;
	// bpf_probe_read_kernel(&ske->ca_state, sizeof(u8),  // dtwdebug
	// 	(u8 *)icsk +
	// 	bpf_core_field_offset(struct inet_connection_sock,
	// 		icsk_retransmits) -
	// 	1);

	// if (bpf_core_helper_exist(jiffies64)) {  // dtwdebug
		// if (bpf_core_field_exists(icsk->icsk_timeout))
		// 	tmo = _C(icsk, icsk_timeout);
		// else
		// 	tmo = _C(icsk, icsk_retransmit_timer.expires);
		// ske->timer_out = tmo - (unsigned long)bpf_jiffies64();
	// }

	// ske->timer_pending = _C(icsk, icsk_pending);  // dtwdebug

	return 0;
err:
	return -1;
}

static inline bool skb_l4_was_set(u16 transport_header)
{
	return transport_header != (typeof(transport_header))~0U;
}

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#endif

static inline int probe_parse_l4(void *l4, packet_t *pkt, pkt_args_t *args)
{
	switch (pkt->proto_l4) {
	case IPPROTO_IP:
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);
		u8 flags;

		if (filter_port(args, sport, dport))
			return -1;

		flags = _(((u8 *)tcp)[13]);
		if (filter_enabled(args, tcp_flags) &&
		    !(flags & args->tcp_flags))
			return -1;

		pkt->l4.tcp.sport = sport;
		pkt->l4.tcp.dport = dport;
		pkt->l4.tcp.flags = flags;
		pkt->l4.tcp.seq = bpf_ntohl(_(tcp->seq));
		pkt->l4.tcp.ack = bpf_ntohl(_(tcp->ack_seq));
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);
	
		if (filter_port(args, sport, dport))
			return -1;

		pkt->l4.udp.sport = sport;
		pkt->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4;

		if (filter_any_enabled(args, port))
			return -1;
		pkt->l4.icmp.code = _(icmp->code);
		pkt->l4.icmp.type = _(icmp->type);
		// pkt->l4.icmp.seq = _(icmp->un.echo.sequence);  // dtwdebug
		// pkt->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	case IPPROTO_ESP: {
		struct ip_esp_hdr *esp_hdr = l4;
		if (filter_any_enabled(args, port))
			return -1;
		// pkt->l4.espheader.seq = _(esp_hdr->seq_no);
		// 	pkt->l4.espheader.spi = _(esp_hdr->spi);
		break;
	}
	default:
		if (filter_any_enabled(args, port))
			return -1;
	}
	return 0;
}

#define skb_cb(__skb) ((void *)(__skb) + bpf_core_field_offset(typeof(*__skb), cb))

/* Parse the IP from socket, and parse TCP/UDP from the header data if
 * transport header was set. Or, parse TCP/UDP from the skb_cb.
 */
static inline int probe_parse_skb_sk(struct sock *sk, struct sk_buff *skb,
				     packet_t *pkt, pkt_args_t *args,
				     parse_ctx_t *ctx)
{
	u16 l3_proto, trans_header;
	struct sock_common *skc;
	u8 l4_proto;

	skc = (struct sock_common *)sk;
	switch (_C(skc, skc_family)) {
	case AF_INET:
		l3_proto = ETH_P_IP;
		pkt->l3.ipv4.saddr = _C(skc, skc_rcv_saddr);
		pkt->l3.ipv4.daddr = _C(skc, skc_daddr);
		if (filter_ipv4_check(args, pkt->l3.ipv4.saddr,
				      pkt->l3.ipv4.daddr))
			return -1;
		break;
	case AF_INET6:
#ifndef NT_DISABLE_IPV6
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr, 16, &skc->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr, 16, &skc->skc_v6_daddr);
		if (filter_ipv6_check(args, pkt->l3.ipv6.saddr,
				      pkt->l3.ipv6.daddr))
			return -1;
#endif
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and 
		 * IPv6
		 */
		return -1;
	}
	if (filter_check(args, l3_proto, l3_proto))
		return -1;

#ifdef NO_BTF
#ifdef __F_SK_PRPTOCOL_LEGACY
	l4_proto = sk_get_protocol(sk);
#else
	l4_proto = _C(sk, sk_protocol);
#endif
#else
	if (bpf_core_field_size(sk->sk_protocol) == 2)
		l4_proto = _C(sk, sk_protocol);
	else
		l4_proto = sk_get_protocol(sk);
#endif

	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (filter_check(args, l4_proto, l4_proto))
		return -1;

	pkt->proto_l3 = l3_proto;
	pkt->proto_l4 = l4_proto;

	/* The TCP header is set, and we can parse it from the skb */
	trans_header = _C(skb, transport_header);
	if (skb_l4_was_set(trans_header)) {
		return probe_parse_l4(_C(skb, head) + trans_header,
				      pkt, args);
	}

	/* parse L4 information from the socket */
	switch (l4_proto) {
	case IPPROTO_TCP: {
		struct tcp_sock *tp = (void *)sk;
		struct tcp_skb_cb *cb;

		cb = skb_cb(skb);
		// pkt->l4.tcp.seq = _C(cb, seq); // dtwdebug
		// pkt->l4.tcp.flags = _C(cb, tcp_flags);
		// if (bpf_core_type_exists(struct tcp_sock))
		// 	pkt->l4.tcp.ack = _C(tp, rcv_nxt);
		// else
		// 	pkt->l4.tcp.ack = _(tp->rcv_nxt);
	}
	case IPPROTO_UDP:
		pkt->l4.min.sport = bpf_htons(_C(skc, skc_num));
		pkt->l4.min.dport = _C(skc, skc_dport);
		break;
	default:
		break;
	}

	return filter_port(args, pkt->l4.tcp.sport, pkt->l4.tcp.dport);
}

#else

static inline int probe_parse_sk(struct sock *sk, sock_t *ske, void *args)
{
	return -1;
}

static inline int probe_parse_skb_sk(struct sock *sk, struct sk_buff *skb,
				     packet_t *pkt, pkt_args_t *args,
				     parse_ctx_t *ctx)
{
	return -1;
}
#endif

#define ETH_HLEN	14		/* Total octets in header.	 */

static inline bool skb_l4_check(u16 l4, u16 l3)
{
	return !skb_l4_was_set(l4) || l4 <= l3;
}

#define TCP_H_LEN	(sizeof(struct tcphdr))
#define UDP_H_LEN	(sizeof(struct udphdr))
#define IP_H_LEN	(sizeof(struct iphdr))
#define ICMP_H_LEN	(sizeof(struct icmphdr))

static inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0x0F) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}

static inline int probe_parse_l3(struct sk_buff *skb, pkt_args_t *args,
				 packet_t *pkt, void *l3,
				 parse_ctx_t *ctx)
{
	u16 trans_header;
	void *l4 = NULL;

	trans_header = _C(skb, transport_header);
	if (!skb_l4_check(trans_header, ctx->network_header))
		l4 = ctx->data + trans_header;

	if (pkt->proto_l3 == ETH_P_IPV6) {
		struct ipv6hdr *ipv6 = l3;

		/* ipv4 address is set, skip ipv6 */
		if (filter_any_enabled(args, addr))
			return -1;

#ifndef NT_DISABLE_IPV6
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr, 16, &ipv6->saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr, 16, &ipv6->daddr);
		if (filter_ipv6_check(args, pkt->l3.ipv6.saddr,
				      pkt->l3.ipv6.daddr))
			return -1;
#endif
		pkt->proto_l4 = _(ipv6->nexthdr);
		l4 = l4 ?: l3 + sizeof(*ipv6);
	} else {
		struct iphdr *ipv4 = l3;
		u32 saddr, daddr, len;

		len = bpf_ntohs(_C(ipv4, tot_len));
		if (args && (args->pkt_len_1 || args->pkt_len_2)) {
			if (len < args->pkt_len_1 || len > args->pkt_len_2)
				return -1;
		}

		/* skip ipv4 if ipv6 is set */
		if (filter_any_enabled(args, addr_v6[0]))
			return -1;

		l4 = l4 ?: l3 + get_ip_header_len(_(((u8 *)l3)[0]));
		saddr = _(ipv4->saddr);
		daddr = _(ipv4->daddr);

		if (filter_ipv4_check(args, saddr, daddr))
			return -1;

		pkt->proto_l4 = _(ipv4->protocol);
		pkt->l3.ipv4.saddr = saddr;
		pkt->l3.ipv4.daddr = daddr;
	}

	if (filter_check(args, l4_proto, pkt->proto_l4))
		return -1;

	return probe_parse_l4(l4, pkt, args);
}

static __always_inline int probe_parse_skb(struct sk_buff *skb, struct sock *sk,
					   packet_t *pkt, pkt_args_t *args)
{
	parse_ctx_t __ctx, *ctx = &__ctx;
	u16 l3_proto;
	void *l3;

	ctx->network_header = _C(skb, network_header);
	ctx->mac_header = _C(skb, mac_header);
	ctx->data = _C(skb, head);

	pr_debug_skb("begin to parse, nh=%d mh=%d", ctx->network_header,
		     ctx->mac_header);
	if (skb_l2_check(ctx->mac_header)) {
		int family;

		sk = sk ?: _C(skb, sk);
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

		if (!ctx->network_header) {
			if (!sk)
				return -1;
			return probe_parse_skb_sk(sk, skb, pkt, args, ctx);
		}

		l3_proto = bpf_ntohs(_C(skb, protocol));
		if (!l3_proto) {
			/* try to parse l3 protocol from the socket */
			if (!sk)
				return -1;
			family = _C((struct sock_common *)sk, skc_family);
			if (family == AF_INET)
				l3_proto = ETH_P_IP;
			else if (family == AF_INET6)
				l3_proto = ETH_P_IPV6;
			else
				return -1;
		}
		l3 = ctx->data + ctx->network_header;
	} else if (ctx->network_header && ctx->mac_header >= ctx->network_header) {
		/* For tun device, mac header is the same to network header.
		 * For this case, we assume that this is a IP packet.
		 *
		 * For vxlan device, mac header may be inner mac, and the
		 * network header is outer, which make mac > network.
		 */
		l3 = ctx->data + ctx->network_header;
		l3_proto = ETH_P_IP;
	} else {
		/* mac header is set properly, we can use it directly. */
		struct ethhdr *eth = ctx->data + ctx->mac_header;

		l3 = (void *)eth + ETH_HLEN;
		l3_proto = bpf_ntohs(_(eth->h_proto));
	}
	bpf_printk("dtwdebug  aaaaa\n");
	if (args) {
		bpf_printk("dtwdebug args->l3_proto = %x, l3_proto = %x\n", 
			args->l3_proto, l3_proto);
		if (args->l3_proto) {
			if (args->l3_proto != l3_proto)
				return -1;
		} else if (args->l4_proto) {
			/* Only IPv4 and IPv6 support L4 protocol filter */
			if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
				return -1;
		}
	}

	pkt->proto_l3 = l3_proto;
	pr_debug_skb("l3=%d", l3_proto);

	switch (l3_proto) {
	case ETH_P_IPV6:
	case ETH_P_IP:
		return probe_parse_l3(skb, args, pkt, l3, ctx);
	case ETH_P_ARP:
		// return probe_parse_arp(l3, pkt, args);
	default:
		return 0;
	}
}

static inline int filter_by_netns(context_info_t *info)
{	
	return 0;
}

#ifdef __F_STACK_TRACE
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");
#endif

#ifdef __F_STACK_TRACE
static inline void try_trace_stack(context_info_t *info)
{
	if (!info->args->stack || !(info->func_status & FUNC_STATUS_STACK))
		return;

	info->e->stack_id = bpf_get_stackid(info->ctx, &m_stack, 0);
}
#else
static inline void try_trace_stack(context_info_t *info) { }
#endif

static inline void try_set_latency(bpf_args_t *args, event_t *e,
				   match_val_t *val)
{
	if (!val->func1 || !trace_mode_latency(args))
		return;

	e->latency = val->ts2 - val->ts1;
	e->latency_func1 = val->func1;
	e->latency_func2 = val->func2;
}

static int auto_inline handle_entry(context_info_t *info)
{
	bpf_args_t *args = (void *)info->args;
	struct sk_buff *skb = info->skb;
	struct net_device *dev;
	detail_event_t *detail;
	event_t *e = info->e;
	pkt_args_t *pkt_args;
	bool mode_ctx, filter;
	packet_t *pkt;
	u32 pid;
	int err;

	pr_debug_skb("begin to handle, func=%d", info->func);
	pid = (u32)bpf_get_current_pid_tgid();
	mode_ctx = mode_has_context(args);
	filter = !info->matched;
	pkt_args = &args->pkt;
	pkt = &e->pkt;

	if (filter && args_check(args, pid, pid))
		goto err;

	/* why we call probe_parse_skb double times? because in the inline
	 * mode, 4.15 kernel will be confused with pkt_args.
	 */
	if (!filter) {
		if (!skb) {
			pr_bpf_debug("no skb available, func=%d", info->func);
			goto err;
		}
		probe_parse_skb(skb, info->sk, pkt, NULL);
		goto no_filter;
	}

	if (info->func_status & FUNC_STATUS_SK) {
		if (!info->sk) {
			pr_bpf_debug("no sock available, func=%d", info->func);
			goto err;
		}
		err = probe_parse_sk(info->sk, &e->ske, pkt_args);
	} else {
		if (!skb) {
			pr_bpf_debug("no skb available, func=%d", info->func);
			goto err;
		}
		// err = probe_parse_skb(skb, info->sk, pkt, pkt_args);  // dtwdebug
	}

	if (err)
		goto err;

no_filter:
	if (filter_by_netns(info) && filter)
		goto err;

	/* latency total mode with filter condition case */
	if (info->no_event)
		return 1;

	if (!args->detail)
		goto out;

	/* store more (detail) information about net or task. */
	dev = _C(skb, dev);
	detail = (void *)e;

	bpf_get_current_comm(detail->task, sizeof(detail->task));
	if (dev) {
		// bpf_core_read_str(detail->ifname, sizeof(detail->ifname) - 1,  // dtwdebug
		// 		  &dev->name);
		detail->ifindex = _C(dev, ifindex);
	} else {
		detail->ifindex = _C(skb, skb_iif);
		detail->ifname[0] = '\0';
	}

out:
	pr_debug_skb("pkt matched");
	try_trace_stack(info);
	pkt->ts = bpf_ktime_get_ns();
#ifdef __PROG_TYPE_TRACING
	e->key = (u64)(void *)_(skb);
#else
	e->key = (u64)(void *)skb;
#endif
	e->func = info->func;
	e->pid = pid;

	try_set_latency(args, e, &info->match_val);

#ifdef __PROG_TYPE_TRACING
	e->retval = info->retval;
#endif

	if (mode_ctx)
		get_ret(info);
	return 0;
err:
	return -1;
}

static __always_inline void do_event_output(context_info_t *info,
					    const int size)
{
	EVENT_OUTPUT_PTR(info->ctx, info->e, size);
}

static inline int default_handle_entry(context_info_t *info)
{
	bool detail = info->args->detail;
	detail_event_t __e;
#ifndef __F_INIT_EVENT
	int size;
#endif
	int err;

	info->e = (void *)&__e;

#ifndef __F_INIT_EVENT
	if (!detail) {
		size = sizeof(event_t);
		__builtin_memset(&__e, 0, size);
	} else {
		size = sizeof(__e);
		__builtin_memset(&__e, 0, size);
	}
#else
	/* the kernel of version 4.X can't spill const variable to stack,
	 * so we need to initialize the whole event.
	 */
	__builtin_memset(&__e, 0, sizeof(__e));
#endif

	err = handle_entry(info);
	if (!err) {
#ifdef __F_INIT_EVENT
#ifdef __F_OUTPUT_WHOLE
		/* output the whole detail event, as the compiler can save
		 * the size to stack sometimes.
		 */
		do_event_output(info, sizeof(__e));
#else
		do_event_output(info, detail ? sizeof(__e) : sizeof(event_t));
#endif
#else
		do_event_output(info, size);
#endif
	}
	return err;
}

static inline void handle_entry_finish(context_info_t *info, int err)
{
	if (err < 0)
		return;

	if (mode_has_context(info->args)) {
		if (func_is_free(info->func_status)) {
			if (info->matched)
				consume_map_ctx(info->args, &info->skb);
		} else if (!info->matched) {
			init_ctx_match(info->skb, info->func,
				       trace_mode_latency(info->args));
		}
	} else {
		info->args->event_count++;
	}

	if (info->args->func_stats)
		update_stats_key(info->func);
}

#define CONFIG_MAP_SIZE	1024

static inline int fake____netif_receive_skb_core(context_info_t *info);

SEC("tp/net/netif_receive_skb")
int __trace___netif_receive_skb_core(void *ctx) {

	context_info_t info = { 
		.func = 6, 
		.ctx = ctx, 
		.args = (void *)(
			{ 
				int _key = 0; 
				void * _v = bpf_map_lookup_elem(&m_config, &_key); 
				if (!_v) 
					return 0; 
				(pkt_args_t *)_v; 

			}), 
		.skb = *(void **)(ctx + 8) }; 
	if (pre_handle_entry(&info, 6)) {
		bpf_printk("dtwdebug1\n");
		return 0; 
	}
	handle_entry_finish(&info, fake____netif_receive_skb_core(&info)); 
	return 0; 
} 
static inline int fake____netif_receive_skb_core(context_info_t *info) {
	 return default_handle_entry(info); 
} 

char LICENSE[] SEC("license") = "Dual BSD/GPL";
