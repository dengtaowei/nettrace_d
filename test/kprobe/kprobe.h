#ifndef _H_KPROBE
#define _H_KPROBE

#include <stdbool.h>

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef __u16 __le16;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

#define be16 u16
#define be32 u32

#define MAX_ENTRIES 256
#define CONFIG_MAP_SIZE	1024

#define ETH_ALEN	6
#define	ARPOP_REQUEST	1
#define	ARPOP_REPLY	2

#define TRACE_MAX 160



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
	/* open and initialize the bpf program */
	int (*trace_load)();
	/* load and attach the bpf program */
	int (*trace_attach)();
	void (*trace_poll)(void *ctx, int cpu, void *data, u32 size);
	int (*trace_anal)(event_t *e);
	void (*trace_close)();
	void (*trace_ready)();
	void (*print_stack)(int key);
	void (*trace_feat_probe)();
	bool (*trace_supported)();
	void (*prepare_traces)();
	int  (*raw_poll)();
	struct analyzer *analyzer;
} trace_ops_t;

typedef struct trace_args {
	bool timeline;
	bool ret;
	bool intel;
	bool intel_quiet;
	bool intel_keep;
	bool basic;
	bool monitor;
	bool drop;
	bool date;
	bool drop_stack;
	bool show_traces;
	bool sock;
	bool netns_current;
	bool force;
	bool latency_show;
	bool rtt;
	bool rtt_detail;
	bool latency;
	bool traces_noclone;
	u32  min_latency;
	char *traces;
	char *traces_stack;
	char *trace_matcher;
	char *trace_exclude;
	char *trace_free;
	char *pkt_len;
	char *tcp_flags;
	u32  count;
	char *btf_path;
} trace_args_t;

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

typedef struct {
	trace_ops_t	*ops;
	trace_args_t	args;
	bpf_args_t	bpf_args;
	trace_mode_t	mode;
	__u64		mode_mask;
	bool		stop;
	/* if drop reason feature is supported */
	bool		drop_reason;
	/* enable detail output */
	bool		detail;
	bool		skip_last;
	bool		trace_clone;
	struct bpf_object *obj;
	/* if reset reason feature is supported */
	bool 		reset_reason;
} trace_context_t;

#endif