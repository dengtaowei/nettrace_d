#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <bpf/bpf.h>
#include "kprobe.h"
#include "kprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	// struct data_t *m = data;

	// printf("%-6d %-6d %-16s %-16s %s protocol: 0x%x\n", m->pid, m->uid, m->command, m->path, m->message, 
	// 	m->l3_proto);
	printf("user dtwdebug\n");
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

// int main()
// {
//     struct kprobe_bpf *skel;
// 	// struct bpf_object_open_opts *o;
//     int err;
// 	struct perf_buffer *pb = NULL;

// 	libbpf_set_print(libbpf_print_fn);

// 	char log_buf[2048 * 1024];
// 	LIBBPF_OPTS(bpf_object_open_opts, opts,
// 		.kernel_log_buf = log_buf,
// 		.kernel_log_size = sizeof(log_buf),
// 		.kernel_log_level = 1,
// 	);

// 	skel = kprobe_bpf__open_opts(&opts);
// 	if (!skel) {
// 		printf("Failed to open BPF object\n");
// 		return 1;
// 	}

// 	err = kprobe_bpf__load(skel);
// 	// Print the verifier log
// 	for (int i=0; i < sizeof(log_buf); i++) {
// 		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
// 			break;
// 		}
// 		printf("%c", log_buf[i]);
// 	}
	
// 	if (err) {
// 		printf("Failed to load BPF object\n");
// 		kprobe_bpf__destroy(skel);
// 		return 1;
// 	}

// 	// Attach the progams to the events
// 	err = kprobe_bpf__attach(skel);
// 	if (err) {
// 		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
// 		kprobe_bpf__destroy(skel);
//         return 1;
// 	}

//     int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "m_event");
// 	if (!map_fd)
// 		return -1;

// 	pb = perf_buffer__new(map_fd, 1024, handle_event,
// 			      lost_event, NULL, NULL);

// 	// pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
// 	if (!pb) {
// 		err = -1;
// 		fprintf(stderr, "Failed to create ring buffer\n");
// 		kprobe_bpf__destroy(skel);
//         return 1;
// 	}

// 	while (true) {
// 		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
// 		// Ctrl-C gives -EINTR
// 		if (err == -EINTR) {
// 			err = 0;
// 			break;
// 		}
// 		if (err < 0) {
// 			printf("Error polling perf buffer: %d\n", err);
// 			break;
// 		}
// 	}

// 	perf_buffer__free(pb);
// 	kprobe_bpf__destroy(skel);
// 	return -err;
// }

#include <sys/resource.h>

int liberate_l()
{
	struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &lim);
}

#define BPF_LOCAL_FUNC_MAPPER(FN, args...)	\
	FN(jiffies64, ##args)			\
	FN(get_func_ret, ##args)

#define FN(name) BPF_LOCAL_FUNC_##name,
enum {
	BPF_LOCAL_FUNC_MAPPER(FN)
	BPF_LOCAL_FUNC_MAX,
};
#undef FN

#define BPF_NO_GLOBAL_DATA

#ifndef BPF_NO_GLOBAL_DATA
#undef BPF_FUNC_CHECK
#define BPF_FUNC_CHECK(name, data, type)			\
data[BPF_LOCAL_FUNC_##name] = libbpf_probe_bpf_helper(type,	\
	BPF_FUNC_##name, NULL) == 1;

#define bpf_func_init(skel, type)				\
	BPF_LOCAL_FUNC_MAPPER(BPF_FUNC_CHECK, skel->rodata->bpf_func_exist, type)
#else
#define bpf_func_init(data, type)
#endif


#define bpf_set_config(skel, sec, value) do {		\
	int fd = bpf_map__fd(skel->maps.m_config);	\
	u8 buf[CONFIG_MAP_SIZE] = {};			\
	int key = 0;					\
							\
	if (fd < 0) {					\
		printf("failed to get config map: %d\n",\
		       fd);				\
		break;					\
	}						\
							\
	memcpy(buf, &value, sizeof(value));		\
	bpf_map_update_elem(fd, &key, buf, 0);		\
} while (0)

#define bpf_set_config_field(skel, sec, type, name, value) do { \
	int fd = bpf_map__fd(skel->maps.m_config);	\
	u8 buf[CONFIG_MAP_SIZE] = {};			\
	type *args = (void *)buf;			\
	int key = 0;					\
							\
	if (fd < 0) {					\
		printf("failed to get config map: %d\n",\
		       fd);				\
		break;					\
	}						\
							\
	bpf_map_lookup_elem(fd, &key, args);		\
	args->name = value;				\
	bpf_map_update_elem(fd, &key, args, 0);		\
} while (0)

int main()
{
	struct kprobe_bpf *skel;
	int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	if (liberate_l())
	{
		printf("failed to set rlimit\n");
	}

	static char log_buf[2048 * 1024];  // 这个 buffer 不能太小，要不然内核打日志的时候会显示 No space

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = NULL,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);
	// int i = 0;

	skel = kprobe_bpf__open_opts(&opts);
	if (!skel) {
		printf("failed to open kprobe-based eBPF\n");
		return -1;
	}
	printf("eBPF is opened successfully\n");

	/* set the max entries of perf event map to current cpu count */
	bpf_map__set_max_entries(skel->maps.m_event, get_nprocs_conf());
	bpf_func_init(skel, BPF_PROG_TYPE_KPROBE);

	err = kprobe_bpf__load(skel);

		// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	
	if (err) {
		printf("Failed to load BPF object\n");
		kprobe_bpf__destroy(skel);
		return 1;
	}

	bpf_args_t bpf_args;
	memset(&bpf_args, 0, sizeof(bpf_args));

	bpf_args.trace_mode = 4;
	bpf_args.drop_reason = 1;
	bpf_args.has_filter = 1;
	bpf_args.pkt.l3_proto = 0x800;
	bpf_args.pkt.bpf_debug = 1;
	

	bpf_set_config(skel, bss, bpf_args);

	// Attach the progams to the events
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		kprobe_bpf__destroy(skel);
        return 1;
	}

    int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "m_event");
	if (!map_fd)
		return -1;

	pb = perf_buffer__new(map_fd, 1024, handle_event,
			      lost_event, NULL, NULL);

	// pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		kprobe_bpf__destroy(skel);
        return 1;
	}

	bpf_set_config_field(skel, bss, bpf_args_t, ready, true);

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	kprobe_bpf__destroy(skel);
	return -err;
}
