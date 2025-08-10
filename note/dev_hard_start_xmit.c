__attribute__((section("kretprobe/""dev_hard_start_xmit"),used))
int
ret__trace_dev_hard_start_xmit(struct pt_regs *ctx)
{
    return handle_exit(ctx, 8);
}

__attribute__((section("kprobe/""dev_hard_start_xmit"),used))
int
__trace_dev_hard_start_xmit(struct pt_regs *ctx)
{
    context_info_t info = {
        .func = 8,
        .ctx = ctx,
        .args = (void *)(
            { 
                int _key = 0;
                void * _v = bpf_map_lookup_elem(&m_config, &_key);
                if (!_v)
                    return 0;
                (pkt_args_t *)_v; 
            }),
        .skb = (void *)(((struct pt_regs *)ctx)->di),
        .sk = ((void *)0)};
    if (pre_handle_entry(&info, 8))
        return 0;
    handle_entry_finish(&info, fake__dev_hard_start_xmit(&info));
    return 0;
}
static inline int fake__dev_hard_start_xmit(context_info_t *info)
{
    return default_handle_entry(info);
}
