static inline int fake__kfree_skb(context_info_t *info);

__attribute__((section("tp/""skb""/""kfree_skb"), used))

int __trace_kfree_skb(void *ctx)
{
    context_info_t info = {
        .func = 156, 
        .ctx = ctx, 
        .args = (void *)(
            { 
                int _key = 0; 
                void * _v = bpf_map_lookup_elem(&m_config, &_key); 
                if (!_v) 
                    return 0; 
                (pkt_args_t *)_v; 
            }), 
        .skb = *(void **)(ctx + 8)};
    if (pre_handle_entry(&info, 156))
        return 0;
    handle_entry_finish(&info, fake__kfree_skb(&info));
    return 0;
}
static inline int fake__kfree_skb(context_info_t *info)
{
    int reason = 0;

    if (false)
    {
        if (false)
            reason = *(int *)((void *)(info->ctx) + 36);
        else
            reason = *(int *)((void *)(info->ctx) + 28);
    }
    else if (info->args->drop_reason)
    {

        reason = (
            { 
                typeof(*(int *)((void *)(info->ctx) + 28)) ____tmp; 
                bpf_probe_read_kernel(&____tmp, sizeof(*&*(int *)((void *)(info->ctx) + 28)), &*(int *)((void *)(info->ctx) + 28)); 
                ____tmp; 
            });
    }

    pure_drop_event_t __attribute__((__unused__)) * e;
    drop_event_t __attribute__((__unused__)) __e;
    detail_drop_event_t __detail_e = {0};
    info->e = (void *)&__detail_e;
    if (info->args->detail)
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((detail_drop_event_t *)0)->__event_filed));
    }
    else
    {
        (*(volatile typeof(e) *)&e) = ((void *)info->e + ((unsigned long)&((drop_event_t *)0)->__event_filed));
    }

    e->location = *(u64 *)((void *)(info->ctx) + 16);
    e->reason = reason;

    return (
        { 
            int err = handle_entry(info); 
            if (!err) 
                do_event_output(info, (info->args->detail ? sizeof(__detail_e) : sizeof(__e))); 
            err; 
        });
}