#include "aidt.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <vmlinux.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif

// Fallback for bpf_loop if using older headers
#ifndef bpf_loop
static long (* const bpf_loop_fallback)(u32 nr_loops, void *callback_fn, void *callback_ctx, u64 flags) = (void *) 181;
#define bpf_loop bpf_loop_fallback
#endif


// TC
#define AF_INET             2
#define AF_INET6            10
#define ETH_P_IP            0x0800
#define ETH_P_IPV6          0x86DD
#define IPPROTO_TCP         6
#define TC_ACT_OK           0
#define TASK_COMM_LEN       16

// SNI
#define SNI_MARK            0x47435644u
#define MAX_SNI_LEN         253
#define MAX_TLS_PEEK        512
#define MAX_EXTENSIONS      24
#define TLS_HANDSHAKE       0x16
#define TLS_CLIENT_HELLO    0x01
#define EXT_SERVER_NAME     0x0000
#define EXT_ECH             0xfe0d
#define SNI_HOST_NAME       0x00

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);  // pid
	__type(value, u8);
} marked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb_events SEC(".maps");

#define SELF_PID   (bpf_get_current_pid_tgid() >> 32)
#define SELF_TGID  ((u32)bpf_get_current_pid_tgid())

static __always_inline u64 get_cookie(struct task_struct *task)
{
    return BPF_CORE_READ(task, start_boottime);
}

static __always_inline int try_mark_process(u32 pid)
{
    u8 one = 1;
    return bpf_map_update_elem(&marked_pids, &pid, &one, BPF_NOEXIST);
}

static __always_inline int unmark_process(u32 pid)
{
    return bpf_map_delete_elem(&marked_pids, &pid);
}


static __always_inline void  
report_process_event(aidt_event_type_e type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	aidt_event_t *e;
	aidt_process_event_t *pe;
	u32 size = sizeof(aidt_event_t) + sizeof(aidt_process_event_t);

	e = bpf_ringbuf_reserve(&rb_events, size, 0);
	if (!e) return;

	e->type = type;
	e->len = sizeof(aidt_process_event_t);

	pe = (aidt_process_event_t *)e->msg;
	pe->pid  = SELF_PID;
	pe->tgid = SELF_TGID;
	pe->ppid = BPF_CORE_READ(task, real_parent, tgid);
	pe->cookie = get_cookie(task);
	bpf_get_current_comm(&pe->comm, sizeof(pe->comm));

    bpf_printk("report_proc: type=%d pid=%d ppid=%d", type, pe->pid, pe->ppid);

	bpf_ringbuf_submit(e, 0);
}

static __always_inline int  UNUSED
fill_conn_event(aidt_conn_event_t *ce, struct sock *sk, aidt_conn_direction_e direction) 
{
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET) return -1;

    struct task_struct *task = bpf_get_current_task_btf();
	ce->pid = SELF_PID;
	ce->cookie = get_cookie(task);

	ce->family = family;
    ce->direction = direction;
	ce->saddr  = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	ce->daddr  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	ce->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
	ce->dport  = BPF_CORE_READ(sk, __sk_common.skc_dport);

	return OK;
}


static __always_inline void UNUSED
report_conn_event(struct sock *sk, aidt_conn_direction_e direction)
{
	aidt_event_t *e;
	aidt_conn_event_t *ce;
	u32 size = sizeof(aidt_event_t) + sizeof(aidt_conn_event_t);

	e = bpf_ringbuf_reserve(&rb_events, size, 0);
	if (!e) return;

	e->type = EVENT_TYPE_CONNECT;
	e->len = sizeof(aidt_conn_event_t);

	ce = (aidt_conn_event_t *)e->msg;
    if (fill_conn_event(ce, sk, direction) != OK) {
        bpf_ringbuf_discard(e, 0);
        return;
    }

    bpf_printk("report_conn: pid=%d daddr=%u:%d", ce->pid, ce->daddr, ce->dport);
	bpf_ringbuf_submit(e, 0);
}

// SEC("tracepoint/sched/sched_process_exec")
// int aidt_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
// {
// 	//report_process_event(EVENT_TYPE_PROCESS_EXEC);
// 	return 0;
// }

SEC("tracepoint/sched/sched_process_exit")
int aidt_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	if (SELF_PID != SELF_TGID)
		return 0;

    if (unmark_process(SELF_PID) == OK) {
		report_process_event(EVENT_TYPE_PROCESS_EXIT);
	}
	return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(aidt_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	if (ret != 0) return 0;

	if (try_mark_process(SELF_PID) == 0) {
        report_process_event(EVENT_TYPE_PROCESS);
    }

	return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(aidt_inet_csk_accept, struct sock *sk, void *arg, struct sock *ret)
{
	if (!ret) return 0;

	if (try_mark_process(SELF_PID) == 0) {
		report_process_event(EVENT_TYPE_PROCESS);
	}

	return 0;
}


//========================================================================= 
//  TC egress: parse SNI from TLS ClientHello and attribute to PID.
// 
//  PID attribution strategy:
//    - fentry/tcp_connect runs in process context when a TCP connect()
//      is issued. There we have current->pid and can compute the socket
//      cookie of the about-to-be-connected sock. We stash:
//          cookie -> {pid, tgid, ppid, cgroup_id}
//      in a flow_owners LRU map.
//    - At TC egress (softirq, not process context) we look up the
//      skb's socket cookie in flow_owners and copy the owner info into
//      the SNI event.
// 
//  Packet access: instead of walking skb data pointers (whose verifier
//  ranges are reset to zero by every helper call), the TLS payload is
//  copied once into a per-CPU scratch buffer with bpf_skb_load_bytes().
//  The parser then works on plain map memory bounded by simple scalar
//  comparisons, so the loop and helper calls below cannot invalidate it.

struct flow_owner {
    u32 pid;
    u32 tgid;
    u32 ppid;
	u64 cookie;
    u64 cgroup_id;
};

// cookie -> owner. Populated at tcp_connect, read at TC egress.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct flow_owner);
} flow_owners SEC(".maps");

// Per-flow dedupe for SNI parsing. 
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, u8);
} seen_flows SEC(".maps");

// Per-CPU scratch buffer holding the TLS payload copied out of the skb. 
struct sni_scratch {
    u8 buf[MAX_TLS_PEEK];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sni_scratch);
} sni_scratch_map SEC(".maps");


SEC("fentry/tcp_connect")
int BPF_PROG(aidt_sni_tcp_connect, struct sock *sk)
{
    u64 cookie = bpf_get_socket_cookie(sk);
    if (!cookie)
        return 0;

    struct flow_owner fo = {};
    fo.pid  = SELF_PID;
	fo.tgid = SELF_TGID;
    fo.ppid = BPF_CORE_READ(bpf_get_current_task_btf(), real_parent, tgid);
    fo.cgroup_id = bpf_get_current_cgroup_id();
    bpf_map_update_elem(&flow_owners, &cookie, &fo, BPF_ANY);
    return 0;
}

/* Best-effort cleanup when the socket goes away. LRU would handle eviction
 * anyway, but this keeps the map tidy for high connection-rate workloads.
 */
SEC("fentry/tcp_close")
int BPF_PROG(aidt_sni_tcp_close, struct sock *sk)
{
    u64 cookie = bpf_get_socket_cookie(sk);
    if (cookie) {
        bpf_map_delete_elem(&flow_owners, &cookie);
        bpf_map_delete_elem(&seen_flows, &cookie);
    }
    return 0;
}

/* ---- TLS parsing helpers ------------------------------------------------- *
 * These operate on the scratch buffer: `buf` is a MAX_TLS_PEEK-byte map
 * value and `buf_len` is the number of valid bytes copied into it. Every
 * bound is a plain scalar comparison, so it survives helper calls.          */

static __always_inline int load_u8(const u8 *buf, u32 buf_len,
                                    u32 off, u8 *out)
{
    if (off >= buf_len || off >= MAX_TLS_PEEK)
        return -1;
    /* `off < MAX_TLS_PEEK` already holds, but in a strength-reduced loop the
     * compiler hands the verifier a running pointer it can't bound. barrier_var()
     * hides `off`'s known range from the compiler so it cannot drop the mask
     * below as redundant; the mask then makes the index provably in-bounds
     * (MAX_TLS_PEEK is a power of two, so this is a no-op at runtime). */
    barrier_var(off);
    *out = buf[off & (MAX_TLS_PEEK - 1)];
    return 0;
}

static __always_inline int load_u16(const u8 *buf, u32 buf_len,
                                     u32 off, u16 *out)
{
    u8 hi, lo;
    if (load_u8(buf, buf_len, off, &hi) < 0) return -1;
    if (load_u8(buf, buf_len, off + 1, &lo) < 0) return -1;
    *out = ((u16)hi << 8) | lo;
    return 0;
}

/* Extension-walk state threaded through bpf_loop(). bpf_loop() verifies the
 * callback body exactly once, no matter the iteration count -- unlike an
 * unrolled bounded loop, which would re-explore the body (and every
 * barrier_var() inside load_u8) per iteration and blow the verifier's
 * instruction budget. `buf` is a map-value pointer, which (unlike a packet
 * pointer) stays valid across the bpf_loop() helper call. */
struct walk_ctx {
    const u8 *buf;
    u32 buf_len;
    u32 ext_off;
    u32 ext_end;
    u32 sni_off;
    u16 sni_len;
    u8  ech_present;
    u8  _pad;
};

// One TLS extension per call. Return 1 to stop the walk, 0 to continue.
static long walk_ext_cb(u32 idx, void *ctx_)
{
    struct walk_ctx *ctx = ctx_;
    if (ctx->ext_off + 4 > ctx->ext_end)
        return 1;

    u16 ext_type, ext_len;
    if (load_u16(ctx->buf, ctx->buf_len, ctx->ext_off, &ext_type) < 0) return 1;
    if (load_u16(ctx->buf, ctx->buf_len, ctx->ext_off + 2, &ext_len) < 0) return 1;

    u32 body = ctx->ext_off + 4;
    if (body + ext_len > ctx->ext_end)
        return 1;

    if (ext_type == EXT_ECH)
        ctx->ech_present = 1;

    if (ext_type == EXT_SERVER_NAME && ctx->sni_len == 0 && ext_len >= 5) {
        u16 list_len, name_len;
        u8 name_type;

        if (load_u16(ctx->buf, ctx->buf_len, body, &list_len) == 0 &&
            (list_len + 2 <= ext_len) &&
            load_u8(ctx->buf, ctx->buf_len, body + 2, &name_type) == 0 &&
            name_type == SNI_HOST_NAME &&
            load_u16(ctx->buf, ctx->buf_len, body + 3, &name_len) == 0 &&
            name_len > 0 && name_len <= MAX_SNI_LEN &&
            (body + 5 + name_len <= ctx->ext_end)) {
                ctx->sni_off = body + 5;
                ctx->sni_len = name_len;
        }
    }

    ctx->ext_off = body + ext_len;
    return 0;
}

// Parse a TLS record starting at offset 0 of `buf`; on success set *sni_off
// sni_len to the SNI host name's location within `buf`.
static __attribute__((noinline)) int find_sni(const u8 *buf, u32 buf_len,
                                     u32 *sni_off, u16 *sni_len,
                                     u8 *ech_present)
{
    u8 rec_type, hs_type, sid_len, cm_len;
    u16 rec_ver, cs_len, ext_total;

    if (load_u8(buf, buf_len, 0, &rec_type) < 0) return -1;
    if (rec_type != TLS_HANDSHAKE) return -1;
    if (load_u16(buf, buf_len, 1, &rec_ver) < 0) return -1;
    if (rec_ver < 0x0301 || rec_ver > 0x0303) return -1;

    if (load_u8(buf, buf_len, 5, &hs_type) < 0) return -1;
    if (hs_type != TLS_CLIENT_HELLO) return -1;

    u32 p = 5 + 38;            /* TLS record hdr + hs_type+hs_len+ver+random */
    if (load_u8(buf, buf_len, p, &sid_len) < 0) return -1;
    p += 1 + sid_len;
    if (load_u16(buf, buf_len, p, &cs_len) < 0) return -1;
    p += 2 + cs_len;
    if (load_u8(buf, buf_len, p, &cm_len) < 0) return -1;
    p += 1 + cm_len;
    if (load_u16(buf, buf_len, p, &ext_total) < 0) return -1;
    p += 2;

    struct walk_ctx wctx = {
        .buf = buf, .buf_len = buf_len,
        .ext_off = p, .ext_end = p + ext_total,
    };
    bpf_loop(MAX_EXTENSIONS, walk_ext_cb, &wctx, 0);

    *ech_present = wctx.ech_present;
    if (wctx.sni_len == 0) return -1;
    *sni_off = wctx.sni_off;
    *sni_len = wctx.sni_len;
    return 0;
}

SEC("tc")
int aidt_sni_egress(struct __sk_buff *skb)
{
    /* L2-L4 headers are linear at TC egress, and no helper has run yet, so
     * direct packet access is safe here. */
    const void *data     = (const void *)(long)skb->data;
    const void *data_end = (const void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    const struct ethhdr *eth = data;
    u16 h_proto = eth->h_proto;
    u32 l3_off = sizeof(struct ethhdr);

    u8  ip_proto;
    u32 l4_off;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        if (data + l3_off + sizeof(struct iphdr) > data_end) return TC_ACT_OK;
        const struct iphdr *iph = data + l3_off;
        if (iph->version != 4) return TC_ACT_OK;
        u8 ihl = iph->ihl;
        if (ihl < 5) return TC_ACT_OK;
        ip_proto = iph->protocol;
        l4_off = l3_off + ((u32)ihl * 4);
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        return TC_ACT_OK;  // TODO: support IPv6
    } else {
        return TC_ACT_OK;
    }

    if (ip_proto != IPPROTO_TCP) return TC_ACT_OK;

    if (data + l4_off + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;
    const struct tcphdr *tcph = data + l4_off;
    u16 dport = bpf_ntohs(tcph->dest);

    // Only peek at likely TLS traffic to save CPU and avoid false positives
    // on non-TLS flows. We might miss TLS on non-standard ports, but that's
    // an acceptable tradeoff for performance and simplicity (no need for stateful
    // parsing to track TLS flows across packets).
    if (dport != 443 && dport != 8443) return TC_ACT_OK;

    u8 doff = tcph->doff;
    if (doff < 5) return TC_ACT_OK;
    u32 payload_off = l4_off + ((u32)doff * 4);

    // From here on only scalars and map memory are used; packet pointers
    // are no longer touched, so the helper calls below are harmless.
    u32 pkt_len = skb->len;
    if (payload_off >= pkt_len) return TC_ACT_OK;

    u64 cookie = bpf_get_socket_cookie(skb);
    if (cookie) {
        u8 *seen = bpf_map_lookup_elem(&seen_flows, &cookie);
        if (seen) return TC_ACT_OK;
    }

    u32 zero = 0;
    struct sni_scratch *scratch = bpf_map_lookup_elem(&sni_scratch_map, &zero);
    if (!scratch)
        goto mark_seen;

    u32 buf_len = pkt_len - payload_off;
    if (buf_len > MAX_TLS_PEEK)
        buf_len = MAX_TLS_PEEK;

    // Explicitly clamp the lower bound to 1 and upper bound to MAX_TLS_PEEK.
    // This gives the verifier an air-tight mathematical range profile [1, 512].
    if (buf_len < 1 || buf_len > MAX_TLS_PEEK)
        goto mark_seen;

    // Prevent LLVM from optimizing out the check below, which would lead
    // the verifier to complain about 'invalid zero-sized read'.
    barrier_var(buf_len);
    if (buf_len == 0)
        goto mark_seen;

    if (bpf_skb_load_bytes(skb, payload_off, scratch->buf, buf_len) < 0)
        goto mark_seen;

    u32 sni_off = 0;
    u16 sni_len = 0;
    u8  ech_present = 0;
    if (find_sni(scratch->buf, buf_len, &sni_off, &sni_len, &ech_present) < 0) {
        goto mark_seen;
	}

	aidt_event_t *e;
	aidt_sni_event_t *pe;
	u32 size = sizeof(aidt_event_t) + sizeof(aidt_sni_event_t);

	e = bpf_ringbuf_reserve(&rb_events, size, 0);
	if (!e) return TC_ACT_OK;

	e->type = EVENT_TYPE_SNI;
	e->len = sizeof(aidt_sni_event_t);

	pe = (aidt_sni_event_t *)e->msg;
	
    /* Owner lookup: cookie -> {pid, tgid, ppid, cgroup_id}. SNI fires in
     * softirq context, so bpf_get_current_* are useless here. */
    if (cookie) {
        struct flow_owner *fo = bpf_map_lookup_elem(&flow_owners, &cookie);
        if (fo) {
            pe->pid       = fo->pid;
			pe->cookie    = fo->cookie;
        }
    }

    u16 n = sni_len;
    if (n > sizeof(pe->sni) - 1)
        n = sizeof(pe->sni) - 1;

    for (u16 i = 0; i < sizeof(pe->sni) - 1; i++) {
        if (i >= n)
            break;
        // Using a mask ensures the index is always within [0, MAX_TLS_PEEK-1],
        // which the verifier can easily prove, avoiding out-of-bounds errors.
        u32 idx = (sni_off + i) & (MAX_TLS_PEEK - 1);
        pe->sni[i] = (char)scratch->buf[idx];
    }

    bpf_ringbuf_submit(e, 0);
    skb->mark = SNI_MARK;

mark_seen:
    if (cookie) {
        u8 one = 1;
        bpf_map_update_elem(&seen_flows, &cookie, &one, BPF_ANY);
    }
    return TC_ACT_OK;
}

static __always_inline void check_mcp_payload(int fd, const char *buf, size_t count)
{
    if (count < 21 || !buf) return;

    char local_buf[128];
    size_t copy_len = count > sizeof(local_buf) - 1 ? sizeof(local_buf) - 1 : count;

    if (bpf_probe_read_user(local_buf, copy_len, buf) != 0) {
        return;
    }
    local_buf[copy_len] = '\0';
    
    int found = 0;
    #pragma unroll
    for (int i = 0; i < 128 - 21; i++) {
        if (i >= copy_len - 21) break;
        if (local_buf[i] == '"' && local_buf[i+1] == 'm' && local_buf[i+2] == 'e' && 
            local_buf[i+3] == 't' && local_buf[i+4] == 'h' && local_buf[i+5] == 'o' && 
            local_buf[i+6] == 'd' && local_buf[i+7] == '"' && local_buf[i+8] == ':' && 
            local_buf[i+9] == '"' && local_buf[i+10] == 't' && local_buf[i+11] == 'o' && 
            local_buf[i+12] == 'o' && local_buf[i+13] == 'l' && local_buf[i+14] == 's' && 
            local_buf[i+15] == '/' && local_buf[i+16] == 'c' && local_buf[i+17] == 'a' && 
            local_buf[i+18] == 'l' && local_buf[i+19] == 'l' && local_buf[i+20] == '"') {
            found = 1;
            break;
        }
    }

    if (found) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        aidt_event_t *e;
        aidt_mcp_call_event_t *ae;
        u32 size = sizeof(aidt_event_t) + sizeof(aidt_mcp_call_event_t);

        e = bpf_ringbuf_reserve(&rb_events, size, 0);
        if (!e) return;

        e->type = EVENT_TYPE_MCP_CALL;
        e->len = sizeof(aidt_mcp_call_event_t);

        ae = (aidt_mcp_call_event_t *)e->msg;
        ae->pid  = SELF_PID;
        ae->tgid = SELF_TGID;
        ae->cookie = get_cookie(task);
        ae->fd = fd;

        bpf_printk("MCP call written on fd=%d pid=%d", fd, ae->pid);
        bpf_ringbuf_submit(e, 0);
    }
}

SEC("tracepoint/syscalls/sys_enter_write")
int aidt_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    check_mcp_payload(fd, buf, count);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int aidt_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    check_mcp_payload(fd, buf, count);
    return 0;
}

struct http_sse_scan_ctx {
    struct sni_scratch *scratch;
    u32 limit;
    int found;
};

static long http_sse_scan_cb(u32 i, void *ctx_)
{
    struct http_sse_scan_ctx *ctx = ctx_;
    if (i >= ctx->limit) return 1;

    u32 idx = i & (MAX_TLS_PEEK - 1);
    const u8 *b = ctx->scratch->buf;
    if (b[idx] == 't' && b[(idx+1) & (MAX_TLS_PEEK-1)] == 'e' &&
        b[(idx+2) & (MAX_TLS_PEEK-1)] == 'x' && b[(idx+3) & (MAX_TLS_PEEK-1)] == 't' &&
        b[(idx+4) & (MAX_TLS_PEEK-1)] == '/' && b[(idx+5) & (MAX_TLS_PEEK-1)] == 'e' &&
        b[(idx+6) & (MAX_TLS_PEEK-1)] == 'v' && b[(idx+7) & (MAX_TLS_PEEK-1)] == 'e' &&
        b[(idx+8) & (MAX_TLS_PEEK-1)] == 'n' && b[(idx+9) & (MAX_TLS_PEEK-1)] == 't' &&
        b[(idx+10) & (MAX_TLS_PEEK-1)] == '-' && b[(idx+11) & (MAX_TLS_PEEK-1)] == 's' &&
        b[(idx+12) & (MAX_TLS_PEEK-1)] == 't' && b[(idx+13) & (MAX_TLS_PEEK-1)] == 'r' &&
        b[(idx+14) & (MAX_TLS_PEEK-1)] == 'e' && b[(idx+15) & (MAX_TLS_PEEK-1)] == 'a' &&
        b[(idx+16) & (MAX_TLS_PEEK-1)] == 'm') {
        ctx->found = 1;
        return 1;
    }
    return 0;
}

struct http_sse_copy_ctx {
    struct sni_scratch *scratch;
    aidt_http_sse_event_t *he;
    u32 copy_len;
};

static long http_sse_copy_cb(u32 i, void *ctx_)
{
    struct http_sse_copy_ctx *ctx = ctx_;
    if (i >= sizeof(ctx->he->payload_snippet)) return 1;
    u32 idx = i & (MAX_TLS_PEEK - 1);
    ctx->he->payload_snippet[i] = (i < ctx->copy_len) ? (char)ctx->scratch->buf[idx] : 0;
    return 0;
}

static __always_inline void check_http_sse_payload(struct sock *sk, int fd, const char *buf, size_t count, u8 direction)
{
    if (count < 17 || !buf) return;

    // bpf_printk("Checking payload for HTTP/SSE signature, fd=%d count=%d dir=%d", fd, count, direction);

    u32 zero = 0;
    struct sni_scratch *scratch = bpf_map_lookup_elem(&sni_scratch_map, &zero);
    if (!scratch) return;

    u32 copy_len = count > 255 ? 255 : (u32)count;
    if (copy_len < 17) return;

    if (bpf_probe_read_user(scratch->buf, copy_len, buf) != 0) {
        return;
    }

    struct http_sse_scan_ctx sctx = {
        .scratch = scratch,
        .limit = copy_len - 17,
        .found = 0,
    };
    bpf_loop(256, http_sse_scan_cb, &sctx, 0);

    if (sctx.found) {
        struct task_struct *task = bpf_get_current_task_btf();
        aidt_event_t *e;
        aidt_http_sse_event_t *he;
        u32 size = sizeof(aidt_event_t) + sizeof(aidt_http_sse_event_t);

        e = bpf_ringbuf_reserve(&rb_events, size, 0);
        if (!e) return;

        e->type = EVENT_TYPE_HTTP_SSE;
        e->len = sizeof(aidt_http_sse_event_t);

        he = (aidt_http_sse_event_t *)e->msg;
        he->pid  = SELF_PID;
        he->tgid = SELF_TGID;
        he->cookie = get_cookie(task);
        he->fd = fd;
        he->direction = direction;

        // 5-tuple from the socket. For outgoing we keep source/dest as-is;
        // for incoming we swap to keep the convention saddr=local, daddr=peer.
        if (sk) {
            u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
            he->family = family;
            he->saddr  = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            he->daddr  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            he->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);   // host order
            he->dport  = BPF_CORE_READ(sk, __sk_common.skc_dport); // net order
        }

        struct http_sse_copy_ctx cctx = {
            .scratch = scratch,
            .he = he,
            .copy_len = copy_len,
        };
        bpf_loop(sizeof(he->payload_snippet), http_sse_copy_cb, &cctx, 0);

        bpf_printk("HTTP/SSE detected on pid=%d", he->pid);
        bpf_ringbuf_submit(e, 0);
    }
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(aidt_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (size < 17) return 0;

    struct iov_iter *iter = &msg->msg_iter;
    u8 iter_type = BPF_CORE_READ(iter, iter_type);
    void *iov_base = NULL;
    
    if (iter_type == 1 /* ITER_IOVEC */) {
        const struct iovec *iov = BPF_CORE_READ(iter, __iov);
        iov_base = BPF_CORE_READ(iov, iov_base);
    } else if (iter_type == 0 /* ITER_UBUF */) {
        iov_base = BPF_CORE_READ(iter, ubuf);
    }

    if (iov_base) {
        check_http_sse_payload(sk, 0, (const char *)iov_base, size, 0 /* outgoing */);
    }

    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(aidt_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len, int ret)
{
    if (ret < 17) return 0;

    struct iov_iter *iter = &msg->msg_iter;
    u8 iter_type = BPF_CORE_READ(iter, iter_type);
    void *iov_base = NULL;

    if (iter_type == 1 /* ITER_IOVEC */) {
        const struct iovec *iov = BPF_CORE_READ(iter, __iov);
        iov_base = BPF_CORE_READ(iov, iov_base);
    } else if (iter_type == 0 /* ITER_UBUF */) {
        iov_base = BPF_CORE_READ(iter, ubuf);
    }

    if (iov_base) {
        check_http_sse_payload(sk, 0, (const char *)iov_base, (size_t)ret, 1 /* incoming */);
    }

    return 0;
}
