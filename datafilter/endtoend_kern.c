#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#define PROG(F) SEC("kprobe/"__stringify(F)) int bpf_func_##F
//#define	UBUFFSIZE	2048
#define	UBUFFSIZE	256

struct bpf_map_def SEC("maps") my_read_map =
{
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,	//used to pass the buffer address from userland
};

struct bpf_map_def SEC("maps") jmp_table = 
{
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 8,
};



SEC("kprobe/copyout_bpf")
int bpf_copyout(struct pt_regs *ctx)
{
	//bpf_my_printk();

	char s1[] = "entering modified copyout\n";
	bpf_trace_printk(s1, sizeof(s1));

	// instantiate parameters
	void __user *to;
	const void *from;
	int blen;

	//parse parameters from ctx
	to = (void __user *) PT_REGS_PARM1(ctx);
	from = (const void *) PT_REGS_PARM2(ctx);
	blen = PT_REGS_PARM3(ctx);

	//check buffer address
	__u32 key = 0;
	__u64 ** val;
	val = bpf_map_lookup_elem(&my_read_map, &key);

	if(!val)
	{
		char s[] = "error reading buffer value from map, read entry\n";
		bpf_trace_printk(s, sizeof(s)); 
		return 0;
	}

	char str2[] = "buffer on params %lu, buffer on map %lu\n";
	bpf_trace_printk(str2, sizeof(str2), (unsigned long) to, (unsigned long) *val);

	if (to == *val)
	{
		char s2[] = "copyout to 0x%p, ul %lu len %d\n";
    	bpf_trace_printk(s2, sizeof(s2), to, (unsigned long) to, blen);
        
		bpf_tail_call(ctx, &jmp_table, (int) 1);

	}

	return 0;
}




char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;