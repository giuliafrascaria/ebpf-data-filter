#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
the filter function takes the from buffer as input, and filters the result to the user buffer
the reduce fuction is called afterwards
*/

#define PROG(F) SEC("kprobe/"__stringify(F)) int bpf_func_##F
#define	UBUFFSIZE	256


struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 8,
};

PROG(1)(struct pt_regs *ctx)
{
    void __user *to; //struct pt_regs *ctx
    const void *from;
    int ret;
    char curr[3];
    char buff[UBUFFSIZE];
	__u32 key = 0;
	__u64 ** val;
    int blen;

	//parse parameters from ctx
	to = (void __user *) PT_REGS_PARM1(ctx);
    from = (const void *) PT_REGS_PARM2(ctx);
	blen = PT_REGS_PARM3(ctx);


    char snonmidire[] = "tail call read stuff filter\n";
	bpf_trace_printk(snonmidire, sizeof(snonmidire));

    
    unsigned long sum = 0;
    unsigned long num = 0; // need initialization or verifier complains on strtol
    u64 base = 10;
    unsigned long elems = 0;



    for (int i = 0; i < 15000; i++)
    {

        ret = bpf_probe_read_str(buff, UBUFFSIZE, from + UBUFFSIZE*i);
        //bpf_probe_write_user((void *) to + UBUFFSIZE*i, buff, UBUFFSIZE);
    }


    bpf_tail_call(ctx, &jmp_table, (int) 1);
	
	return 0;
}


char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;