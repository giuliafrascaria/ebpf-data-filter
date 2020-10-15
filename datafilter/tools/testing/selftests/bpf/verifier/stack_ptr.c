{
	"PTR_TO_STACK store/load",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -10),
	BPF_ST_MEM(BPF_DW, BPF_REG_1, 2, 0xfaceb00c),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 0xfaceb00c,
},
{
	"PTR_TO_STACK store/load - bad alignment on off",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_1, 2, 0xfaceb00c),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 2),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "misaligned stack access off (0x0; 0x0)+-8+2 size 8",
},
{
	"PTR_TO_STACK store/load - bad alignment on reg",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -10),
	BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0xfaceb00c),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "misaligned stack access off (0x0; 0x0)+-10+8 size 8",
},
{
	"PTR_TO_STACK store/load - out of bounds low",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -80000),
	BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0xfaceb00c),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid stack off=-79992 size=8",
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
},
{
	"PTR_TO_STACK store/load - out of bounds high",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0xfaceb00c),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid stack off=0 size=8",
},
{
	"PTR_TO_STACK check high 1",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -1),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK check high 2",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ST_MEM(BPF_B, BPF_REG_1, -1, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, -1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK check high 3",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 0),
	BPF_ST_MEM(BPF_B, BPF_REG_1, -1, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, -1),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
	.result_unpriv = REJECT,
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK check high 4",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 0),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
	.errstr = "invalid stack off=0 size=1",
	.result = REJECT,
},
{
	"PTR_TO_STACK check high 5",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, (1 << 29) - 1),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid stack off",
},
{
	"PTR_TO_STACK check high 6",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, (1 << 29) - 1),
	BPF_ST_MEM(BPF_B, BPF_REG_1, SHRT_MAX, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, SHRT_MAX),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid stack off",
},
{
	"PTR_TO_STACK check high 7",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, (1 << 29) - 1),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, (1 << 29) - 1),
	BPF_ST_MEM(BPF_B, BPF_REG_1, SHRT_MAX, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, SHRT_MAX),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
	.errstr = "fp pointer offset",
},
{
	"PTR_TO_STACK check low 1",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -512),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK check low 2",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -513),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 1, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 1),
	BPF_EXIT_INSN(),
	},
	.result_unpriv = REJECT,
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK check low 3",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -513),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
	.errstr = "invalid stack off=-513 size=1",
	.result = REJECT,
},
{
	"PTR_TO_STACK check low 4",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, INT_MIN),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "math between fp pointer",
},
{
	"PTR_TO_STACK check low 5",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -((1 << 29) - 1)),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid stack off",
},
{
	"PTR_TO_STACK check low 6",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -((1 << 29) - 1)),
	BPF_ST_MEM(BPF_B, BPF_REG_1, SHRT_MIN, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, SHRT_MIN),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid stack off",
},
{
	"PTR_TO_STACK check low 7",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -((1 << 29) - 1)),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -((1 << 29) - 1)),
	BPF_ST_MEM(BPF_B, BPF_REG_1, SHRT_MIN, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, SHRT_MIN),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr_unpriv = "R1 stack pointer arithmetic goes out of range",
	.errstr = "fp pointer offset",
},
{
	"PTR_TO_STACK mixed reg/k, 1",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -3),
	BPF_MOV64_IMM(BPF_REG_2, -3),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK mixed reg/k, 2",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -3),
	BPF_MOV64_IMM(BPF_REG_2, -3),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_5, -6),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = 42,
},
{
	"PTR_TO_STACK mixed reg/k, 3",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -3),
	BPF_MOV64_IMM(BPF_REG_2, -3),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = -3,
},
{
	"PTR_TO_STACK reg",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_MOV64_IMM(BPF_REG_2, -3),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 42),
	BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
	BPF_EXIT_INSN(),
	},
	.result_unpriv = REJECT,
	.errstr_unpriv = "invalid stack off=0 size=1",
	.result = ACCEPT,
	.retval = 42,
},
{
	"stack pointer arithmetic",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_1, 4),
	BPF_JMP_IMM(BPF_JA, 0, 0, 0),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -10),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1),
	BPF_ST_MEM(0, BPF_REG_2, 4, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8),
	BPF_ST_MEM(0, BPF_REG_2, 4, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"store PTR_TO_STACK in R10 to array map using BPF_B",
	.insns = {
	/* Load pointer to map. */
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	/* Copy R10 to R9. */
	BPF_MOV64_REG(BPF_REG_9, BPF_REG_10),
	/* Pollute other registers with unaligned values. */
	BPF_MOV64_IMM(BPF_REG_2, -1),
	BPF_MOV64_IMM(BPF_REG_3, -1),
	BPF_MOV64_IMM(BPF_REG_4, -1),
	BPF_MOV64_IMM(BPF_REG_5, -1),
	BPF_MOV64_IMM(BPF_REG_6, -1),
	BPF_MOV64_IMM(BPF_REG_7, -1),
	BPF_MOV64_IMM(BPF_REG_8, -1),
	/* Store both R9 and R10 with BPF_B and read back. */
	BPF_STX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, 0),
	BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_1, 0),
	BPF_STX_MEM(BPF_B, BPF_REG_1, BPF_REG_9, 0),
	BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_1, 0),
	/* Should read back as same value. */
	BPF_JMP_REG(BPF_JEQ, BPF_REG_2, BPF_REG_3, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 42),
	BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 3 },
	.result = ACCEPT,
	.retval = 42,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
