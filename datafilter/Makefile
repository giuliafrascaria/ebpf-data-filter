# SPDX-License-Identifier: GPL-2.0

BPF_SAMPLES_PATH ?= $(CURDIR)
TOOLS_PATH := ./tools

# List of programs to build
tprogs-y += tracex1


# Libbpf dependencies
LIBBPF = $(TOOLS_PATH)/lib/bpf/libbpf.a

CGROUP_HELPERS := ./tools/testing/selftests/bpf/cgroup_helpers.o
TRACE_HELPERS := ./tools/testing/selftests/bpf/trace_helpers.o

tracex1-objs := bpf_load.o tracex1_user.o $(TRACE_HELPERS)

# Tell kbuild to always build the programs
always-y := $(tprogs-y)
always-y += tracex1_kern.o


TPROGS_CFLAGS += -Wall -O2
TPROGS_CFLAGS += -Wmissing-prototypes
TPROGS_CFLAGS += -Wstrict-prototypes

TPROGS_CFLAGS += -I./usr/include
TPROGS_CFLAGS += -I./tools/testing/selftests/bpf/
TPROGS_CFLAGS += -I./tools/lib/
TPROGS_CFLAGS += -I./tools/include
TPROGS_CFLAGS += -I./tools/perf
TPROGS_CFLAGS += -DHAVE_ATTR_TEST=0


TPROGCFLAGS_bpf_load.o += -Wno-unused-variable

TPROGS_LDLIBS			+= $(LIBBPF) -lelf -lz
TPROGLDLIBS_tracex4		+= -lrt
TPROGLDLIBS_trace_output	+= -lrt
TPROGLDLIBS_map_perf_test	+= -lrt
TPROGLDLIBS_test_overhead	+= -lrt
TPROGLDLIBS_xdpsock		+= -pthread

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make M=samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
LLVM_OBJCOPY ?= llvm-objcopy
BTF_PAHOLE ?= pahole

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C M=$(CURDIR) BPF_SAMPLES_PATH=$(CURDIR)/compiled

clean:
	$(MAKE) -C ../../ M=$(CURDIR) clean
	@find $(CURDIR) -type f -name '*~' -delete


# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
$(obj)/%.o: $(src)/%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(BPF_EXTRA_CFLAGS) \
		-I$(obj) -I$(srctree)/tools/testing/selftests/bpf/ \
		-I$(srctree)/tools/lib/ \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
	    -include asm_goto_workaround.h \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

