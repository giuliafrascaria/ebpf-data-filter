#!/bin/bash
#clang -target bpf , see https://www.kernel.org/doc/html/latest/bpf/bpf_devel_QA.html#q-clang-flag-for-target-bpf
# also : https://stackoverflow.com/questions/56975861/error-compiling-ebpf-c-code-out-of-kernel-tree

C_FLAGS="-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option"

function magic_make {
DEFAULT=$1
KERN="$DEFAULT"_kern
USER="$DEFAULT"_user

clang -nostdinc -isystem `clang -print-file-name=include` \
	-D__KERNEL__ -D__BPF_TRACING__ -D__ASM_SYSREG_H -D__TARGET_ARCH_x86 \
	$C_FLAGS \
	-Icommon/ \
	-include /usr/src/linux-headers-`uname -r`/include/linux/kconfig.h \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include/generated/ \
	-I/usr/src/linux-headers-`uname -r`/include/ \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include/uapi/ \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include/generated/uapi/ \
	-I/usr/src/linux-headers-`uname -r`/include/uapi/ \
	-I/usr/src/linux-headers-`uname -r`/include/generated/uapi/ \
	-I./tools/testing/selftests/bpf/ \
    -I./tools/lib/ \
    -include asm_goto_workaround.h \
	-O2 -emit-llvm -c "$KERN".c -o -| llc -march=bpf -filetype=obj -o "compiled/$KERN".o


#gcc "$USER".c bpf_load.c /home/giogge/linux/samples/bpf/../../tools/lib/bpf/libbpf.a -iquote -I/thesis/libbpf/src/ \
# -I./usr/include -I./tools/lib/bpf/ -I./tools/testing/selftests/bpf/ -I./tools/lib/ \
#-I./tools/include -I./tools/perf -I./tools/perf/util -I./tools/perf/tests -lelf -DHAVE_ATTR_TEST=0 -o compiled/$DEFAULT

gcc "$USER".c bpf_load.c ./tools/lib/bpf/libbpf.a ./tools/testing/selftests/bpf/trace_helpers.o \
-iquote -I./libbpf/src/ -I./usr/include -I./tools/lib/bpf/ \
-I./tools/testing/selftests/bpf/ -I./tools/lib/ \
-I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0 \
-o compiled/$DEFAULT -lelf -lz


}

function magic_make_helpers {
	
DEFAULT=$1
FUNC="$DEFAULT"_func

clang -nostdinc -isystem `clang -print-file-name=include` \
	-D__KERNEL__ -D__BPF_TRACING__ -D__ASM_SYSREG_H -D__TARGET_ARCH_x86 \
	$C_FLAGS \
	-Icommon/ \
	-include /usr/src/linux-headers-`uname -r`/include/linux/kconfig.h \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include/generated/ \
	-I/usr/src/linux-headers-`uname -r`/include/ \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include/uapi/ \
	-I/usr/src/linux-headers-`uname -r`/arch/x86/include/generated/uapi/ \
	-I/usr/src/linux-headers-`uname -r`/include/uapi/ \
	-I/usr/src/linux-headers-`uname -r`/include/generated/uapi/ \
	-I./tools/testing/selftests/bpf/ \
    -I./tools/lib/ \
    -include asm_goto_workaround.h \
	-O2 -emit-llvm -c "$FUNC".c -o -| llc -march=bpf -filetype=obj -o "compiled/$FUNC".o


}

targets=( endtoend benchoverride nooverride progarray tracex1 odirect freplace procfs_override readiter hellotrace strtol override_exec fentry_test verifier)

for t in "${targets[@]}" ; do
	echo "making ...$t"
	magic_make $t
done

funcs=( sum filter 1 2 3 4 5)

for t in "${funcs[@]}" ; do
	echo "making function...$t"
	magic_make_helpers $t
done
