// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <assert.h>
#include <bpf.h>
#include "bpf_load.h"
#include <libbpf.h>


#define MIN_FUNC 1
#define MIN_FUNC_PROG_FD (prog_fd[0])
#define PROG_ARRAY_FD (map_fd[2])


int main(int argc, char **argv)
{
	if (argc != 3)
	{
		printf("usage: ./progarray filter-function reduce-function\n");
	}
	char filename[256];
	int ret, err, id, fkey = MIN_FUNC;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	printf("eBPF file to be loaded is : %s \n", filename);
	setrlimit(RLIMIT_MEMLOCK, &r);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	// ------------------ filter ---------------------------
	char extension[256];
	snprintf(extension, sizeof(extension), "%s_func.o", argv[1]);
	printf("eBPF file to be loaded is : %s \n", extension);

	struct bpf_object *obj;

	int prog_fd;
	if (bpf_prog_load(extension, BPF_PROG_TYPE_KPROBE, &obj, &prog_fd))
	{
		printf("error reading extension");
		return 1;
	}

	// ---------------- reduce -------------------------------
	char extension2[256];
	snprintf(extension2, sizeof(extension2), "%s_func.o", argv[2]);
	printf("eBPF file to be loaded is : %s \n", extension);

	struct bpf_object *obj2;

	int prog_fd2;
	if (bpf_prog_load(extension2, BPF_PROG_TYPE_KPROBE, &obj2, &prog_fd2))
	{
		printf("error reading extension");
		return 1;
	}

	// load filter function prog fd in main kprobe intrumentation
	err = bpf_map_update_elem(map_fd[2], &fkey, &prog_fd, BPF_ANY);
	if(err)
	{
		printf("map update error for prog\n");
		return 1;
	}

	//load reduce function progfd in filter instrumentation
	int filter_map_fd = bpf_object__find_map_fd_by_name(obj, "jmp_table");
	err = bpf_map_update_elem(filter_map_fd, &fkey, &prog_fd2, BPF_ANY);
	if(err)
	{
		printf("map update error for filter prog\n");
		return 1;
	}

	// open file and read to trigger the instrumentation
	int fd = open("f", O_RDONLY);
	if (fd == -1)
	{
		printf("error open file\n");
		exit(EXIT_FAILURE);
	}

 	char * buf = malloc(4096);

	__u32 key = 0;
	printf("buffer on user side = %lu\n", (unsigned long) buf);	
	if (bpf_map_update_elem(map_fd[0], &key, &buf, BPF_ANY) != 0) 
	{
		fprintf(stderr, "map_update failed: %s\n", strerror(errno));
		return 1;
    }

	ssize_t readbytes = read(fd, buf, 128);
	printf("retval = %d\n", (int) readbytes);


	// retrieve results from maps
	//unsigned long avg;
	//bpf_map_lookup_elem(map_fd[1], &key, &avg);
	//printf("avg = %lu, on buffer %s\n", avg, buf);


	int result_map_fd = bpf_object__find_map_fd_by_name(obj2, "result_map");
	unsigned long min;
	bpf_map_lookup_elem(result_map_fd, &key, &min);
	printf("res = %lu\n", min);


	printf("loaded module OK.\nCheck the trace pipe to see the output : sudo cat /sys/kernel/debug/tracing/trace_pipe \n");

	close(fd);
	free(buf);
	return 0;
}
