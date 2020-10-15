// SPDX-License-Identifier: GPL-2.0

// https://programmingtoddler.wordpress.com/2014/11/09/c-how-to-get-system-timestamp-in-second-millisecond-and-microsecond/

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
#include <time.h>
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
    int ret1, ret2, ret3, ret4, ret5, ret6;
    struct timespec tp1, tp2, tp3, tp4, tp5, tp6;
    clockid_t clk_id1, clk_id2, clk_id3, clk_id4, clk_id5, clk_id6;
    clk_id1 = CLOCK_MONOTONIC;
    clk_id2 = CLOCK_MONOTONIC;

    clk_id3 = CLOCK_MONOTONIC;
    clk_id4 = CLOCK_MONOTONIC;

    clk_id5 = CLOCK_MONOTONIC;
    clk_id6 = CLOCK_MONOTONIC;


    // open file and read to trigger the instrumentation
	int fd1 = open("f", O_RDONLY);
	if (fd1 == -1)
	{
		printf("error open file\n");
		exit(EXIT_FAILURE);
	}

 	char * buf1 = malloc(4096);

    ret1 = clock_gettime(clk_id1, &tp1);

	ssize_t readbytes1 = read(fd1, buf1, 256);

    ret2 = clock_gettime(clk_id2, &tp2);
    printf("native time: %ld\n", tp2.tv_nsec- tp1.tv_nsec);
    
    close(fd1);



	if (argc != 2)
	{
		printf("usage: ./endtoend filter-function reduce-function\n");
	}
	char filename[256];
	int ret, err, id, fkey = MIN_FUNC;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	//printf("eBPF file to be loaded is : %s \n", filename);
	setrlimit(RLIMIT_MEMLOCK, &r);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	// ------------------ end to end latency test for loading ---------------------------
	char extension[256];
	snprintf(extension, sizeof(extension), "%s_func.o", argv[1]);
	//printf("eBPF file to be loaded is : %s \n", extension);

	struct bpf_object *obj;

	int prog_fd;
                    
    ret3 = clock_gettime(clk_id3, &tp3);


	if (bpf_prog_load(extension, BPF_PROG_TYPE_KPROBE, &obj, &prog_fd))
	{
		printf("error reading extension");
		return 1;
	}


    ret4 = clock_gettime(clk_id4, &tp4);
    printf("load time: %ld\n", tp4.tv_nsec- tp3.tv_nsec);


    // load filter function prog fd in main kprobe intrumentation
	err = bpf_map_update_elem(map_fd[1], &fkey, &prog_fd, BPF_ANY);
	if(err)
	{
		printf("map update error for prog\n");
		return 1;
	}

	// ---------------- trigger call with instrumentattion and measure performace -------------------------------
	



	// open file and read to trigger the instrumentation
	int fd = open("f", O_RDONLY);
	if (fd == -1)
	{
		printf("error open file\n");
		exit(EXIT_FAILURE);
	}

 	char * buf = malloc(4096);


    __u32 key = 0;
	//printf("buffer on user side = %lu\n", (unsigned long) buf);	
	if (bpf_map_update_elem(map_fd[0], &key, &buf, BPF_ANY) != 0) 
	{
		fprintf(stderr, "map_update failed: %s\n", strerror(errno));
		return 1;
    }

    ret5 = clock_gettime(clk_id5, &tp5);

	ssize_t readbytes = read(fd, buf, 256);
	//printf("retval = %d\n", (int) readbytes);

    ret6 = clock_gettime(clk_id6, &tp6);
    printf("jit time: %ld\n", tp6.tv_nsec- tp5.tv_nsec);


	//printf("loaded module OK.\nCheck the trace pipe to see the output : sudo cat /sys/kernel/debug/tracing/trace_pipe \n");

	return 0;
}
