/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE

#if !defined(__x86_64__)
#error "This regression test covers the x86_64 KCOV ABI only"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_TRACE_PC 0UL
#define KCOV_TRACE_CMP 1UL
#define KCOV_CMP_CONST 1UL
#define KCOV_CMP_SIZE_MASK 6UL
#define KCOV_CMP_WORDS 4UL
#define KCOV_CMP_TEST_IOCTL 0xdeadbeefUL
#define KCOV_ENTRIES 4096UL
#define KCOV_BYTES (KCOV_ENTRIES * sizeof(unsigned long))
#define KCOV_PC_LIMIT (KCOV_ENTRIES - 1UL)
#define KCOV_CMP_TYPE_MASK (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK)

_Static_assert(sizeof(unsigned long) == sizeof(uint64_t),
	       "KCOV x86_64 entries must be 64 bits");

#define REQUIRE(condition)                                                   \
	do {                                                                 \
		if (!(condition)) {                                            \
			fprintf(stderr,                                         \
				"FAIL line %d: %s (errno=%d: %s)\n",             \
				__LINE__, #condition, errno, strerror(errno)); \
			exit(EXIT_FAILURE);                                    \
		}                                                                \
	} while (0)

static unsigned long text_start, text_end;

static void read_text_bounds(void)
{
	FILE *file = fopen("/proc/kallsyms", "r");
	unsigned long addr;
	char type, name[64];

	REQUIRE(file != NULL);
	while (fscanf(file, "%lx %c %63s", &addr, &type, name) == 3) {
		if (type == 'T' && strcmp(name, "_stext") == 0)
			text_start = addr;
		if (type == 'T' && strcmp(name, "_etext") == 0)
			text_end = addr;
	}
	REQUIRE(fclose(file) == 0);
	REQUIRE(text_start > 0 && text_end > text_start);
}

static int ioctl_fails_with(int fd, unsigned long command,
			    unsigned long argument, int expected_errno)
{
	errno = 0;
	return ioctl(fd, command, argument) == -1 && errno == expected_errno;
}

static void wait_for_success(pid_t child)
{
	int status;

	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void check_root_only_access(void)
{
	pid_t child = fork();

	REQUIRE(child >= 0);
	if (child == 0) {
		int fd;

		if (setresuid(65534, 65534, 65534) != 0 || geteuid() == 0)
			_exit(2);
		errno = 0;
		fd = open("/dev/kcov", O_RDWR | O_CLOEXEC);
		if (fd >= 0) {
			close(fd);
			_exit(1);
		}
		_exit(errno == EPERM || errno == EACCES ? 0 : 1);
	}

	wait_for_success(child);
}

static unsigned long validate_pc_buffer(volatile unsigned long *area)
{
	unsigned long count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);

	REQUIRE(count > 0 && count <= KCOV_PC_LIMIT);
	for (unsigned long i = 1; i <= count; i++)
		REQUIRE(area[i] >= text_start && area[i] < text_end);
	return count;
}

static unsigned long collect_pc(volatile unsigned long *area, long syscall_nr)
{
	long result;

	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	result = syscall(syscall_nr);
	REQUIRE(result >= 0);
	return validate_pc_buffer(area);
}

struct thread_context {
	int fd;
	volatile unsigned long *area;
	int start;
	int done;
	int count_changed;
	int enable_result;
	int enable_errno;
	int disable_result;
	int disable_errno;
};

static void *thread_worker(void *argument)
{
	struct thread_context *context = argument;

	while (!__atomic_load_n(&context->start, __ATOMIC_ACQUIRE))
		__asm__ __volatile__("pause" ::: "memory");

	unsigned long count_before =
		__atomic_load_n(&context->area[0], __ATOMIC_ACQUIRE);
	(void)syscall(SYS_getpid);
	(void)syscall(SYS_getuid);
	if (__atomic_load_n(&context->area[0], __ATOMIC_ACQUIRE) != count_before)
		context->count_changed = 1;

	errno = 0;
	context->enable_result =
		ioctl(context->fd, KCOV_ENABLE, KCOV_TRACE_PC);
	context->enable_errno = errno;
	if (__atomic_load_n(&context->area[0], __ATOMIC_ACQUIRE) != count_before)
		context->count_changed = 1;

	errno = 0;
	context->disable_result = ioctl(context->fd, KCOV_DISABLE, 0);
	context->disable_errno = errno;
	if (__atomic_load_n(&context->area[0], __ATOMIC_ACQUIRE) != count_before)
		context->count_changed = 1;

	__atomic_store_n(&context->done, 1, __ATOMIC_RELEASE);
	return NULL;
}

static void run_thread_isolation(int fd, volatile unsigned long *area)
{
	struct thread_context context = {
		.fd = fd,
		.area = area,
	};
	pthread_t thread;

	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(pthread_create(&thread, NULL, thread_worker, &context) == 0);
	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	__atomic_store_n(&context.start, 1, __ATOMIC_RELEASE);

	while (!__atomic_load_n(&context.done, __ATOMIC_ACQUIRE))
		__asm__ __volatile__("pause" ::: "memory");

	REQUIRE(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) == 0);
	REQUIRE(context.count_changed == 0);
	REQUIRE(context.enable_result == -1 && context.enable_errno == EBUSY);
	REQUIRE(context.disable_result == -1 && context.disable_errno == EINVAL);
	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(pthread_join(thread, NULL) == 0);
	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
}

static void *exit_with_coverage(void *arg)
{
	int fd = *(int *)arg;

	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(syscall(SYS_getpid) > 0);
	return NULL;
}

static void check_pc_and_reset(volatile unsigned long *area)
{
	unsigned long getpid_count = collect_pc(area, SYS_getpid);
	unsigned long getuid_count = collect_pc(area, SYS_getuid);

	printf("KCOV PC: getpid=%lu entries, getuid=%lu entries\n", getpid_count,
	       getuid_count);

	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	for (unsigned long i = 0; i < KCOV_ENTRIES; i++) {
		REQUIRE(syscall(SYS_getpid) >= 0);
		if (__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) == KCOV_PC_LIMIT)
			break;
	}
	REQUIRE(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) == KCOV_PC_LIMIT);

	__atomic_store_n(&area[0], ULONG_MAX, __ATOMIC_RELAXED);
	REQUIRE(syscall(SYS_getpid) >= 0);
	REQUIRE(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) == ULONG_MAX);

	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	area[1] = 0;
	REQUIRE(syscall(SYS_getuid) >= 0);
	REQUIRE(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) > 0);
	REQUIRE(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) <= KCOV_PC_LIMIT);
	REQUIRE(area[1] != 0);
}

static unsigned long validate_cmp_buffer(volatile unsigned long *area)
{
	unsigned long count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);
	int found_test_ioctl = 0;

	REQUIRE(count > 0);
	REQUIRE(count <= (KCOV_ENTRIES - 1UL) / KCOV_CMP_WORDS);
	for (unsigned long i = 0; i < count; i++) {
		unsigned long base = 1UL + i * KCOV_CMP_WORDS;
		unsigned long type = area[base];
		unsigned long arg1 = area[base + 1UL];
		unsigned long arg2 = area[base + 2UL];
		unsigned long pc = area[base + 3UL];

		REQUIRE((type & ~KCOV_CMP_TYPE_MASK) == 0);
		unsigned int bits = 8U << ((type & KCOV_CMP_SIZE_MASK) >> 1);
		if (bits < 64) {
			REQUIRE((arg1 >> bits) == 0);
			REQUIRE((arg2 >> bits) == 0);
		}
		REQUIRE(pc >= text_start && pc < text_end);
		if (arg1 == KCOV_CMP_TEST_IOCTL || arg2 == KCOV_CMP_TEST_IOCTL)
			found_test_ioctl = 1;
	}
	REQUIRE(found_test_ioctl);
	return count;
}

static void check_cmp(int fd, volatile unsigned long *area)
{
	unsigned long count;

	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	REQUIRE(ioctl_fails_with(fd, KCOV_CMP_TEST_IOCTL, 0, ENOTTY));
	count = validate_cmp_buffer(area);
	printf("KCOV CMP: %lu comparison records\n", count);
}

static int open_initialized_kcov(volatile unsigned long **area)
{
	int fd = open("/dev/kcov", O_RDWR | O_CLOEXEC);

	REQUIRE(fd >= 0);
	REQUIRE(ioctl(fd, KCOV_INIT_TRACE, KCOV_ENTRIES) == 0);
	*area = mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	REQUIRE(*area != MAP_FAILED);
	return fd;
}

static void run_independent_open_sessions(int fd,
					  volatile unsigned long *area)
{
	volatile unsigned long *other_area;
	int other_fd = open_initialized_kcov(&other_area);

	REQUIRE(ioctl_fails_with(other_fd, KCOV_ENABLE, KCOV_TRACE_PC, EBUSY));
	REQUIRE(ioctl_fails_with(other_fd, KCOV_DISABLE, 0, EINVAL));
	REQUIRE(collect_pc(area, SYS_getpid) > 0);

	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(ioctl(other_fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(collect_pc(other_area, SYS_getuid) > 0);
	REQUIRE(ioctl(other_fd, KCOV_DISABLE, 0) == 0);

	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(collect_pc(area, SYS_getpid) > 0);
	REQUIRE(munmap((void *)other_area, KCOV_BYTES) == 0);
	REQUIRE(close(other_fd) == 0);
}

static void run_dup_after_close(int *fd, volatile unsigned long *area)
{
	int duplicate_fd = dup(*fd);

	REQUIRE(duplicate_fd >= 0);
	REQUIRE(close(*fd) == 0);
	*fd = duplicate_fd;

	REQUIRE(collect_pc(area, SYS_getpid) > 0);
	REQUIRE(ioctl(*fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(ioctl(*fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(collect_pc(area, SYS_getuid) > 0);
}

static void run_mapping_after_fd_close(void)
{
	volatile unsigned long *area;
	int fd = open_initialized_kcov(&area);

	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(collect_pc(area, SYS_getpid) > 0);
	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
	unsigned long count = validate_pc_buffer(area);
	unsigned long first_pc = area[1];
	REQUIRE(close(fd) == 0);
	REQUIRE(syscall(SYS_getuid) >= 0);
	REQUIRE(validate_pc_buffer(area) == count && area[1] == first_pc);
	REQUIRE(munmap((void *)area, KCOV_BYTES) == 0);
}

struct parallel_session {
	int pc_fd;
	volatile unsigned long *pc_area;
	unsigned int phase;
};

static void wait_for_phase(unsigned int *phase, unsigned int expected)
{
	while (__atomic_load_n(phase, __ATOMIC_ACQUIRE) != expected)
		__asm__ __volatile__("pause" ::: "memory");
}

static void *parallel_pc_worker(void *argument)
{
	struct parallel_session *session = argument;

	REQUIRE(ioctl(session->pc_fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	__atomic_store_n(&session->pc_area[0], 0, __ATOMIC_RELAXED);
	__atomic_store_n(&session->phase, 1, __ATOMIC_RELEASE);
	wait_for_phase(&session->phase, 2);
	(void)collect_pc(session->pc_area, SYS_getpid);
	__atomic_store_n(&session->phase, 3, __ATOMIC_RELEASE);
	wait_for_phase(&session->phase, 4);
	REQUIRE(ioctl(session->pc_fd, KCOV_DISABLE, 0) == 0);
	return NULL;
}

static void run_parallel_coverage_sessions(void)
{
	volatile unsigned long *cmp_area;
	struct parallel_session session = { 0 };
	int cmp_fd = open_initialized_kcov(&cmp_area);
	session.pc_fd = open_initialized_kcov(&session.pc_area);
	pthread_t worker;
	REQUIRE(pthread_create(&worker, NULL, parallel_pc_worker, &session) == 0);
	REQUIRE(ioctl(cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) == 0);
	wait_for_phase(&session.phase, 1);

	/* Both sessions are active. Each syscall must update just its own buffer. */
	__atomic_store_n(&cmp_area[0], 0, __ATOMIC_RELAXED);
	REQUIRE(ioctl_fails_with(cmp_fd, KCOV_CMP_TEST_IOCTL, 0, ENOTTY));
	unsigned long cmp_count = validate_cmp_buffer(cmp_area);
	REQUIRE(__atomic_load_n(&session.pc_area[0], __ATOMIC_ACQUIRE) == 0);
	__atomic_store_n(&session.phase, 2, __ATOMIC_RELEASE);
	wait_for_phase(&session.phase, 3);
	REQUIRE(__atomic_load_n(&cmp_area[0], __ATOMIC_ACQUIRE) == cmp_count);
	unsigned long pc_count = validate_pc_buffer(session.pc_area);

	__atomic_store_n(&session.phase, 4, __ATOMIC_RELEASE);
	REQUIRE(ioctl(cmp_fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(pthread_join(worker, NULL) == 0);
	printf("KCOV parallel: PC=%lu entries, CMP=%lu records\n", pc_count, cmp_count);
	REQUIRE(munmap((void *)session.pc_area, KCOV_BYTES) == 0);
	REQUIRE(munmap((void *)cmp_area, KCOV_BYTES) == 0);
	REQUIRE(close(session.pc_fd) == 0);
	REQUIRE(close(cmp_fd) == 0);
}

static void trigger_trace(int fd, unsigned long mode)
{
	if (mode == KCOV_TRACE_PC)
		REQUIRE(syscall(SYS_getpid) > 0);
	else
		REQUIRE(ioctl_fails_with(fd, KCOV_CMP_TEST_IOCTL, 0, ENOTTY));
}

/* Check the unused words on both sides of the record and in the page padding. */
static void check_capacity(unsigned long mode, size_t entries,
			   size_t initial_count, size_t expected_count)
{
	const unsigned long marker = 0x5a5aa5a55a5aa5a5UL;
	size_t record_words = mode == KCOV_TRACE_PC ? 1 : KCOV_CMP_WORDS;
	size_t first = 1 + initial_count * record_words;
	size_t end = 1 + expected_count * record_words;
	long page_size = sysconf(_SC_PAGESIZE);
	REQUIRE(page_size > 0);
	size_t bytes = (entries * sizeof(unsigned long) + page_size - 1)
		       / page_size * page_size;
	size_t map_words = bytes / sizeof(unsigned long);
	unsigned long *saved = malloc(bytes);
	REQUIRE(saved != NULL);

	int fd = open("/dev/kcov", O_RDWR | O_CLOEXEC);
	REQUIRE(fd >= 0);
	REQUIRE(ioctl(fd, KCOV_INIT_TRACE, entries) == 0);
	volatile unsigned long *area = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
					    MAP_SHARED, fd, 0);
	REQUIRE(area != MAP_FAILED);
	REQUIRE(ioctl(fd, KCOV_ENABLE, mode) == 0);

	/* Reinitialize every slot while enabled so each pass must write a new record. */
	for (unsigned int pass = 0; pass < 2; pass++) {
		for (size_t i = 1; i < map_words; i++)
			area[i] = marker;
		__atomic_store_n(&area[0], initial_count, __ATOMIC_RELAXED);
		trigger_trace(fd, mode);
		unsigned long count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);
		if (count != expected_count) {
			fprintf(stderr, "FAIL: %s buffer of %zu words: expected count %zu, got %lu\n",
				mode == KCOV_TRACE_PC ? "PC" : "CMP", entries,
				expected_count, count);
			exit(EXIT_FAILURE);
		}
		for (size_t i = 1; i < first; i++)
			REQUIRE(area[i] == marker);
		for (size_t i = end; i < map_words; i++)
			REQUIRE(area[i] == marker);
		if (expected_count > initial_count) {
			if (mode == KCOV_TRACE_CMP) {
				REQUIRE((area[first] & ~KCOV_CMP_TYPE_MASK) == 0);
				REQUIRE(area[first + 1] != marker);
				REQUIRE(area[first + 2] != marker);
			}
			unsigned long pc = area[end - 1];
			REQUIRE(pc >= text_start && pc < text_end);
		}
		for (size_t i = 0; i < map_words; i++)
			saved[i] = area[i];
		trigger_trace(fd, mode);
		for (size_t i = 0; i < map_words; i++)
			REQUIRE(saved[i] == area[i]);
	}
	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(munmap((void *)area, bytes) == 0);
	REQUIRE(close(fd) == 0);
	free(saved);
}

static void check_buffer_geometry(void)
{
	check_capacity(KCOV_TRACE_PC, 2, 0, 1);
	check_capacity(KCOV_TRACE_CMP, 2, 0, 0);
	check_capacity(KCOV_TRACE_CMP, 5, 0, 1);
	check_capacity(KCOV_TRACE_CMP, 8, 0, 1);

	long page_size = sysconf(_SC_PAGESIZE);
	REQUIRE(page_size > 0);
	size_t page_words = (size_t)page_size / sizeof(unsigned long);
	REQUIRE(page_words % KCOV_CMP_WORDS == 0);
	size_t records = page_words / KCOV_CMP_WORDS;
	/* The last record places its PC in the first word of the next page. */
	check_capacity(KCOV_TRACE_CMP, page_words + KCOV_CMP_WORDS,
		       records - 1, records);
}

static void check_fork_handoff(int fd, volatile unsigned long *area)
{
	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		REQUIRE(ioctl_fails_with(fd, KCOV_DISABLE, 0, EINVAL));
		REQUIRE(ioctl_fails_with(fd, KCOV_ENABLE, KCOV_TRACE_PC, EBUSY));
		_exit(EXIT_SUCCESS);
	}
	wait_for_success(child);
	REQUIRE(collect_pc(area, SYS_getpid) > 0);
	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);

	/* An inherited file description and mapping can be used by a new owner. */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
		REQUIRE(syscall(SYS_getuid) >= 0);
		REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
		_exit(EXIT_SUCCESS);
	}
	wait_for_success(child);
	(void)validate_pc_buffer(area);
}

int main(void)
{
	int fd;
	volatile unsigned long *area;
	unsigned long text_bytes = KCOV_BYTES;

	if (geteuid() != 0) {
		fprintf(stderr, "FAIL: KCOV regression requires root\n");
		return EXIT_FAILURE;
	}

	fd = open("/dev/kcov", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "FAIL: open /dev/kcov: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	read_text_bounds();
	check_root_only_access();

	REQUIRE(ioctl_fails_with(fd, KCOV_ENABLE, KCOV_TRACE_PC, EINVAL));
	REQUIRE(ioctl_fails_with(fd, KCOV_DISABLE, 0, EINVAL));
	REQUIRE(ioctl_fails_with(fd, KCOV_INIT_TRACE, 0, EINVAL));
	REQUIRE(ioctl_fails_with(fd, KCOV_INIT_TRACE, 1, EINVAL));
	REQUIRE(ioctl_fails_with(fd, KCOV_INIT_TRACE, ULONG_MAX, EINVAL));
	REQUIRE(ioctl(fd, KCOV_INIT_TRACE, KCOV_ENTRIES) == 0);
	REQUIRE(ioctl_fails_with(fd, KCOV_INIT_TRACE, KCOV_ENTRIES, EBUSY));
	REQUIRE(ioctl_fails_with(fd, KCOV_ENABLE, 2, EINVAL));

	errno = 0;
	area = mmap(NULL, text_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	REQUIRE(area == MAP_FAILED && errno == EINVAL);
	errno = 0;
	area = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	REQUIRE(area == MAP_FAILED && errno == EINVAL);
	errno = 0;
	area = mmap(NULL, text_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		    4096);
	REQUIRE(area == MAP_FAILED && errno == EINVAL);

	area = mmap(NULL, text_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	REQUIRE(area != MAP_FAILED);

	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(ioctl_fails_with(fd, KCOV_ENABLE, KCOV_TRACE_PC, EBUSY));
	REQUIRE(ioctl_fails_with(fd, KCOV_ENABLE, KCOV_TRACE_CMP, EBUSY));
	REQUIRE(ioctl_fails_with(fd, KCOV_DISABLE, 1, EINVAL));

	check_pc_and_reset(area);
	run_thread_isolation(fd, area);
	run_independent_open_sessions(fd, area);
	run_dup_after_close(&fd, area);

	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);
	REQUIRE(ioctl_fails_with(fd, KCOV_DISABLE, 0, EINVAL));
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	REQUIRE(syscall(SYS_getpid) >= 0);
	REQUIRE(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) == 0);

	run_mapping_after_fd_close();
	run_parallel_coverage_sessions();

	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_CMP) == 0);
	REQUIRE(ioctl_fails_with(fd, KCOV_ENABLE, KCOV_TRACE_PC, EBUSY));
	check_cmp(fd, area);
	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);

	pthread_t owner;
	REQUIRE(pthread_create(&owner, NULL, exit_with_coverage, &fd) == 0);
	REQUIRE(pthread_join(owner, NULL) == 0);
	REQUIRE(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0);
	REQUIRE(collect_pc(area, SYS_getpid) > 0);
	REQUIRE(ioctl(fd, KCOV_DISABLE, 0) == 0);

	check_fork_handoff(fd, area);
	check_buffer_geometry();

	REQUIRE(munmap((void *)area, text_bytes) == 0);
	REQUIRE(close(fd) == 0);
	printf("PASS: real KCOV PCs, getpid/getuid and CMP records verified, root access, mmap, limits, reset, "
	       "thread isolation, independent opens, dup lifetime, parallel PC/CMP, fork handoff, buffer boundaries, ioctl errors\n");
	return EXIT_SUCCESS;
}
