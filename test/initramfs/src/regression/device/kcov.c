// SPDX-License-Identifier: MPL-2.0

/*
 * Regression tests for `/dev/kcov` and `/proc/kallsyms`.
 *
 * Covers device permissions, Linux KCOV ioctl/mmap state machine,
 * `VM_DONTEXPAND` enforcement, PC and comparison tracing, user page-fault
 * tracing, cross-page buffer boundaries, thread isolation, parallel sessions,
 * fd/mapping lifetimes, task-exit cleanup, and `fork` handoff.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/capability.h"
#include "../common/test.h"

#define KCOV_DEVICE "/dev/kcov"
#define KALLSYMS_PATH "/proc/kallsyms"

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_TRACE_PC 0UL
#define KCOV_TRACE_CMP 1UL
#define KCOV_CMP_CONST 1UL
#define KCOV_CMP_SIZE_MASK 6UL
#define KCOV_CMP_TYPE_MASK (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK)
#define KCOV_CMP_WORDS 4UL

#define KCOV_UNKNOWN_IOCTL 0xdeadbeefUL
#define KCOV_CMP_TEST_ARG 0x123456789abcdef0UL
#define KCOV_ENTRIES 4096UL
#define KCOV_BYTES (KCOV_ENTRIES * sizeof(unsigned long))
#define KCOV_PC_LIMIT (KCOV_ENTRIES - 1UL)
#define KCOV_MAX_ENTRIES ((unsigned long)INT_MAX / sizeof(unsigned long))

static unsigned long text_start;
static unsigned long text_end;
static size_t page_size;
static size_t page_words;

static bool validate_pc_entries(volatile unsigned long *area, size_t max_pcs,
				unsigned long *out_count)
{
	unsigned long count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);

	if (count == 0 || count > max_pcs)
		return false;
	for (unsigned long i = 1; i <= count; i++) {
		unsigned long pc = area[i];

		if (pc < text_start || pc >= text_end)
			return false;
	}
	if (out_count != NULL)
		*out_count = count;
	return true;
}

static bool validate_cmp_entries(volatile unsigned long *area, size_t entries,
				 bool require_magic, unsigned long *out_count)
{
	unsigned long count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);
	unsigned long max_comps = (entries - 1UL) / KCOV_CMP_WORDS;
	bool found_magic = false;

	if (count == 0 || count > max_comps)
		return false;
	for (unsigned long i = 0; i < count; i++) {
		unsigned long base = 1UL + i * KCOV_CMP_WORDS;
		unsigned long type = area[base];
		unsigned long arg1 = area[base + 1UL];
		unsigned long arg2 = area[base + 2UL];
		unsigned long pc = area[base + 3UL];
		unsigned int bits;

		if ((type & ~KCOV_CMP_TYPE_MASK) != 0)
			return false;
		bits = 8U << ((type & KCOV_CMP_SIZE_MASK) >> 1);
		if (bits < sizeof(unsigned long) * CHAR_BIT) {
			if ((arg1 >> bits) != 0 || (arg2 >> bits) != 0)
				return false;
		}
		if (pc < text_start || pc >= text_end)
			return false;
		if (arg1 == KCOV_CMP_TEST_ARG || arg2 == KCOV_CMP_TEST_ARG)
			found_magic = true;
	}
	if (require_magic && !found_magic)
		return false;
	if (out_count != NULL)
		*out_count = count;
	return true;
}

static int open_mapped_kcov(size_t entries, volatile unsigned long **out_area)
{
	int fd = CHECK(open(KCOV_DEVICE, O_RDWR | O_CLOEXEC));
	size_t bytes = entries * sizeof(unsigned long);
	void *mapped;

	CHECK(ioctl(fd, KCOV_INIT_TRACE, entries));
	mapped = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK_WITH(mapped, _ret != MAP_FAILED);
	*out_area = (volatile unsigned long *)mapped;
	return fd;
}

static void close_mapped_kcov(int fd, volatile unsigned long *area,
			      size_t entries)
{
	CHECK(munmap((void *)area, entries * sizeof(unsigned long)));
	CHECK(close(fd));
}

static void spin_until_eq(unsigned int *flag, unsigned int expected)
{
	while (__atomic_load_n(flag, __ATOMIC_ACQUIRE) != expected)
		sched_yield();
}

/*
 * Busy-wait in user space without calling `sched_yield()` so a traced thread
 * does not enter the kernel and record spurious coverage while waiting.
 */
static void spin_in_userspace_until_eq(unsigned int *flag,
				       unsigned int expected)
{
	while (__atomic_load_n(flag, __ATOMIC_ACQUIRE) != expected) {
		/* Stay in user space without entering the kernel. */
	}
}

FN_SETUP(check_kcov_availability)
{
	int fd = open(KCOV_DEVICE, O_RDWR | O_CLOEXEC);
	long ps;
	FILE *file;
	unsigned long addr;
	unsigned long stext = 0;
	unsigned long double_stext = 0;
	unsigned long etext = 0;
	char type;
	char name[64];

	if (fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr, "kcov tests skipped: %s (%s)\n",
				KCOV_DEVICE, strerror(errno));
			exit(EXIT_SUCCESS);
		}
		fprintf(stderr, "fatal error: open('%s') failed: %s\n",
			KCOV_DEVICE, strerror(errno));
		exit(EXIT_FAILURE);
	}
	CHECK(close(fd));

	ps = CHECK_WITH(sysconf(_SC_PAGESIZE), _ret > 0);
	page_size = (size_t)ps;
	page_words = page_size / sizeof(unsigned long);
	CHECK_WITH(page_words % KCOV_CMP_WORDS, _ret == 0);

	file = CHECK_WITH(fopen(KALLSYMS_PATH, "r"), _ret != NULL);
	while (fscanf(file, "%lx %c %63s", &addr, &type, name) == 3) {
		if (type == 'T' && strcmp(name, "_stext") == 0)
			stext = addr;
		else if (type == 'T' && strcmp(name, "__stext") == 0)
			double_stext = addr;
		else if (type == 'T' && strcmp(name, "_etext") == 0)
			etext = addr;
	}
	CHECK_WITH(fclose(file), _ret == 0);
	CHECK_WITH(stext > 0 && stext == double_stext && etext > stext,
		   _ret != 0);

	text_start = stext;
	text_end = etext;
}
END_SETUP()

FN_TEST(kcov_device_mode_and_root_only_access)
{
	struct stat st;
	pid_t child;
	int status;

	TEST_RES(stat(KCOV_DEVICE, &st),
		 S_ISCHR(st.st_mode) && (st.st_mode & 0777) == 0600);
	TEST_RES(stat(KALLSYMS_PATH, &st),
		 S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0400);

	child = TEST_SUCC(fork());
	if (child == 0) {
		int fd;

		if (setresuid(65534, 65534, 65534) != 0 || geteuid() == 0)
			_exit(2);

		errno = 0;
		fd = open(KCOV_DEVICE, O_RDWR | O_CLOEXEC);
		if (fd >= 0 || (errno != EACCES && errno != EPERM))
			_exit(3);

		errno = 0;
		fd = open(KALLSYMS_PATH, O_RDONLY | O_CLOEXEC);
		if (fd >= 0 || (errno != EACCES && errno != EPERM))
			_exit(4);

		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);

	/* UID 0 without CAP_SYS_ADMIN must also be rejected. */
	child = TEST_SUCC(fork());
	if (child == 0) {
		int fd;

		drop_capability(CAP_SYS_ADMIN);
		if (geteuid() != 0)
			_exit(2);

		errno = 0;
		fd = open(KCOV_DEVICE, O_RDWR | O_CLOEXEC);
		if (fd >= 0 || errno != EPERM)
			_exit(3);

		_exit(EXIT_SUCCESS);
	}

	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
}
END_TEST()

FN_TEST(kcov_proc_mem_prot_none_and_exec_rejected)
{
	int fd = TEST_SUCC(open(KCOV_DEVICE, O_RDWR | O_CLOEXEC));
	int mem_fd = TEST_SUCC(open("/proc/self/mem", O_RDONLY | O_CLOEXEC));
	void *none_area;
	void *exec_area;
	volatile unsigned long *rw_area;
	unsigned long val = 0;

	TEST_SUCC(ioctl(fd, KCOV_INIT_TRACE, KCOV_ENTRIES));

	/* Forced alien reads on PROT_NONE / PROT_EXEC KCOV mappings must fail cleanly. */
	none_area = (void *)TEST_RES(mmap(NULL, KCOV_BYTES, PROT_NONE,
					  MAP_SHARED, fd, 0),
				     _ret != MAP_FAILED);
	TEST_ERRNO(pread(mem_fd, &val, sizeof(val),
			 (off_t)(uintptr_t)none_area),
		   EIO);
	TEST_SUCC(munmap(none_area, KCOV_BYTES));

	exec_area = (void *)TEST_RES(mmap(NULL, KCOV_BYTES, PROT_EXEC,
					  MAP_SHARED, fd, 0),
				     _ret != MAP_FAILED);
	TEST_ERRNO(pread(mem_fd, &val, sizeof(val),
			 (off_t)(uintptr_t)exec_area),
		   EIO);
	TEST_SUCC(munmap(exec_area, KCOV_BYTES));

	/* Readable KCOV mappings succeed via /proc/self/mem until mprotect(PROT_NONE). */
	rw_area = (volatile unsigned long *)TEST_RES(
		mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		     0),
		_ret != MAP_FAILED);
	rw_area[1] = 0x13572468UL;
	TEST_RES(pread(mem_fd, &val, sizeof(val),
		       (off_t)(uintptr_t)&rw_area[1]),
		 _ret == (ssize_t)sizeof(val) && val == 0x13572468UL);
	TEST_SUCC(mprotect((void *)rw_area, KCOV_BYTES, PROT_NONE));
	TEST_ERRNO(pread(mem_fd, &val, sizeof(val), (off_t)(uintptr_t)rw_area),
		   EIO);

	TEST_SUCC(munmap((void *)rw_area, KCOV_BYTES));
	TEST_SUCC(close(mem_fd));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(kcov_file_ops_and_state_machine_errors)
{
	char buf[8] = { 0 };
	int fd = TEST_SUCC(open(KCOV_DEVICE, O_RDWR | O_CLOEXEC));
	int unaligned_fd;
	volatile unsigned long *area;
	volatile unsigned long *area2;

	/* Unsupported generic file operations. */
	TEST_ERRNO(read(fd, buf, sizeof(buf)), EINVAL);
	TEST_ERRNO(write(fd, buf, sizeof(buf)), EINVAL);
	TEST_ERRNO(lseek(fd, 0, SEEK_SET), ESPIPE);
	TEST_ERRNO(ioctl(fd, KCOV_UNKNOWN_IOCTL, 0), ENOTTY);

	/* Operations before KCOV_INIT_TRACE fail with EINVAL. */
	TEST_ERRNO(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC), EINVAL);
	TEST_ERRNO(ioctl(fd, KCOV_DISABLE, 0), EINVAL);
	TEST(mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
	     EINVAL, _ret == MAP_FAILED);

	/* Invalid buffer sizes are rejected before initialization succeeds. */
	TEST_ERRNO(ioctl(fd, KCOV_INIT_TRACE, 0UL), EINVAL);
	TEST_ERRNO(ioctl(fd, KCOV_INIT_TRACE, 1UL), EINVAL);
	TEST_ERRNO(ioctl(fd, KCOV_INIT_TRACE, KCOV_MAX_ENTRIES + 1UL), EINVAL);
	TEST_ERRNO(ioctl(fd, KCOV_INIT_TRACE, ULONG_MAX), EINVAL);

	/* Initialize once; repeated KCOV_INIT_TRACE returns EBUSY. */
	TEST_SUCC(ioctl(fd, KCOV_INIT_TRACE, KCOV_ENTRIES));
	TEST_ERRNO(ioctl(fd, KCOV_INIT_TRACE, KCOV_ENTRIES), EBUSY);
	TEST_ERRNO(ioctl(fd, KCOV_INIT_TRACE, 0UL), EBUSY);

	/* Linux rejects KCOV_ENABLE until the buffer has been mmapped. */
	TEST_ERRNO(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC), EINVAL);
	TEST_ERRNO(ioctl(fd, KCOV_DISABLE, 0), EINVAL);

	/* Invalid mmap requests are rejected. */
	TEST(mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0),
	     EINVAL, _ret == MAP_FAILED);
	TEST(mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
	     EINVAL, _ret == MAP_FAILED);
	TEST(mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		  (off_t)page_size),
	     EINVAL, _ret == MAP_FAILED);

	/* Non-page-aligned KCOV_INIT_TRACE succeeds, but mmap rejects it. */
	unaligned_fd = TEST_SUCC(open(KCOV_DEVICE, O_RDWR | O_CLOEXEC));
	TEST_SUCC(ioctl(unaligned_fd, KCOV_INIT_TRACE, 2UL));
	TEST(mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		  unaligned_fd, 0),
	     EINVAL, _ret == MAP_FAILED);
	TEST_SUCC(close(unaligned_fd));

	/* Valid mmap succeeds; a second mmap shares the same backing pages. */
	area = (volatile unsigned long *)TEST_RES(mmap(NULL, KCOV_BYTES,
						       PROT_READ | PROT_WRITE,
						       MAP_SHARED, fd, 0),
						  _ret != MAP_FAILED);
	area2 = (volatile unsigned long *)TEST_RES(mmap(NULL, KCOV_BYTES,
							PROT_READ | PROT_WRITE,
							MAP_SHARED, fd, 0),
						   _ret != MAP_FAILED);
	area[1] = 0x12345678UL;
	TEST_RES(area2[1], _ret == 0x12345678UL);
	TEST_SUCC(munmap((void *)area2, KCOV_BYTES));

	/* VM_DONTEXPAND: growing the KCOV mapping via mremap must fail. */
	TEST(mremap((void *)area, KCOV_BYTES, KCOV_BYTES + page_size,
		    MREMAP_MAYMOVE),
	     EFAULT, _ret == MAP_FAILED);

	/* Enable/disable argument validation. */
	TEST_ERRNO(ioctl(fd, KCOV_ENABLE, 2UL), EINVAL);
	TEST_SUCC(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));
	TEST_ERRNO(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC), EINVAL);
	TEST_ERRNO(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_CMP), EINVAL);
	/* Linux rejects mmap() while the descriptor is actively enabled. */
	TEST(mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
	     EINVAL, _ret == MAP_FAILED);
	TEST_ERRNO(ioctl(fd, KCOV_DISABLE, 1UL), EINVAL);
	TEST_SUCC(ioctl(fd, KCOV_DISABLE, 0));
	TEST_ERRNO(ioctl(fd, KCOV_DISABLE, 0), EINVAL);

	/* Once disabled, syscalls no longer write into the buffer. */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	TEST_RES(syscall(SYS_getpid), _ret > 0);
	TEST_RES(__atomic_load_n(&area[0], __ATOMIC_ACQUIRE), _ret == 0);

	TEST_SUCC(munmap((void *)area, KCOV_BYTES));
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(kcov_trace_pc_reset_saturation_and_page_fault)
{
	volatile unsigned long *area;
	int fd = open_mapped_kcov(KCOV_ENTRIES, &area);
	unsigned long getpid_count = 0;
	unsigned long getuid_count = 0;
	unsigned long fault_count = 0;
	unsigned long sat_count;
	unsigned long hostile_count;
	unsigned long resumed_count;
	unsigned long first_resumed_pc;
	bool getpid_ok;
	bool getuid_ok;
	bool fault_ok;
	char *anon;

	TEST_SUCC(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));

	/* Syscalls record valid kernel text PCs. */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	getpid_ok = validate_pc_entries(area, KCOV_PC_LIMIT, &getpid_count);

	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getuid));
	getuid_ok = validate_pc_entries(area, KCOV_PC_LIMIT, &getuid_count);

	/* Synchronous user page faults also record kernel text PCs. */
	anon = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK_WITH(anon, _ret != MAP_FAILED);
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	*(volatile char *)anon = 0x42;
	fault_ok = validate_pc_entries(area, KCOV_PC_LIMIT, &fault_count);
	CHECK(munmap(anon, page_size));

	/* Repeated syscalls saturate cleanly at KCOV_ENTRIES - 1. */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	for (unsigned long i = 0; i < KCOV_ENTRIES; i++) {
		CHECK(syscall(SYS_getpid));
		if (__atomic_load_n(&area[0], __ATOMIC_ACQUIRE) ==
		    KCOV_PC_LIMIT)
			break;
	}
	sat_count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);

	/* Hostile word 0 must not overflow or be clobbered. */
	__atomic_store_n(&area[0], ULONG_MAX, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	hostile_count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);

	/* Resetting word 0 resumes recording from entry 1. */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	area[1] = 0;
	CHECK(syscall(SYS_getuid));
	resumed_count = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);
	first_resumed_pc = area[1];

	TEST_SUCC(ioctl(fd, KCOV_DISABLE, 0));

	TEST_RES(getpid_ok && getpid_count > 0, _ret);
	TEST_RES(getuid_ok && getuid_count > 0, _ret);
	TEST_RES(fault_ok && fault_count > 0, _ret);
	TEST_RES(sat_count, _ret == KCOV_PC_LIMIT);
	TEST_RES(hostile_count, _ret == ULONG_MAX);
	TEST_RES(resumed_count, _ret > 0 && _ret <= KCOV_PC_LIMIT);
	TEST_RES(first_resumed_pc, _ret >= text_start && _ret < text_end);

	close_mapped_kcov(fd, area, KCOV_ENTRIES);
}
END_TEST()

FN_TEST(kcov_trace_cmp_and_cross_page_boundaries)
{
	const unsigned long marker = 0x5a5aa5a55a5aa5a5UL;
	volatile unsigned long *area;
	int fd = open_mapped_kcov(KCOV_ENTRIES, &area);
	unsigned long cmp_count = 0;
	bool cmp_ok;
	size_t two_page_entries = 2UL * page_words;
	size_t single_page_comps = (page_words - 1UL) / KCOV_CMP_WORDS;
	size_t two_page_comps = (two_page_entries - 1UL) / KCOV_CMP_WORDS;
	volatile unsigned long *small_area;
	int small_fd;
	unsigned long count;
	bool padding_ok = true;
	bool cross_page_ok = true;

	/* Basic CMP capture using a rejected 64-bit KCOV_DISABLE argument. */
	TEST_SUCC(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_CMP));
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	errno = 0;
	CHECK_WITH(ioctl(fd, KCOV_DISABLE, KCOV_CMP_TEST_ARG),
		   _ret == -1 && errno == EINVAL);
	cmp_ok = validate_cmp_entries(area, KCOV_ENTRIES, true, &cmp_count);
	TEST_SUCC(ioctl(fd, KCOV_DISABLE, 0));
	TEST_RES(cmp_ok && cmp_count > 0, _ret);
	close_mapped_kcov(fd, area, KCOV_ENTRIES);

	/*
	 * Two-page CMP buffer:
	 *   - Record `single_page_comps` starts at word `1 + 127 * 4 = 509`,
	 *     putting words 0..2 on page 0 and word 3 (PC) at word 512 (page 1).
	 *   - Trailing words beyond `1 + two_page_comps * 4` remain untouched.
	 */
	small_fd = open_mapped_kcov(two_page_entries, &small_area);
	CHECK(ioctl(small_fd, KCOV_ENABLE, KCOV_TRACE_CMP));
	for (size_t i = 1; i < two_page_entries; i++)
		small_area[i] = marker;
	__atomic_store_n(&small_area[0], single_page_comps, __ATOMIC_RELAXED);
	for (size_t i = 0; i < two_page_comps; i++) {
		errno = 0;
		CHECK_WITH(ioctl(small_fd, KCOV_DISABLE, KCOV_CMP_TEST_ARG),
			   _ret == -1 && errno == EINVAL);
		if (__atomic_load_n(&small_area[0], __ATOMIC_ACQUIRE) ==
		    two_page_comps)
			break;
	}
	count = __atomic_load_n(&small_area[0], __ATOMIC_ACQUIRE);
	TEST_SUCC(ioctl(small_fd, KCOV_DISABLE, 0));

	/* Words before the starting record must remain untouched. */
	for (size_t i = 1; i < 1UL + single_page_comps * KCOV_CMP_WORDS; i++) {
		if (small_area[i] != marker)
			padding_ok = false;
	}
	/* Trailing padding words after the final complete record stay untouched. */
	for (size_t i = 1UL + two_page_comps * KCOV_CMP_WORDS;
	     i < two_page_entries; i++) {
		if (small_area[i] != marker)
			padding_ok = false;
	}
	/* Cross-page record has a valid type and PC on page 1 (`small_area[512]`). */
	{
		size_t cross_base = 1UL + single_page_comps * KCOV_CMP_WORDS;
		unsigned long cross_type = small_area[cross_base];
		unsigned long cross_pc = small_area[cross_base + 3UL];

		if ((cross_type & ~KCOV_CMP_TYPE_MASK) != 0 ||
		    cross_pc < text_start || cross_pc >= text_end)
			cross_page_ok = false;
	}

	TEST_RES(count, _ret == two_page_comps);
	TEST_RES(padding_ok, _ret);
	TEST_RES(cross_page_ok, _ret);
	close_mapped_kcov(small_fd, small_area, two_page_entries);
}
END_TEST()

struct isolation_ctx {
	int fd;
	volatile unsigned long *area;
	unsigned int start;
	unsigned int done;
	int count_changed;
	int enable_res;
	int enable_errno;
	int disable_res;
	int disable_errno;
};

static void *isolation_worker(void *arg)
{
	struct isolation_ctx *ctx = arg;
	unsigned long before;

	spin_until_eq(&ctx->start, 1);
	before = __atomic_load_n(&ctx->area[0], __ATOMIC_ACQUIRE);

	(void)syscall(SYS_getpid);
	(void)syscall(SYS_getuid);
	if (__atomic_load_n(&ctx->area[0], __ATOMIC_ACQUIRE) != before)
		ctx->count_changed = 1;

	errno = 0;
	ctx->enable_res = ioctl(ctx->fd, KCOV_ENABLE, KCOV_TRACE_PC);
	ctx->enable_errno = errno;
	if (__atomic_load_n(&ctx->area[0], __ATOMIC_ACQUIRE) != before)
		ctx->count_changed = 1;

	errno = 0;
	ctx->disable_res = ioctl(ctx->fd, KCOV_DISABLE, 0);
	ctx->disable_errno = errno;
	if (__atomic_load_n(&ctx->area[0], __ATOMIC_ACQUIRE) != before)
		ctx->count_changed = 1;

	__atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
	return NULL;
}

FN_TEST(kcov_thread_isolation_and_ownership)
{
	volatile unsigned long *area;
	int fd = open_mapped_kcov(KCOV_ENTRIES, &area);
	struct isolation_ctx ctx = {
		.fd = fd,
		.area = area,
	};
	pthread_t worker;
	unsigned long count_after;

	TEST_SUCC(pthread_create(&worker, NULL, isolation_worker, &ctx));
	TEST_SUCC(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));

	/*
	 * Busy-wait in user space without issuing syscalls on this thread so
	 * `area[0]` must stay 0 while the worker issues syscalls.
	 */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	__atomic_store_n(&ctx.start, 1, __ATOMIC_RELEASE);
	spin_in_userspace_until_eq(&ctx.done, 1);
	count_after = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);

	TEST_SUCC(ioctl(fd, KCOV_DISABLE, 0));
	TEST_SUCC(pthread_join(worker, NULL));

	TEST_RES(count_after, _ret == 0);
	TEST_RES(ctx.count_changed, _ret == 0);
	TEST_RES(ctx.enable_res == -1 && ctx.enable_errno == EINVAL, _ret);
	TEST_RES(ctx.disable_res == -1 && ctx.disable_errno == EINVAL, _ret);

	close_mapped_kcov(fd, area, KCOV_ENTRIES);
}
END_TEST()

FN_TEST(kcov_independent_opens_dup_and_close_lifetimes)
{
	volatile unsigned long *area1;
	volatile unsigned long *area2;
	int fd1 = open_mapped_kcov(KCOV_ENTRIES, &area1);
	int fd2 = open_mapped_kcov(KCOV_ENTRIES, &area2);
	int dup_fd;
	unsigned long saved_count = 0;
	unsigned long saved_first_pc;
	bool ok;

	/* Only one KCOV buffer can be enabled on a task at a time. */
	TEST_SUCC(ioctl(fd1, KCOV_ENABLE, KCOV_TRACE_PC));
	TEST_ERRNO(ioctl(fd2, KCOV_ENABLE, KCOV_TRACE_PC), EBUSY);
	TEST_ERRNO(ioctl(fd2, KCOV_DISABLE, 0), EINVAL);

	__atomic_store_n(&area1[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	ok = validate_pc_entries(area1, KCOV_PC_LIMIT, NULL);
	TEST_SUCC(ioctl(fd1, KCOV_DISABLE, 0));
	TEST_RES(ok, _ret);

	/* Switching to the second fd works once the first is disabled. */
	TEST_SUCC(ioctl(fd2, KCOV_ENABLE, KCOV_TRACE_PC));
	__atomic_store_n(&area2[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getuid));
	ok = validate_pc_entries(area2, KCOV_PC_LIMIT, NULL);
	TEST_SUCC(ioctl(fd2, KCOV_DISABLE, 0));
	TEST_RES(ok, _ret);
	close_mapped_kcov(fd2, area2, KCOV_ENTRIES);

	/* Closing an old fd after dup() preserves the active session. */
	TEST_SUCC(ioctl(fd1, KCOV_ENABLE, KCOV_TRACE_PC));
	dup_fd = TEST_SUCC(dup(fd1));
	TEST_SUCC(close(fd1));
	fd1 = dup_fd;

	__atomic_store_n(&area1[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	TEST_SUCC(ioctl(fd1, KCOV_DISABLE, 0));
	ok = validate_pc_entries(area1, KCOV_PC_LIMIT, &saved_count);
	saved_first_pc = area1[1];
	TEST_RES(ok, _ret);

	/* Mapping and recorded contents survive close(fd). */
	TEST_SUCC(close(fd1));
	TEST_RES(syscall(SYS_getuid), _ret >= 0);
	TEST_RES(__atomic_load_n(&area1[0], __ATOMIC_ACQUIRE),
		 _ret == saved_count);
	TEST_RES(area1[1], _ret == saved_first_pc);
	TEST_SUCC(munmap((void *)area1, KCOV_BYTES));
}
END_TEST()

struct parallel_ctx {
	int pc_fd;
	volatile unsigned long *pc_area;
	unsigned int phase;
	bool pc_ok;
};

static void *parallel_pc_worker(void *arg)
{
	struct parallel_ctx *ctx = arg;

	CHECK(ioctl(ctx->pc_fd, KCOV_ENABLE, KCOV_TRACE_PC));
	__atomic_store_n(&ctx->pc_area[0], 0, __ATOMIC_RELAXED);
	__atomic_store_n(&ctx->phase, 1, __ATOMIC_RELEASE);

	spin_in_userspace_until_eq(&ctx->phase, 2);
	CHECK(syscall(SYS_getpid));
	ctx->pc_ok = validate_pc_entries(ctx->pc_area, KCOV_PC_LIMIT, NULL);
	__atomic_store_n(&ctx->phase, 3, __ATOMIC_RELEASE);

	spin_in_userspace_until_eq(&ctx->phase, 4);
	CHECK(ioctl(ctx->pc_fd, KCOV_DISABLE, 0));
	return NULL;
}

FN_TEST(kcov_parallel_pc_and_cmp_sessions)
{
	volatile unsigned long *cmp_area;
	int cmp_fd = open_mapped_kcov(KCOV_ENTRIES, &cmp_area);
	struct parallel_ctx ctx = { 0 };
	pthread_t worker;
	unsigned long cmp_count = 0;
	unsigned long pc_count_before;
	unsigned long cmp_count_after;
	bool cmp_ok;

	ctx.pc_fd = open_mapped_kcov(KCOV_ENTRIES, &ctx.pc_area);
	TEST_SUCC(pthread_create(&worker, NULL, parallel_pc_worker, &ctx));
	TEST_SUCC(ioctl(cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP));
	spin_until_eq(&ctx.phase, 1);

	/* Both sessions are active; main thread records CMP without touching PC. */
	__atomic_store_n(&cmp_area[0], 0, __ATOMIC_RELAXED);
	errno = 0;
	CHECK_WITH(ioctl(cmp_fd, KCOV_DISABLE, KCOV_CMP_TEST_ARG),
		   _ret == -1 && errno == EINVAL);
	cmp_ok = validate_cmp_entries(cmp_area, KCOV_ENTRIES, true, &cmp_count);
	pc_count_before = __atomic_load_n(&ctx.pc_area[0], __ATOMIC_ACQUIRE);

	/* Let worker record PC while main thread stays in user space. */
	__atomic_store_n(&ctx.phase, 2, __ATOMIC_RELEASE);
	spin_in_userspace_until_eq(&ctx.phase, 3);
	cmp_count_after = __atomic_load_n(&cmp_area[0], __ATOMIC_ACQUIRE);

	__atomic_store_n(&ctx.phase, 4, __ATOMIC_RELEASE);
	TEST_SUCC(ioctl(cmp_fd, KCOV_DISABLE, 0));
	TEST_SUCC(pthread_join(worker, NULL));

	TEST_RES(cmp_ok && cmp_count > 0, _ret);
	TEST_RES(pc_count_before, _ret == 0);
	TEST_RES(ctx.pc_ok, _ret);
	TEST_RES(cmp_count_after, _ret == cmp_count);

	close_mapped_kcov(ctx.pc_fd, ctx.pc_area, KCOV_ENTRIES);
	close_mapped_kcov(cmp_fd, cmp_area, KCOV_ENTRIES);
}
END_TEST()

static void *exit_with_enabled_worker(void *arg)
{
	int fd = *(int *)arg;

	CHECK(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));
	CHECK(syscall(SYS_getpid));
	return NULL;
}

static void *close_while_enabled_worker(void *arg)
{
	volatile unsigned long *area;
	int fd = open_mapped_kcov(KCOV_ENTRIES, &area);
	bool *recorded_after_close = arg;

	CHECK(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));
	CHECK(close(fd));

	/* Closing the fd while enabled keeps tracing alive until task exit. */
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	*recorded_after_close = validate_pc_entries(area, KCOV_PC_LIMIT, NULL);

	CHECK(munmap((void *)area, KCOV_BYTES));
	return NULL;
}

FN_TEST(kcov_task_exit_cleanup_and_close_while_enabled)
{
	volatile unsigned long *area;
	int fd = open_mapped_kcov(KCOV_ENTRIES, &area);
	pthread_t worker;
	bool ok;
	bool recorded_after_close = false;

	/* Exiting without KCOV_DISABLE detaches so the fd is immediately reusable. */
	TEST_SUCC(pthread_create(&worker, NULL, exit_with_enabled_worker, &fd));
	TEST_SUCC(pthread_join(worker, NULL));

	TEST_SUCC(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));
	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	ok = validate_pc_entries(area, KCOV_PC_LIMIT, NULL);
	TEST_SUCC(ioctl(fd, KCOV_DISABLE, 0));
	TEST_RES(ok, _ret);
	close_mapped_kcov(fd, area, KCOV_ENTRIES);

	/* Closing fd while enabled keeps recording and cleans up on thread exit. */
	TEST_SUCC(pthread_create(&worker, NULL, close_while_enabled_worker,
				 &recorded_after_close));
	TEST_SUCC(pthread_join(worker, NULL));
	TEST_RES(recorded_after_close, _ret);
}
END_TEST()

FN_TEST(kcov_fork_handoff_and_shared_writable_mapping)
{
	volatile unsigned long *area;
	int fd = open_mapped_kcov(KCOV_ENTRIES, &area);
	pid_t child;
	int status;
	bool parent_ok;
	bool child_ok;

	/* While enabled in parent, child does not inherit ownership. */
	TEST_SUCC(ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC));
	child = TEST_SUCC(fork());
	if (child == 0) {
		errno = 0;
		if (ioctl(fd, KCOV_DISABLE, 0) != -1 || errno != EINVAL)
			_exit(2);
		errno = 0;
		if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) != -1 ||
		    errno != EINVAL)
			_exit(3);
		_exit(EXIT_SUCCESS);
	}
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);

	__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
	CHECK(syscall(SYS_getpid));
	parent_ok = validate_pc_entries(area, KCOV_PC_LIMIT, NULL);
	TEST_SUCC(ioctl(fd, KCOV_DISABLE, 0));
	TEST_RES(parent_ok, _ret);

	/*
	 * After parent disables, child inherits both the fd and the writable
	 * shared device mapping, can write word 0 directly, and parent observes
	 * the PCs collected by the child.
	 */
	area[0] = 0xdeadbeefUL;
	child = TEST_SUCC(fork());
	if (child == 0) {
		__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
		if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) != 0)
			_exit(2);
		if (syscall(SYS_getuid) < 0)
			_exit(3);
		if (ioctl(fd, KCOV_DISABLE, 0) != 0)
			_exit(4);
		_exit(EXIT_SUCCESS);
	}
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);

	child_ok = validate_pc_entries(area, KCOV_PC_LIMIT, NULL);
	TEST_RES(child_ok, _ret);

	close_mapped_kcov(fd, area, KCOV_ENTRIES);
}
END_TEST()
