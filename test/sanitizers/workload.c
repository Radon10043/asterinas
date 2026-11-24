/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define WORKER_COUNT 8U
#define ROUND_COUNT 256U
#define SLOT_COUNT 4U
#define FILE_PREFIX "/tmp/asterinas-sanitizer-workload"

struct workload_message {
	uint64_t magic;
	uint32_t worker;
	uint32_t round;
};

_Static_assert(sizeof(struct workload_message) == 16,
	       "workload message must remain a fixed 16-byte record");

struct start_gate {
	int ready_count;
	int start;
};

struct worker_context {
	unsigned int worker;
	struct start_gate *gate;
	int error_number;
	const char *operation;
};

static void record_failure(struct worker_context *context,
			   const char *operation, int error_number)
{
	if (context->error_number == 0) {
		context->operation = operation;
		context->error_number = error_number != 0 ? error_number : EIO;
	}
}

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *bytes = buffer;
	size_t written = 0;

	while (written < length) {
		ssize_t result = write(fd, bytes + written, length - written);

		if (result < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (result == 0) {
			errno = EIO;
			return -1;
		}
		written += (size_t)result;
	}
	return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
	unsigned char *bytes = buffer;
	size_t received = 0;

	while (received < length) {
		ssize_t result = read(fd, bytes + received, length - received);

		if (result < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (result == 0) {
			errno = EIO;
			return -1;
		}
		received += (size_t)result;
	}
	return 0;
}

static int pwrite_all(int fd, const void *buffer, size_t length, off_t offset)
{
	const unsigned char *bytes = buffer;
	size_t written = 0;

	while (written < length) {
		ssize_t result = pwrite(fd, bytes + written, length - written,
					offset + (off_t)written);

		if (result < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (result == 0) {
			errno = EIO;
			return -1;
		}
		written += (size_t)result;
	}
	return 0;
}

static int pread_all(int fd, void *buffer, size_t length, off_t offset)
{
	unsigned char *bytes = buffer;
	size_t received = 0;

	while (received < length) {
		ssize_t result = pread(fd, bytes + received, length - received,
				       offset + (off_t)received);

		if (result < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (result == 0) {
			errno = EIO;
			return -1;
		}
		received += (size_t)result;
	}
	return 0;
}

static uint64_t memory_pattern(unsigned int worker, unsigned int round,
			       unsigned int slot)
{
	return UINT64_C(0x9e3779b97f4a7c15) ^
	       ((uint64_t)worker << 48) ^ ((uint64_t)round << 8) ^ slot;
}

static struct workload_message make_message(unsigned int worker,
					    unsigned int round)
{
	struct workload_message message = {
		.magic = UINT64_C(0x4153544552494e41) ^
			 ((uint64_t)worker << 32) ^ round,
		.worker = worker,
		.round = round,
	};

	return message;
}

static int run_pipe_round(int read_fd, int write_fd,
			  const struct workload_message *expected)
{
	struct workload_message received;

	if (write_all(write_fd, expected, sizeof(*expected)) != 0)
		return -1;
	if (read_all(read_fd, &received, sizeof(received)) != 0)
		return -1;
	if (memcmp(&received, expected, sizeof(received)) != 0) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int pipe_retry(int pipe_fds[2])
{
	int result;

	do {
		result = pipe(pipe_fds);
	} while (result < 0 && errno == EINTR);
	return result;
}

static int unlink_retry(const char *path)
{
	int result;

	do {
		result = unlink(path);
	} while (result < 0 && errno == EINTR);
	return result;
}

static int run_file_round(unsigned int worker, unsigned int round,
			  const struct workload_message *expected)
{
	char path[128];
	struct workload_message received;
	int fd = -1;
	int path_exists = 0;
	int path_length = snprintf(path, sizeof(path), FILE_PREFIX "-%ld-%u-%u",
				  (long)getpid(), worker, round);

	if (path_length < 0) {
		errno = EIO;
		return -1;
	}
	if ((size_t)path_length >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	do {
		fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	} while (fd < 0 && errno == EINTR);
	if (fd < 0)
		return -1;
	path_exists = 1;

	if (unlink_retry(path) != 0 && errno != ENOENT)
		goto fail;
	path_exists = 0;
	if (pwrite_all(fd, expected, sizeof(*expected), 0) != 0)
		goto fail;
	if (pread_all(fd, &received, sizeof(received), 0) != 0)
		goto fail;
	if (memcmp(&received, expected, sizeof(received)) != 0) {
		errno = EIO;
		goto fail;
	}
	if (close(fd) != 0)
		return -1;
	return 0;

fail: {
	int saved_errno = errno != 0 ? errno : EIO;

	(void)close(fd);
	if (path_exists)
		(void)unlink_retry(path);
	errno = saved_errno;
	return -1;
}
}

static void *run_worker(void *argument)
{
	struct worker_context *context = argument;
	long page_size_value = sysconf(_SC_PAGESIZE);
	size_t page_size = 0;
	size_t mapping_size = 0;
	void *mapping = MAP_FAILED;
	int pipe_fds[2] = { -1, -1 };
	volatile uint64_t *slots[SLOT_COUNT] = { NULL, NULL, NULL, NULL };

	if (page_size_value <= 0) {
		record_failure(context, "sysconf(_SC_PAGESIZE)",
			       errno != 0 ? errno : EINVAL);
	} else if ((uint64_t)page_size_value > SIZE_MAX / 2U) {
		record_failure(context, "page size overflow", EOVERFLOW);
	} else {
		page_size = (size_t)page_size_value;
		mapping_size = page_size * 2U;
		if (page_size < sizeof(uint64_t)) {
			record_failure(context, "page size is too small", EINVAL);
		} else {
			mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (mapping == MAP_FAILED) {
				record_failure(context, "mmap", errno);
			} else if (pipe_retry(pipe_fds) != 0) {
				record_failure(context, "pipe", errno);
			} else {
				unsigned char *bytes = mapping;

				slots[0] = (volatile uint64_t *)bytes;
				slots[1] = (volatile uint64_t *)(bytes + page_size -
							  sizeof(uint64_t));
				slots[2] = (volatile uint64_t *)(bytes + page_size);
				slots[3] = (volatile uint64_t *)(bytes + mapping_size -
							  sizeof(uint64_t));
			}
		}
	}

	__atomic_fetch_add(&context->gate->ready_count, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&context->gate->start, __ATOMIC_ACQUIRE))
		__asm__ __volatile__("pause" ::: "memory");

	if (context->error_number == 0) {
		for (unsigned int round = 0; round < ROUND_COUNT; round++) {
			struct workload_message message =
				make_message(context->worker, round);

			for (unsigned int slot = 0; slot < SLOT_COUNT; slot++)
				*slots[slot] = memory_pattern(context->worker,
							      round, slot);
			for (unsigned int slot = 0; slot < SLOT_COUNT; slot++) {
				if (*slots[slot] != memory_pattern(context->worker,
									  round, slot)) {
					record_failure(context,
						       "mmap boundary check", EIO);
					break;
				}
			}
			if (context->error_number != 0)
				break;

			if (run_pipe_round(pipe_fds[0], pipe_fds[1],
					   &message) != 0) {
				record_failure(context, "pipe transfer/check", errno);
				break;
			}
			if (run_file_round(context->worker, round, &message) != 0) {
				record_failure(context, "temporary file transfer/check",
					       errno);
				break;
			}
		}
	}

	for (unsigned int i = 0; i < 2; i++) {
		if (pipe_fds[i] >= 0 && close(pipe_fds[i]) != 0)
			record_failure(context, "close pipe fd", errno);
	}
	if (mapping != MAP_FAILED && munmap(mapping, mapping_size) != 0)
		record_failure(context, "munmap", errno);
	return NULL;
}

int main(void)
{
	struct start_gate gate = { 0 };
	struct worker_context contexts[WORKER_COUNT] = { 0 };
	pthread_t threads[WORKER_COUNT];
	unsigned int created = 0;
	int thread_error = 0;

	for (unsigned int worker = 0; worker < WORKER_COUNT; worker++) {
		contexts[worker].worker = worker;
		contexts[worker].gate = &gate;
		thread_error = pthread_create(&threads[worker], NULL, run_worker,
					      &contexts[worker]);
		if (thread_error != 0)
			break;
		created++;
	}

	while (__atomic_load_n(&gate.ready_count, __ATOMIC_ACQUIRE) !=
	       (int)created)
		__asm__ __volatile__("pause" ::: "memory");
	__atomic_store_n(&gate.start, 1, __ATOMIC_RELEASE);

	int join_error = 0;
	for (unsigned int worker = 0; worker < created; worker++) {
		int result = pthread_join(threads[worker], NULL);

		if (result != 0 && join_error == 0)
			join_error = result;
	}

	if (thread_error != 0) {
		fprintf(stderr, "pthread_create failed: %s\n",
			strerror(thread_error));
		return EXIT_FAILURE;
	}
	if (join_error != 0) {
		fprintf(stderr, "pthread_join failed: %s\n", strerror(join_error));
		return EXIT_FAILURE;
	}
	for (unsigned int worker = 0; worker < WORKER_COUNT; worker++) {
		if (contexts[worker].error_number != 0) {
			fprintf(stderr,
				"SANITIZER_WORKLOAD_FAIL worker=%u operation=%s errno=%d (%s)\n",
				worker, contexts[worker].operation,
				contexts[worker].error_number,
				strerror(contexts[worker].error_number));
			return EXIT_FAILURE;
		}
	}

	printf("SANITIZER_WORKLOAD_PASS workers=8 rounds=256\n");
	return EXIT_SUCCESS;
}
