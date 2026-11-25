/* SPDX-License-Identifier: MPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_TRACE_PC 0UL
#define KCOV_TRACE_CMP 1UL
#define KCOV_WORDS 1048576UL
#define KCOV_BYTES (KCOV_WORDS * sizeof(uint64_t))
#define KCOV_PC_CAPACITY (KCOV_WORDS - 1UL)
#define KCOV_CMP_CAPACITY ((KCOV_WORDS - 1UL) / 4UL)
#define MAX_WORKERS 4
#define PAGE_BYTES 4096UL
#define GETPID_BASE_ITERATIONS 20000UL
#define PIPE_BASE_ITERATIONS 2000UL
#define FILE_BASE_ITERATIONS 500UL
#define MMAP_BASE_ITERATIONS 1000UL

_Static_assert(sizeof(unsigned long) == sizeof(uint64_t),
               "KCOV x86_64 entries must be 64 bits");

#define REQUIRE(condition, ...)                                                \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                     \
      fprintf(stderr, __VA_ARGS__);                                            \
      fprintf(stderr, " (errno=%d: %s)\n", errno, strerror(errno));            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

enum trace_mode {
  TRACE_OFF,
  TRACE_PC,
  TRACE_CMP,
};

enum workload_kind {
  WORKLOAD_GETPID,
  WORKLOAD_PIPE,
  WORKLOAD_FILE,
  WORKLOAD_MMAP,
};

struct start_gate {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  unsigned int ready;
  int go;
};

struct worker_context {
  struct start_gate *gate;
  pthread_barrier_t *finish_barrier;
  enum trace_mode trace;
  enum workload_kind workload;
  unsigned int worker_id;
  uint64_t iterations;
  pid_t expected_pid;
  uid_t expected_uid;
  int pipe_fds[2];
  char temp_dir[PATH_MAX];
  char file_path[PATH_MAX];
  int kcov_fd;
  volatile uint64_t *kcov_area;
  uint8_t payload[PAGE_BYTES];
  uint8_t readback[PAGE_BYTES];
  uint64_t records;
  uint64_t max_records;
  uint64_t syscall_calls;
  uint64_t end_ns;
};

struct workload_result {
  uint64_t elapsed_ns;
  uint64_t total_ops;
  uint64_t total_records;
  uint64_t max_records;
  uint64_t syscall_calls;
  uint64_t memfree_kb;
};

static const char *trace_name(enum trace_mode trace) {
  switch (trace) {
  case TRACE_OFF:
    return "off";
  case TRACE_PC:
    return "pc";
  case TRACE_CMP:
    return "cmp";
  }
  return "invalid";
}

static const char *workload_name(enum workload_kind workload) {
  switch (workload) {
  case WORKLOAD_GETPID:
    return "syscalls";
  case WORKLOAD_PIPE:
    return "pipe";
  case WORKLOAD_FILE:
    return "file";
  case WORKLOAD_MMAP:
    return "mmap";
  }
  return "invalid";
}

static uint64_t workload_base_iterations(enum workload_kind workload) {
  switch (workload) {
  case WORKLOAD_GETPID:
    return GETPID_BASE_ITERATIONS;
  case WORKLOAD_PIPE:
    return PIPE_BASE_ITERATIONS;
  case WORKLOAD_FILE:
    return FILE_BASE_ITERATIONS;
  case WORKLOAD_MMAP:
    return MMAP_BASE_ITERATIONS;
  }
  return 0;
}

static uint64_t record_capacity(enum trace_mode trace) {
  if (trace == TRACE_PC)
    return KCOV_PC_CAPACITY;
  if (trace == TRACE_CMP)
    return KCOV_CMP_CAPACITY;
  return 0;
}

static uint64_t monotonic_ns(void) {
  struct timespec time;

  REQUIRE(clock_gettime(CLOCK_MONOTONIC, &time) == 0, "clock_gettime failed");
  return (uint64_t)time.tv_sec * 1000000000ULL + (uint64_t)time.tv_nsec;
}

static uint64_t read_memfree_kb(void) {
  FILE *file = fopen("/proc/meminfo", "r");
  char line[256];
  uint64_t value = 0;

  REQUIRE(file != NULL, "cannot open /proc/meminfo");
  while (fgets(line, sizeof(line), file) != NULL) {
    if (sscanf(line, "MemFree: %" SCNu64 " kB", &value) == 1)
      break;
  }
  REQUIRE(!ferror(file), "error reading /proc/meminfo");
  REQUIRE(fclose(file) == 0, "cannot close /proc/meminfo");
  REQUIRE(value > 0, "MemFree was not found in /proc/meminfo");
  return value;
}

static int is_json_safe_path(const char *path) {
  for (const unsigned char *cursor = (const unsigned char *)path;
       *cursor != '\0'; cursor++) {
    if (*cursor < 0x20 || *cursor == '"' || *cursor == '\\')
      return 0;
  }
  return 1;
}

static int is_writable_tmpfs(const char *path) {
  struct statfs stats;

  return statfs(path, &stats) == 0 &&
         (unsigned long)stats.f_type == (unsigned long)TMPFS_MAGIC &&
         access(path, W_OK | X_OK) == 0;
}

static const char *find_tmpfs_root(void) {
  static const char *const candidates[] = {"/tmp", "/dev/shm", "/run"};
  const char *override = getenv("BENCH_TMPDIR");

  if (override != NULL && override[0] != '\0')
    return is_json_safe_path(override) && is_writable_tmpfs(override) ? override
                                                                      : NULL;
  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    if (is_writable_tmpfs(candidates[i]))
      return candidates[i];
  }
  return NULL;
}

static void fill_payload(uint8_t *payload) {
  for (size_t i = 0; i < PAGE_BYTES; i++)
    payload[i] = (uint8_t)((i * 37U + 11U) & 0xffU);
}

static long counted_syscall(struct worker_context *context, long number,
                            long a1, long a2, long a3, long a4, long a5,
                            long a6) {
  context->syscall_calls++;
  return syscall(number, a1, a2, a3, a4, a5, a6);
}

static uint64_t read_kcov_count(struct worker_context *context) {
  uint64_t count;
  uint64_t capacity = record_capacity(context->trace);

  count = __atomic_load_n(&context->kcov_area[0], __ATOMIC_ACQUIRE);
  REQUIRE(count > 0, "%s worker %u recorded zero %s entries",
          workload_name(context->workload), context->worker_id,
          trace_name(context->trace));
  REQUIRE(count < capacity,
          "%s worker %u saturated the %s buffer: count=%" PRIu64
          " capacity=%" PRIu64,
          workload_name(context->workload), context->worker_id,
          trace_name(context->trace), count, capacity);
  return count;
}

static void check_readback(struct worker_context *context) {
  REQUIRE(memcmp(context->payload, context->readback, PAGE_BYTES) == 0,
          "%s worker %u read data mismatch", workload_name(context->workload),
          context->worker_id);
}

static void write_all(struct worker_context *context, int fd,
                      const uint8_t *buffer, size_t length) {
  size_t offset = 0;

  while (offset < length) {
    long written =
        counted_syscall(context, SYS_write, fd, (long)(buffer + offset),
                        (long)(length - offset), 0, 0, 0);
    if (written < 0 && errno == EINTR)
      continue;
    REQUIRE(written > 0, "%s worker %u write failed",
            workload_name(context->workload), context->worker_id);
    offset += (size_t)written;
  }
}

static void read_all(struct worker_context *context, int fd, uint8_t *buffer,
                     size_t length) {
  size_t offset = 0;

  while (offset < length) {
    long received =
        counted_syscall(context, SYS_read, fd, (long)(buffer + offset),
                        (long)(length - offset), 0, 0, 0);
    if (received < 0 && errno == EINTR)
      continue;
    REQUIRE(received > 0, "%s worker %u read failed or reached EOF",
            workload_name(context->workload), context->worker_id);
    offset += (size_t)received;
  }
}

static void run_getpid_iteration(struct worker_context *context) {
  long pid = counted_syscall(context, SYS_getpid, 0, 0, 0, 0, 0, 0);
  long uid = counted_syscall(context, SYS_getuid, 0, 0, 0, 0, 0, 0);

  REQUIRE(pid == (long)context->expected_pid,
          "getpid returned %ld, expected %ld", pid,
          (long)context->expected_pid);
  REQUIRE(uid == (long)context->expected_uid,
          "getuid returned %ld, expected %ld", uid,
          (long)context->expected_uid);
}

static void run_pipe_iteration(struct worker_context *context) {
  write_all(context, context->pipe_fds[1], context->payload, PAGE_BYTES);
  read_all(context, context->pipe_fds[0], context->readback, PAGE_BYTES);
  check_readback(context);
}

static void run_file_iteration(struct worker_context *context,
                               uint64_t iteration) {
  long fd;
  long result;
  int length = snprintf(context->file_path, sizeof(context->file_path),
                        "%s/%08" PRIu64, context->temp_dir, iteration);

  REQUIRE(length > 0 && (size_t)length < sizeof(context->file_path),
          "temporary file path is too long");
  fd = counted_syscall(context, SYS_openat, AT_FDCWD, (long)context->file_path,
                       O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600, 0, 0);
  REQUIRE(fd >= 0, "tmpfs openat failed for %s", context->file_path);
  write_all(context, (int)fd, context->payload, PAGE_BYTES);
  result = counted_syscall(context, SYS_lseek, fd, 0, SEEK_SET, 0, 0, 0);
  REQUIRE(result == 0, "tmpfs lseek failed for %s", context->file_path);
  read_all(context, (int)fd, context->readback, PAGE_BYTES);
  check_readback(context);
  result = counted_syscall(context, SYS_close, fd, 0, 0, 0, 0, 0);
  REQUIRE(result == 0, "tmpfs close failed for %s", context->file_path);
  result = counted_syscall(context, SYS_unlinkat, AT_FDCWD,
                           (long)context->file_path, 0, 0, 0, 0);
  REQUIRE(result == 0, "tmpfs unlinkat failed for %s", context->file_path);
}

static uint8_t mmap_pattern(size_t offset, uint64_t iteration) {
  return (uint8_t)((offset * 29U + iteration * 7U + 3U) & 0xffU);
}

static void run_mmap_iteration(struct worker_context *context,
                               uint64_t iteration) {
  long address =
      counted_syscall(context, SYS_mmap, 0, PAGE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  volatile uint8_t *page;
  long result;

  REQUIRE(address != -1, "anonymous mmap failed");
  page = (volatile uint8_t *)address;
  for (size_t offset = 0; offset < PAGE_BYTES; offset += 64)
    page[offset] = mmap_pattern(offset, iteration);
  page[PAGE_BYTES - 1] = mmap_pattern(PAGE_BYTES - 1, iteration);
  for (size_t offset = 0; offset < PAGE_BYTES; offset += 64)
    REQUIRE(page[offset] == mmap_pattern(offset, iteration),
            "mmap data mismatch at offset %zu", offset);
  REQUIRE(page[PAGE_BYTES - 1] == mmap_pattern(PAGE_BYTES - 1, iteration),
          "mmap final byte mismatch");
  result =
      counted_syscall(context, SYS_munmap, address, PAGE_BYTES, 0, 0, 0, 0);
  REQUIRE(result == 0, "munmap failed");
}

static void run_one_iteration(struct worker_context *context,
                              uint64_t iteration, int collect_stats) {
  uint64_t count = 0;

  if (context->trace != TRACE_OFF)
    __atomic_store_n(&context->kcov_area[0], 0, __ATOMIC_RELAXED);

  switch (context->workload) {
  case WORKLOAD_GETPID:
    run_getpid_iteration(context);
    break;
  case WORKLOAD_PIPE:
    run_pipe_iteration(context);
    break;
  case WORKLOAD_FILE:
    run_file_iteration(context, iteration);
    break;
  case WORKLOAD_MMAP:
    run_mmap_iteration(context, iteration);
    break;
  }

  if (context->trace != TRACE_OFF) {
    count = read_kcov_count(context);
    if (collect_stats) {
      REQUIRE(UINT64_MAX - context->records >= count, "record count overflow");
      context->records += count;
      if (count > context->max_records)
        context->max_records = count;
    }
  }
}

static void prepare_kcov(struct worker_context *context) {
  unsigned long trace_type;
  void *mapping;

  if (context->trace == TRACE_OFF)
    return;

  context->kcov_fd = open("/dev/kcov", O_RDWR | O_CLOEXEC);
  REQUIRE(context->kcov_fd >= 0, "worker %u cannot open /dev/kcov",
          context->worker_id);
  REQUIRE(ioctl(context->kcov_fd, KCOV_INIT_TRACE, (unsigned long)KCOV_WORDS) ==
              0,
          "worker %u KCOV_INIT_TRACE failed", context->worker_id);
  mapping = mmap(NULL, KCOV_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED,
                 context->kcov_fd, 0);
  REQUIRE(mapping != MAP_FAILED, "worker %u cannot map KCOV buffer",
          context->worker_id);
  context->kcov_area = mapping;
  memset((void *)context->kcov_area, 0, KCOV_BYTES);
  trace_type = context->trace == TRACE_PC ? KCOV_TRACE_PC : KCOV_TRACE_CMP;
  REQUIRE(ioctl(context->kcov_fd, KCOV_ENABLE, trace_type) == 0,
          "worker %u KCOV_ENABLE(%s) failed", context->worker_id,
          trace_name(context->trace));
}

static void cleanup_kcov(struct worker_context *context) {
  if (context->trace == TRACE_OFF)
    return;
  REQUIRE(ioctl(context->kcov_fd, KCOV_DISABLE, 0) == 0,
          "worker %u KCOV_DISABLE failed", context->worker_id);
  REQUIRE(munmap((void *)context->kcov_area, KCOV_BYTES) == 0,
          "worker %u cannot unmap KCOV buffer", context->worker_id);
  REQUIRE(close(context->kcov_fd) == 0, "worker %u cannot close KCOV fd",
          context->worker_id);
}

static void wait_at_start_gate(struct worker_context *context) {
  struct start_gate *gate = context->gate;

  REQUIRE(pthread_mutex_lock(&gate->mutex) == 0,
          "cannot lock worker start gate");
  gate->ready++;
  REQUIRE(pthread_cond_broadcast(&gate->condition) == 0,
          "cannot signal ready worker");
  while (!gate->go)
    REQUIRE(pthread_cond_wait(&gate->condition, &gate->mutex) == 0,
            "worker start gate wait failed");
  REQUIRE(pthread_mutex_unlock(&gate->mutex) == 0,
          "cannot unlock worker start gate");
}

static void *worker_main(void *argument) {
  struct worker_context *context = argument;

  prepare_kcov(context);
  fill_payload(context->payload);
  for (uint64_t i = 0; i < context->iterations; i++)
    run_one_iteration(context, i, 0);
  context->syscall_calls = 0;
  context->records = 0;
  context->max_records = 0;
  if (context->trace != TRACE_OFF)
    __atomic_store_n(&context->kcov_area[0], 0, __ATOMIC_RELAXED);

  wait_at_start_gate(context);
  for (uint64_t i = 0; i < context->iterations; i++)
    run_one_iteration(context, i, 1);
  context->end_ns = monotonic_ns();
  int barrier_status = pthread_barrier_wait(context->finish_barrier);
  REQUIRE(barrier_status == 0 ||
              barrier_status == PTHREAD_BARRIER_SERIAL_THREAD,
          "worker %u finish barrier failed", context->worker_id);
  cleanup_kcov(context);
  return NULL;
}

static uint64_t checked_iterations(enum workload_kind workload,
                                   uint64_t scale) {
  uint64_t base = workload_base_iterations(workload);

  REQUIRE(base > 0 && scale <= UINT64_MAX / base, "iteration count overflow");
  return base * scale;
}

static void prepare_workload_resources(enum workload_kind workload,
                                       struct worker_context *contexts,
                                       unsigned int workers,
                                       const char *tmpfs_root) {
  for (unsigned int i = 0; i < workers; i++) {
    contexts[i].pipe_fds[0] = -1;
    contexts[i].pipe_fds[1] = -1;
    contexts[i].kcov_fd = -1;
    contexts[i].expected_pid = getpid();
    contexts[i].expected_uid = getuid();
    if (workload == WORKLOAD_PIPE) {
      REQUIRE(pipe(contexts[i].pipe_fds) == 0, "cannot create worker %u pipe",
              i);
    } else if (workload == WORKLOAD_FILE) {
      int length = snprintf(contexts[i].temp_dir, sizeof(contexts[i].temp_dir),
                            "%s/asterinas-kcov-bench-XXXXXX", tmpfs_root);
      REQUIRE(length > 0 && (size_t)length < sizeof(contexts[i].temp_dir),
              "worker temporary directory path is too long");
      REQUIRE(mkdtemp(contexts[i].temp_dir) != NULL,
              "cannot create tmpfs directory for worker %u", i);
    }
  }
}

static void cleanup_workload_resources(enum workload_kind workload,
                                       struct worker_context *contexts,
                                       unsigned int workers) {
  for (unsigned int i = 0; i < workers; i++) {
    if (workload == WORKLOAD_PIPE) {
      REQUIRE(close(contexts[i].pipe_fds[0]) == 0,
              "cannot close worker %u pipe read fd", i);
      REQUIRE(close(contexts[i].pipe_fds[1]) == 0,
              "cannot close worker %u pipe write fd", i);
    } else if (workload == WORKLOAD_FILE) {
      REQUIRE(rmdir(contexts[i].temp_dir) == 0,
              "cannot remove worker tmpfs directory %s", contexts[i].temp_dir);
    }
  }
}

static struct workload_result
run_workload(enum workload_kind workload, enum trace_mode trace,
             unsigned int workers, uint64_t scale, pid_t expected_pid,
             uid_t expected_uid, const char *tmpfs_root) {
  struct worker_context contexts[MAX_WORKERS] = {0};
  pthread_t threads[MAX_WORKERS];
  struct start_gate gate = {
      .mutex = PTHREAD_MUTEX_INITIALIZER,
      .condition = PTHREAD_COND_INITIALIZER,
  };
  pthread_barrier_t finish_barrier;
  struct workload_result result = {0};
  uint64_t start_ns, max_end_ns = 0;
  uint64_t iterations = checked_iterations(workload, scale);

  prepare_workload_resources(workload, contexts, workers, tmpfs_root);
  REQUIRE(pthread_barrier_init(&finish_barrier, NULL, workers) == 0,
          "cannot initialize worker finish barrier");
  for (unsigned int i = 0; i < workers; i++) {
    contexts[i].gate = &gate;
    contexts[i].finish_barrier = &finish_barrier;
    contexts[i].trace = trace;
    contexts[i].workload = workload;
    contexts[i].worker_id = i;
    contexts[i].iterations = iterations;
    contexts[i].expected_pid = expected_pid;
    contexts[i].expected_uid = expected_uid;
    REQUIRE(pthread_create(&threads[i], NULL, worker_main, &contexts[i]) == 0,
            "cannot create worker %u", i);
  }

  REQUIRE(pthread_mutex_lock(&gate.mutex) == 0, "cannot lock ready gate");
  while (gate.ready < workers)
    REQUIRE(pthread_cond_wait(&gate.condition, &gate.mutex) == 0,
            "waiting for worker warmup failed");
  result.memfree_kb = read_memfree_kb();
  start_ns = monotonic_ns();
  gate.go = 1;
  REQUIRE(pthread_cond_broadcast(&gate.condition) == 0,
          "cannot release workers");
  REQUIRE(pthread_mutex_unlock(&gate.mutex) == 0, "cannot unlock ready gate");

  for (unsigned int i = 0; i < workers; i++)
    REQUIRE(pthread_join(threads[i], NULL) == 0, "cannot join worker %u", i);
  REQUIRE(pthread_barrier_destroy(&finish_barrier) == 0,
          "cannot destroy worker finish barrier");

  for (unsigned int i = 0; i < workers; i++) {
    if (contexts[i].end_ns > max_end_ns)
      max_end_ns = contexts[i].end_ns;
    result.total_records += contexts[i].records;
    result.syscall_calls += contexts[i].syscall_calls;
    if (contexts[i].max_records > result.max_records)
      result.max_records = contexts[i].max_records;
  }
  REQUIRE(max_end_ns >= start_ns, "monotonic end time precedes start");
  result.elapsed_ns = max_end_ns - start_ns;
  REQUIRE(UINT64_MAX / workers >= iterations, "total operation count overflow");
  result.total_ops = iterations * workers;

  cleanup_workload_resources(workload, contexts, workers);
  REQUIRE(pthread_cond_destroy(&gate.condition) == 0,
          "cannot destroy worker condition");
  REQUIRE(pthread_mutex_destroy(&gate.mutex) == 0,
          "cannot destroy worker mutex");
  return result;
}

static uint64_t parse_positive(const char *text, const char *name) {
  char *end = NULL;
  unsigned long long value;

  REQUIRE(text != NULL && text[0] != '\0', "%s must not be empty", name);
  for (const unsigned char *cursor = (const unsigned char *)text;
       *cursor != '\0'; cursor++)
    REQUIRE(*cursor >= '0' && *cursor <= '9',
            "%s must contain only decimal digits: %s", name, text);

  errno = 0;
  value = strtoull(text, &end, 10);
  REQUIRE(errno == 0 && end != text && *end == '\0' && value > 0,
          "invalid %s: %s", name, text);
  return (uint64_t)value;
}

int main(int argc, char **argv) {
  static const enum workload_kind workloads[] = {
      WORKLOAD_GETPID,
      WORKLOAD_PIPE,
      WORKLOAD_FILE,
      WORKLOAD_MMAP,
  };
  enum trace_mode trace;
  unsigned int workers;
  uint64_t scale;
  pid_t expected_pid;
  uid_t expected_uid;
  const char *tmpfs_root;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s TRACE WORKERS SCALE\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (strcmp(argv[1], "off") == 0)
    trace = TRACE_OFF;
  else if (strcmp(argv[1], "pc") == 0)
    trace = TRACE_PC;
  else if (strcmp(argv[1], "cmp") == 0)
    trace = TRACE_CMP;
  else {
    fprintf(stderr, "TRACE must be off, pc, or cmp\n");
    return EXIT_FAILURE;
  }
  if (strcmp(argv[2], "1") == 0)
    workers = 1;
  else if (strcmp(argv[2], "4") == 0)
    workers = 4;
  else {
    fprintf(stderr, "WORKERS must be 1 or 4\n");
    return EXIT_FAILURE;
  }
  scale = parse_positive(argv[3], "SCALE");
  expected_pid = getpid();
  expected_uid = getuid();
  tmpfs_root = find_tmpfs_root();
  REQUIRE(tmpfs_root != NULL,
          "no writable tmpfs found at /dev/shm, /tmp, or /run");

  for (size_t i = 0; i < sizeof(workloads) / sizeof(workloads[0]); i++) {
    enum workload_kind workload = workloads[i];
    struct workload_result result =
        run_workload(workload, trace, workers, scale, expected_pid,
                     expected_uid, tmpfs_root);
    uint64_t iterations = checked_iterations(workload, scale);
    uint64_t capacity = record_capacity(trace);

    printf("BENCH_RESULT {\"workload\":\"%s\","
           "\"trace\":\"%s\",\"workers\":%u,"
           "\"iterations\":%" PRIu64 ","
           "\"total_ops\":%" PRIu64 ","
           "\"elapsed_ns\":%" PRIu64 ","
           "\"records\":%" PRIu64 ","
           "\"max_records\":%" PRIu64 ","
           "\"capacity\":%" PRIu64 ","
           "\"memfree_kib\":%" PRIu64 ","
           "\"scale\":%" PRIu64 ","
           "\"syscall_calls\":%" PRIu64 ","
           "\"capacity_words\":%lu,"
           "\"capacity_unit\":\"%s\","
           "\"warmup_iterations_per_worker\":%" PRIu64 ","
           "\"join_included\":false,"
           "\"validation\":\"passed\"",
           workload_name(workload), trace_name(trace), workers, iterations,
           result.total_ops, result.elapsed_ns, result.total_records,
           result.max_records, capacity, result.memfree_kb, scale,
           result.syscall_calls, KCOV_WORDS,
           trace == TRACE_PC    ? "pc_records"
           : trace == TRACE_CMP ? "cmp_records"
                                : "none",
           iterations);
    printf(",\"tmpfs_root\":\"%s\"",
           workload == WORKLOAD_FILE ? tmpfs_root : "");
    printf("}\n");
    REQUIRE(fflush(stdout) == 0, "cannot flush benchmark result");
  }
  printf("BENCH_PROGRAM_PASS\n");
  REQUIRE(fflush(stdout) == 0, "cannot flush benchmark success marker");
  return EXIT_SUCCESS;
}