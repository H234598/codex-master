/* Linux/glibc >= 2.39 runtime-image spawn contract. */
#define _GNU_SOURCE 1

#include <errno.h>
#include <features.h>
#include <spawn.h>

#if !defined(__linux__)
# error "codex-master runtime spawn helper requires Linux"
#endif

#if !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 39)
# error "codex-master runtime spawn helper requires glibc 2.39 or newer"
#endif

#ifndef POSIX_SPAWN_SETSID
# error "codex-master runtime spawn helper requires POSIX_SPAWN_SETSID"
#endif

int
codex_master_pidfd_spawnp(int *pidfd, int stdin_fd, int stdout_fd, int stderr_fd,
                          const char *cwd, char *const argv[], char *const envp[])
{
  posix_spawnattr_t attributes;
  posix_spawn_file_actions_t actions;
  int attributes_initialized = 0;
  int actions_initialized = 0;
  int result;

  if (pidfd == NULL || cwd == NULL || argv == NULL || argv[0] == NULL)
    return EINVAL;

  result = posix_spawnattr_init(&attributes);
  if (result != 0)
    return result;
  attributes_initialized = 1;

  result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSID);
  if (result != 0)
    goto out;

  result = posix_spawn_file_actions_init(&actions);
  if (result != 0)
    goto out;
  actions_initialized = 1;

  result = posix_spawn_file_actions_adddup2(&actions, stdin_fd, 0);
  if (result != 0)
    goto out;
  result = posix_spawn_file_actions_adddup2(&actions, stdout_fd, 1);
  if (result != 0)
    goto out;
  result = posix_spawn_file_actions_adddup2(&actions, stderr_fd, 2);
  if (result != 0)
    goto out;
  result = posix_spawn_file_actions_addchdir_np(&actions, cwd);
  if (result != 0)
    goto out;
  result = posix_spawn_file_actions_addclosefrom_np(&actions, 3);
  if (result != 0)
    goto out;

  result = pidfd_spawnp(pidfd, argv[0], &actions, &attributes, argv, envp);

out:
  if (actions_initialized)
    posix_spawn_file_actions_destroy(&actions);
  if (attributes_initialized)
    posix_spawnattr_destroy(&attributes);
  return result;
}

/* Prospective direct-child ABI. The original bounded spawn ABI above is unchanged. */
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct codex_master_owned_child_args_v1 {
  int cgroup_fd, executable_fd, cwd_fd;
  int stdin_fd, stdout_fd, stderr_fd;
  int control_fd, events_fd, d17_fd, d17_target;
  int release_fd, error_fd, kind;
  int64_t start_deadline_ns;
  char *const *argv;
  char *const *envp;
};

struct codex_master_owned_child_result_v1 {
  int pid;
  int pidfd;
};

#if defined(SYS_clone3) && defined(SYS_close_range) && defined(SYS_execveat) \
    && defined(SYS_poll) && defined(CLONE_INTO_CGROUP) && defined(CLONE_PIDFD)
#define OWNED_CHILD_NATIVE_AVAILABLE 1
static __attribute__((noreturn)) void
owned_child_fail(int error_fd, int error)
{
  (void) syscall(SYS_write, error_fd, &error, sizeof(error));
  (void) syscall(SYS_exit_group, 125);
  __builtin_unreachable();
}

static void
owned_child_dup(int source, int target, int flags, int error_fd)
{
  if (syscall(SYS_dup3, source, target, flags) < 0)
    owned_child_fail(error_fd, errno);
}

static unsigned char
owned_child_release_byte(int64_t deadline, int error_fd)
{
  struct timespec now;
  struct pollfd item = { .fd = 196, .events = POLLIN };
  unsigned char byte = 0;
  for (;;) {
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) < 0)
      owned_child_fail(error_fd, errno);
    int64_t remaining = deadline - ((int64_t) now.tv_sec * 1000000000 + now.tv_nsec);
    if (remaining <= 0)
      owned_child_fail(error_fd, ETIMEDOUT);
    int64_t milliseconds = (remaining + 999999) / 1000000;
    int wait = milliseconds > INT_MAX ? INT_MAX : (int) milliseconds;
    long ready = syscall(SYS_poll, &item, 1, wait);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0 || (item.revents & (POLLERR | POLLNVAL)))
      owned_child_fail(error_fd, ready == 0 ? ETIMEDOUT : EIO);
    long count = syscall(SYS_read, 196, &byte, 1);
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0)
      owned_child_fail(error_fd, errno);
    /* 0 is EOF, 1 is the only release byte. Any other byte is invalid. */
    return count == 0 ? 0 : (byte == 1 ? 1 : 255);
  }
}

#endif

int
codex_master_owned_child_start_v1(
  struct codex_master_owned_child_result_v1 *result,
  const struct codex_master_owned_child_args_v1 *input)
{
#ifndef OWNED_CHILD_NATIVE_AVAILABLE
  (void) result;
  (void) input;
  return ENOSYS;
#else
  int copies[11];
  int sources[11];
  struct clone_args arguments = {0};
  long child;
  int error = 0;
  if (result == NULL || input == NULL)
    return EINVAL;
  result->pid = result->pidfd = -1;
  if (input->cgroup_fd < 0 || input->executable_fd < 0 || input->cwd_fd < 0
      || input->stdin_fd < 0 || input->stdout_fd < 0 || input->stderr_fd < 0
      || input->release_fd < 0 || input->error_fd < 0
      || input->start_deadline_ns <= 0 || input->argv == NULL
      || input->argv[0] == NULL || input->envp == NULL
      || (input->kind != 1 && input->kind != 2))
    return EINVAL;
  if ((input->kind == 1 && (input->control_fd < 0 || input->events_fd < 0
                            || input->d17_fd != -1))
      || (input->kind == 2 && (input->control_fd != -1 || input->events_fd != -1
                              || input->d17_fd < 0 || input->d17_target < 3
                              || input->d17_target > 190)))
    return EINVAL;
  sources[0] = input->executable_fd;
  sources[1] = input->cwd_fd;
  sources[2] = input->stdin_fd;
  sources[3] = input->stdout_fd;
  sources[4] = input->stderr_fd;
  sources[5] = input->control_fd;
  sources[6] = input->events_fd;
  sources[7] = input->d17_fd;
  sources[8] = input->release_fd;
  sources[9] = input->error_fd;
  sources[10] = input->cgroup_fd;
  for (int index = 0; index < 11; ++index)
    copies[index] = -1;
  for (int index = 0; index < 11; ++index) {
    if (sources[index] < 0)
      continue;
    copies[index] = fcntl(sources[index], F_DUPFD_CLOEXEC, 256);
    if (copies[index] < 0) {
      error = errno;
      goto out;
    }
  }
  arguments.flags = CLONE_PIDFD | CLONE_INTO_CGROUP;
  arguments.exit_signal = SIGCHLD;
  arguments.pidfd = (uint64_t) (uintptr_t) &result->pidfd;
  arguments.cgroup = (uint64_t) copies[10];
  /* Resolves libc syscall in the parent before any child-only calls. No Python preexec. */
  errno = 0;
  child = syscall(SYS_clone3, &arguments, sizeof(arguments));
  if (child < 0) {
    error = errno;
    goto out;
  }
  if (child == 0) {
    /* All source FDs are >=256; target assignments cannot destroy a later source. */
    int error_fd = copies[9];
    owned_child_dup(copies[9], 195, O_CLOEXEC, error_fd);
    error_fd = 195;
    owned_child_dup(copies[8], 196, O_CLOEXEC, error_fd);
    owned_child_dup(copies[0], 197, O_CLOEXEC, error_fd);
    owned_child_dup(copies[2], 0, 0, error_fd);
    owned_child_dup(copies[3], 1, 0, error_fd);
    owned_child_dup(copies[4], 2, 0, error_fd);
    if (input->kind == 1) {
      owned_child_dup(copies[5], 198, 0, error_fd);
      owned_child_dup(copies[6], 199, 0, error_fd);
    } else {
      owned_child_dup(copies[7], input->d17_target, 0, error_fd);
    }
    if (syscall(SYS_fchdir, copies[1]) < 0 || syscall(SYS_setsid) < 0)
      owned_child_fail(error_fd, errno);
    for (int descriptor = 3; descriptor <= 199; ++descriptor) {
      int keep = descriptor == 195 || descriptor == 196 || descriptor == 197
        || (input->kind == 1 && (descriptor == 198 || descriptor == 199))
        || (input->kind == 2 && descriptor == input->d17_target);
      if (!keep)
        (void) syscall(SYS_close, descriptor);
    }
    if (syscall(SYS_close_range, 200U, ~0U, 0) < 0)
      owned_child_fail(error_fd, errno);
    if (owned_child_release_byte(input->start_deadline_ns, error_fd) != 1
        || owned_child_release_byte(input->start_deadline_ns, error_fd) != 0)
      owned_child_fail(error_fd, EPROTO);
    (void) syscall(SYS_close, 196);
    (void) syscall(SYS_execveat, 197, "", input->argv, input->envp, AT_EMPTY_PATH);
    owned_child_fail(error_fd, errno);
  }
  result->pid = (int) child;
out:
  for (int index = 0; index < 11; ++index)
    if (copies[index] >= 0)
      close(copies[index]);
  return error;
#endif
}
