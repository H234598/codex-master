/* Linux/glibc >= 2.39 runtime-image spawn contract. */
#define _GNU_SOURCE 1

#include <errno.h>
#include <features.h>
#include <spawn.h>
#include <sys/prctl.h>

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
codex_master_enable_subreaper(void)
{
  if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1)
    return errno;
  return 0;
}

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
