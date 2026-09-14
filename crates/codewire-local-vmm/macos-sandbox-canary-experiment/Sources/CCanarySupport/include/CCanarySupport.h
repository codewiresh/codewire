#ifndef CODEWIRE_CANARY_SUPPORT_H
#define CODEWIRE_CANARY_SUPPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  CW_CANARY_OK = 0,
  CW_CANARY_INVALID = 1,
  CW_CANARY_SYSTEM = 2,
  CW_CANARY_IDENTITY = 3,
};

enum {
  CW_CANARY_CLEANUP_COMPLETE = 0,
  CW_CANARY_CLEANUP_UNKNOWN = 1,
};

int cw_canary_listen(const char *path);
int cw_canary_connect(const char *path);
int cw_canary_accept(int listener_fd, int timeout_milliseconds);

/*
 * Spawn an exact argument-free direct child. Only descriptor 3 is inherited.
 * The caller remains the sole reaper and the child starts a fresh process
 * group.
 */
int cw_canary_spawn(const char *executable, int control_fd, pid_t *pid_out);

/* Restore the sole-reaper premise before any direct child is spawned. */
int cw_canary_normalize_sigchld(void);

/* Return 1 while the exact child is live, 0 after exit, and -1 on error. */
int cw_canary_child_live(pid_t pid);
int cw_canary_wait(pid_t pid, int timeout_milliseconds, int *status_out);

/*
 * Terminate/reap only while waitid proves pid is still our unreaped child.
 * Unknown ownership (including ECHILD) never authorizes a signal.
 */
int cw_canary_cleanup_child(pid_t pid);

/* Durably replace one bounded, private checkpoint with caller-supplied bytes.
 */
int cw_canary_replace_checkpoint(const char *path, const uint8_t *bytes,
                                 size_t length);

/*
 * Bind a retained, exclusively unreaped direct child PID to its exact code.
 * This PID-only helper is never a substitute for connected-peer audit tokens.
 */
int cw_canary_verify_direct_child(pid_t pid, const char *expected_bundle,
                                  const char *expected_executable,
                                  const char *expected_identifier,
                                  const char *expected_cdhash,
                                  int expected_sandboxed);

/*
 * Bind a newly connected AF_UNIX peer to the exact admitted signed code.
 * This is intentionally not used for socketpairs created before posix_spawn:
 * Darwin reports mutable most-recent-accessor state for LOCAL_PEERPID/TOKEN.
 */
int cw_canary_verify_connected_peer(int connected_fd, pid_t expected_pid,
                                    const char *expected_bundle,
                                    const char *expected_executable,
                                    const char *expected_identifier,
                                    const char *expected_cdhash);

#ifdef __cplusplus
}
#endif

#endif
