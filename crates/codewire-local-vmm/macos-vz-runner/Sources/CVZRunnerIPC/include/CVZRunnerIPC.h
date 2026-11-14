#ifndef CODEWIRE_VZ_RUNNER_IPC_H
#define CODEWIRE_VZ_RUNNER_IPC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CW_VZ_BRIDGE_BUFFER_BYTES ((size_t)32768)

// Product VM hybrid vsock. Bind a new owner-only listener at an absolute path
// (never replacing one); returns the descriptor or -1.
int cw_vz_listen_unix(const char *path);
// Read exactly one "CONNECT <decimal port>\n" line within two seconds.
int cw_vz_read_connect(int fd, uint32_t *port);
int cw_vz_write_all(int fd, const uint8_t *bytes, size_t size);
// Copy both directions until each has reached EOF, forwarding each EOF as a
// write shutdown. Returns 0 after both EOFs and -1 on error. Does not close.
int cw_vz_splice(int a, int b);

// Product VM shared directory. Open `path` without following a symlink in any
// component and require this user's directory `device`/`inode` (raw st_dev and
// st_ino), still named exactly `path`. Returns 0 on a match and -1 otherwise.
int cw_vz_verify_shared_directory(const char *path, uint32_t device, uint64_t inode);

// Product VM control channel (#4654). The runner passes one end of an unnamed
// AF_UNIX stream socketpair as an inherited descriptor. Returns 0 when `fd`
// is exactly that (a socket, SOCK_STREAM, AF_UNIX, no name) and marks it
// close-on-exec; -1 for anything else, a closed number included.
int cw_vz_check_control(int fd);
// Read up to `size` control bytes. Ancillary data is never accepted: any
// descriptors that arrive with it are closed and -2 is returned. Returns the
// byte count, 0 at EOF, or -1 on error.
ssize_t cw_vz_control_read(int fd, uint8_t *buffer, size_t size);

// Irreversibly confine this whole process with one inline Seatbelt profile.
// Returns 0, or -1 when the profile was not applied.
int cw_vz_apply_sandbox(const char *profile);

#endif
