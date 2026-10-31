#ifndef CODEWIRE_VZ_RUNNER_IPC_H
#define CODEWIRE_VZ_RUNNER_IPC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CW_VZ_MAX_FRAME_BYTES ((size_t)16384)
#define CW_VZ_DESCRIPTOR_COUNT ((size_t)4)
#define CW_VZ_PRODUCTION_DESCRIPTOR_COUNT ((size_t)9)
#define CW_VZ_PRODUCTION_ARTIFACT_COUNT ((size_t)6)
#define CW_VZ_WORKLOAD_NETWORK_DESCRIPTOR_COUNT ((size_t)10)
#define CW_VZ_BRIDGE_BUFFER_BYTES ((size_t)32768)
#define CW_VZ_FRAME_HEADER_BYTES ((size_t)4)

enum cw_vz_ipc_result {
    CW_VZ_IPC_INVALID_ARGUMENT = -1,
    CW_VZ_IPC_NOT_PRIVATE_STREAM = -2,
    CW_VZ_IPC_PEER_MISMATCH = -3,
    CW_VZ_IPC_RECEIVE_FAILED = -4,
    CW_VZ_IPC_FRAME_INVALID = -5,
    CW_VZ_IPC_DESCRIPTOR_SET_INVALID = -6,
    CW_VZ_IPC_CLOEXEC_FAILED = -7,
    CW_VZ_IPC_SEND_FAILED = -8,
};

// Receive one four-byte-length-prefixed frame and exactly four descriptors from
// a same-EUID connected AF_UNIX SOCK_STREAM peer. The header, payload, and
// descriptor set must accompany the peer's first bytes; the receiver handles
// partial stream reads of the length header and payload. On failure, every
// received descriptor is closed.
ssize_t cw_vz_receive_request(
    int socket_fd,
    uint8_t *buffer,
    size_t buffer_capacity,
    int descriptors[CW_VZ_DESCRIPTOR_COUNT]
);

// Return one only when every descriptor refers to a different filesystem
// object. Descriptor numbers alone are insufficient because SCM_RIGHTS creates
// new receiver numbers for duplicated references to the same object.
int cw_vz_descriptors_are_distinct_files(
    const int descriptors[CW_VZ_DESCRIPTOR_COUNT]
);

int cw_vz_send_response(int socket_fd, const uint8_t *buffer, size_t size);

// Receive the one-byte start command in a normal length-prefixed frame after
// descriptor admission. No further descriptors or authority can be added.
int cw_vz_receive_start(int socket_fd);

// Separate fixed-count entrypoint; descriptor count never comes from the wire.
ssize_t cw_vz_receive_production_request(
    int socket_fd, uint8_t *buffer, size_t buffer_capacity,
    int descriptors[CW_VZ_PRODUCTION_DESCRIPTOR_COUNT]
);
int cw_vz_validate_production_descriptors(
    int control_fd, const int descriptors[CW_VZ_PRODUCTION_DESCRIPTOR_COUNT]
);

// Eight boot artifacts and two private channels; no host packet channel.
ssize_t cw_vz_receive_workload_network_request(
    int socket_fd, uint8_t *buffer, size_t buffer_capacity,
    int descriptors[CW_VZ_WORKLOAD_NETWORK_DESCRIPTOR_COUNT]
);
int cw_vz_validate_workload_network_descriptors(
    int control_fd, const int descriptors[CW_VZ_WORKLOAD_NETWORK_DESCRIPTOR_COUNT]
);

// Bounded, opaque forwarding. No protocol parsing, address selection or dial.
// Returns 0 on cancellation, 1 on EOF, 2 after preserved guest EOF has drained
// and half-closed local output, and -1 on error/deadline. Does not close
// descriptors; their owner must retain them until the bridge has returned.
int cw_vz_bridge_streams(
    int local_fd, int guest_fd, int cancellation_fd, int seconds, int preserve_guest_eof
);
// Daemon-only directional shutdown. Local EOF is forwarded as guest SHUT_WR
// after pending requests drain; it is never proof of guest EOF. Returns 2 only
// after actual guest EOF, drained forwarding buffers and local SHUT_WR, 0 on
// cancellation, and -1 on error/deadline. The caller retains both endpoints.
int cw_vz_bridge_daemon_streams(int local_fd, int guest_fd, int cancellation_fd, int seconds);
int cw_vz_prepare_control(int socket_fd);
int cw_vz_control_event(int socket_fd, int milliseconds);

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

// Irreversibly confine this whole process with one inline Seatbelt profile.
// Returns 0, or -1 when the profile was not applied.
int cw_vz_apply_sandbox(const char *profile);

#endif
