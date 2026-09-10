#ifndef CODEWIRE_VZ_RUNNER_IPC_H
#define CODEWIRE_VZ_RUNNER_IPC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CW_VZ_MAX_FRAME_BYTES ((size_t)16384)
#define CW_VZ_DESCRIPTOR_COUNT ((size_t)4)
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

#endif
