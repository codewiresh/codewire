#define _GNU_SOURCE
#include "CVZRunnerIPC.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CW_VZ_MAX_RECEIVED_DESCRIPTORS ((size_t)256)

static void close_descriptors(int *descriptors, size_t count) {
    for (size_t index = 0; index < count; index++) {
        if (descriptors[index] >= 0) {
            close(descriptors[index]);
            descriptors[index] = -1;
        }
    }
}

static int control_payload_size(
    const struct msghdr *message,
    const struct cmsghdr *header,
    size_t *payload_size
) {
    const uint8_t *base = (const uint8_t *)message->msg_control;
    const uint8_t *limit = base + message->msg_controllen;
    const uint8_t *header_bytes = (const uint8_t *)header;
    const uint8_t *payload = (const uint8_t *)CMSG_DATA(header);
    if (header_bytes < base || header_bytes > limit ||
        (size_t)(limit - header_bytes) < sizeof(struct cmsghdr) ||
        header->cmsg_len < CMSG_LEN(0) ||
        header->cmsg_len > (size_t)(limit - header_bytes) ||
        payload < header_bytes || payload > limit) {
        return -1;
    }
    size_t size = header->cmsg_len - CMSG_LEN(0);
    if (size > (size_t)(limit - payload)) {
        return -1;
    }
    *payload_size = size;
    return 0;
}

static void close_message_descriptors(struct msghdr *message) {
    for (struct cmsghdr *header = CMSG_FIRSTHDR(message);
         header != NULL;
         header = CMSG_NXTHDR(message, header)) {
        size_t payload_size = 0;
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            control_payload_size(message, header, &payload_size) != 0) {
            continue;
        }
        size_t count = payload_size / sizeof(int);
        int *received = (int *)CMSG_DATA(header);
        for (size_t index = 0; index < count; index++) {
            if (received[index] >= 0) {
                close(received[index]);
            }
        }
    }
}

static int validate_private_socket(int socket_fd) {
    int socket_type = 0;
    socklen_t socket_type_size = sizeof(socket_type);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_size) != 0 ||
        socket_type != SOCK_STREAM) {
        return CW_VZ_IPC_NOT_PRIVATE_STREAM;
    }

#if defined(__APPLE__)
    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    if (getpeereid(socket_fd, &peer_uid, &peer_gid) != 0 || peer_uid != geteuid()) {
        return CW_VZ_IPC_PEER_MISMATCH;
    }
#elif defined(__linux__)
    struct ucred peer = {0};
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
        peer_size != sizeof(peer) || peer.uid != geteuid()) {
        return CW_VZ_IPC_PEER_MISMATCH;
    }
#else
    return CW_VZ_IPC_PEER_MISMATCH;
#endif
    return 0;
}

ssize_t cw_vz_receive_request(
    int socket_fd,
    uint8_t *buffer,
    size_t buffer_capacity,
    int descriptors[CW_VZ_DESCRIPTOR_COUNT]
) {
    if (socket_fd < 0 || buffer == NULL || descriptors == NULL ||
        buffer_capacity == 0 || buffer_capacity > CW_VZ_MAX_FRAME_BYTES) {
        return CW_VZ_IPC_INVALID_ARGUMENT;
    }
    for (size_t index = 0; index < CW_VZ_DESCRIPTOR_COUNT; index++) {
        descriptors[index] = -1;
    }

    int validation = validate_private_socket(socket_fd);
    if (validation != 0) {
        return validation;
    }

    uint8_t frame[CW_VZ_FRAME_HEADER_BYTES + CW_VZ_MAX_FRAME_BYTES] = {0};
    struct iovec vector = {
        .iov_base = frame,
        .iov_len = CW_VZ_FRAME_HEADER_BYTES + buffer_capacity,
    };
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(int) * CW_VZ_MAX_RECEIVED_DESCRIPTORS)];
    } control = {0};
    struct msghdr message = {0};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);

    ssize_t received;
    do {
        received = recvmsg(socket_fd, &message, 0);
    } while (received < 0 && errno == EINTR);
    if (received < 0) {
        return CW_VZ_IPC_RECEIVE_FAILED;
    }
    if (received == 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        close_message_descriptors(&message);
        return CW_VZ_IPC_FRAME_INVALID;
    }

    size_t control_count = 0;
    struct cmsghdr *rights = NULL;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message);
         header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        size_t payload_size = 0;
        control_count++;
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            control_payload_size(&message, header, &payload_size) != 0 ||
            payload_size != sizeof(int) * CW_VZ_DESCRIPTOR_COUNT) {
            close_message_descriptors(&message);
            return CW_VZ_IPC_DESCRIPTOR_SET_INVALID;
        }
        rights = header;
    }
    if (control_count != 1 || rights == NULL) {
        close_message_descriptors(&message);
        return CW_VZ_IPC_DESCRIPTOR_SET_INVALID;
    }
    memcpy(descriptors, CMSG_DATA(rights), sizeof(int) * CW_VZ_DESCRIPTOR_COUNT);
    size_t descriptor_count = CW_VZ_DESCRIPTOR_COUNT;
    for (size_t index = 0; index < descriptor_count; index++) {
        int flags = fcntl(descriptors[index], F_GETFD);
        if (flags < 0 || fcntl(descriptors[index], F_SETFD, flags | FD_CLOEXEC) != 0) {
            close_descriptors(descriptors, descriptor_count);
            return CW_VZ_IPC_CLOEXEC_FAILED;
        }
    }

    size_t frame_size = (size_t)received;
    while (frame_size < CW_VZ_FRAME_HEADER_BYTES) {
        ssize_t part;
        do {
            part = recv(
                socket_fd,
                frame + frame_size,
                CW_VZ_FRAME_HEADER_BYTES - frame_size,
                0
            );
        } while (part < 0 && errno == EINTR);
        if (part <= 0) {
            close_descriptors(descriptors, descriptor_count);
            return CW_VZ_IPC_FRAME_INVALID;
        }
        frame_size += (size_t)part;
    }
    size_t payload_size = ((size_t)frame[0] << 24) |
        ((size_t)frame[1] << 16) |
        ((size_t)frame[2] << 8) |
        (size_t)frame[3];
    if (payload_size == 0 || payload_size > buffer_capacity ||
        frame_size > CW_VZ_FRAME_HEADER_BYTES + payload_size) {
        close_descriptors(descriptors, descriptor_count);
        return CW_VZ_IPC_FRAME_INVALID;
    }
    size_t expected_size = CW_VZ_FRAME_HEADER_BYTES + payload_size;
    while (frame_size < expected_size) {
        ssize_t part;
        do {
            part = recv(socket_fd, frame + frame_size, expected_size - frame_size, 0);
        } while (part < 0 && errno == EINTR);
        if (part <= 0) {
            close_descriptors(descriptors, descriptor_count);
            return CW_VZ_IPC_FRAME_INVALID;
        }
        frame_size += (size_t)part;
    }
    memcpy(buffer, frame + CW_VZ_FRAME_HEADER_BYTES, payload_size);
    return (ssize_t)payload_size;
}

int cw_vz_descriptors_are_distinct_files(
    const int descriptors[CW_VZ_DESCRIPTOR_COUNT]
) {
    if (descriptors == NULL) {
        return 0;
    }
    struct stat identities[CW_VZ_DESCRIPTOR_COUNT];
    for (size_t index = 0; index < CW_VZ_DESCRIPTOR_COUNT; index++) {
        if (descriptors[index] < 0 || fstat(descriptors[index], &identities[index]) != 0) {
            return 0;
        }
        for (size_t prior = 0; prior < index; prior++) {
            if (identities[index].st_dev == identities[prior].st_dev &&
                identities[index].st_ino == identities[prior].st_ino) {
                return 0;
            }
        }
    }
    return 1;
}

int cw_vz_send_response(int socket_fd, const uint8_t *buffer, size_t size) {
    if (socket_fd < 0 || buffer == NULL || size == 0 || size > CW_VZ_MAX_FRAME_BYTES) {
        return CW_VZ_IPC_INVALID_ARGUMENT;
    }
    int send_flags = 0;
#if defined(__APPLE__)
    int no_sigpipe = 1;
    if (setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &no_sigpipe,
            sizeof(no_sigpipe)
        ) != 0) {
        return CW_VZ_IPC_SEND_FAILED;
    }
#elif defined(MSG_NOSIGNAL)
    send_flags = MSG_NOSIGNAL;
#endif
    uint8_t frame[CW_VZ_FRAME_HEADER_BYTES + CW_VZ_MAX_FRAME_BYTES];
    frame[0] = (uint8_t)(size >> 24);
    frame[1] = (uint8_t)(size >> 16);
    frame[2] = (uint8_t)(size >> 8);
    frame[3] = (uint8_t)size;
    memcpy(frame + CW_VZ_FRAME_HEADER_BYTES, buffer, size);
    size_t written = 0;
    size_t frame_size = CW_VZ_FRAME_HEADER_BYTES + size;
    while (written < frame_size) {
        ssize_t part;
        do {
            part = send(socket_fd, frame + written, frame_size - written, send_flags);
        } while (part < 0 && errno == EINTR);
        if (part <= 0) {
            return CW_VZ_IPC_SEND_FAILED;
        }
        written += (size_t)part;
    }
    return 0;
}
