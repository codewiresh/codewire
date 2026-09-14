#include "CVZRunnerIPCTestSupport.h"
#include "CVZRunnerIPC.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int cw_vz_fixture_socketpair(int sockets[2]) {
    return socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
}

int cw_vz_fixture_send_request(
    int socket_fd,
    const uint8_t *buffer,
    size_t size,
    const int *descriptors,
    size_t descriptor_count
) {
    if (socket_fd < 0 || buffer == NULL || size == 0 || size > CW_VZ_MAX_FRAME_BYTES + 1 ||
        descriptors == NULL || descriptor_count == 0 || descriptor_count > 12) {
        return -1;
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
        return -1;
    }
#elif defined(MSG_NOSIGNAL)
    send_flags = MSG_NOSIGNAL;
#endif
    size_t frame_size = CW_VZ_FRAME_HEADER_BYTES + size;
    uint8_t *frame = malloc(frame_size);
    if (frame == NULL) {
        return -1;
    }
    frame[0] = (uint8_t)(size >> 24);
    frame[1] = (uint8_t)(size >> 16);
    frame[2] = (uint8_t)(size >> 8);
    frame[3] = (uint8_t)size;
    memcpy(frame + CW_VZ_FRAME_HEADER_BYTES, buffer, size);
    struct iovec vector = {.iov_base = frame, .iov_len = frame_size};
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(int) * 12)];
    } control = {0};
    struct msghdr message = {0};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen =
        (socklen_t)CMSG_SPACE(sizeof(int) * descriptor_count);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * descriptor_count);
    memcpy(CMSG_DATA(header), descriptors, sizeof(int) * descriptor_count);
    ssize_t sent;
    do {
        sent = sendmsg(socket_fd, &message, send_flags);
    } while (sent < 0 && errno == EINTR);
    if (sent <= 0) {
        free(frame);
        return -1;
    }
    size_t written = (size_t)sent;
    while (written < frame_size) {
        do {
            sent = send(socket_fd, frame + written, frame_size - written, send_flags);
        } while (sent < 0 && errno == EINTR);
        if (sent <= 0) {
            free(frame);
            return -1;
        }
        written += (size_t)sent;
    }
    free(frame);
    return 0;
}

int cw_vz_fixture_descriptor_is_closed(int descriptor) {
    return fcntl(descriptor, F_GETFD) < 0 && errno == EBADF;
}
