#define _GNU_SOURCE
#include "CVZRunnerIPC.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int prepare_stream(int fd) {
    int flags = fcntl(fd, F_GETFL), descriptor_flags = fcntl(fd, F_GETFD);
    if (flags < 0 || descriptor_flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) { return -1; }
#if defined(__APPLE__)
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) { return -1; }
#endif
    return 0;
}

static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { return -1; }
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

struct bounded_buffer {
    unsigned char bytes[CW_VZ_BRIDGE_BUFFER_BYTES];
    size_t offset;
    size_t size;
};

static int forward_buffer(int fd, struct bounded_buffer *buffer) {
    int flags = 0;
#if defined(MSG_NOSIGNAL)
    flags = MSG_NOSIGNAL;
#endif
    ssize_t count = send(fd, buffer->bytes + buffer->offset, buffer->size - buffer->offset, flags);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { return 0; }
    if (count <= 0) { return -1; }
    buffer->offset += (size_t)count;
    if (buffer->offset == buffer->size) { buffer->offset = buffer->size = 0; }
    return 0;
}

static int receive_buffer(int fd, struct bounded_buffer *buffer) {
    ssize_t count = recv(fd, buffer->bytes, sizeof(buffer->bytes), 0);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { return 0; }
    if (count < 0) { return -1; }
    if (count == 0) { return 1; }
    buffer->offset = 0;
    buffer->size = (size_t)count;
    return 0;
}

int cw_vz_bridge_streams(int local_fd, int guest_fd, int cancellation_fd, int seconds, int preserve_guest_eof) {
    if (local_fd < 0 || guest_fd < 0 || cancellation_fd < 0 || local_fd == guest_fd ||
        seconds <= 0 || seconds > 180 || (preserve_guest_eof != 0 && preserve_guest_eof != 1) ||
        prepare_stream(local_fd) != 0 || prepare_stream(guest_fd) != 0) { return -1; }
    double started = monotonic_seconds();
    if (started < 0) { return -1; }
    double deadline = started + seconds;
    struct bounded_buffer to_guest = {0}, to_local = {0};
    int guest_eof = 0;
    while (1) {
        double now = monotonic_seconds();
        if (now < 0 || now >= deadline) { return -1; }
        struct pollfd fds[3] = {
            {.fd = local_fd, .events = (to_guest.size == 0 ? POLLIN : 0) | (to_local.size != 0 ? POLLOUT : 0)},
            {.fd = guest_fd, .events = (!guest_eof && to_local.size == 0 ? POLLIN : 0) | (to_guest.size != 0 ? POLLOUT : 0)},
            {.fd = cancellation_fd, .events = POLLIN}
        };
        int result = poll(fds, 3, 100);
        if (result < 0 && errno == EINTR) { continue; }
        if (result < 0) { return -1; }
        // Never consume cancellation: every bridge observes the same event.
        if (fds[2].revents != 0) { return 0; }
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLNVAL)) { return -1; }
        if ((fds[0].revents & POLLOUT) && to_local.size && forward_buffer(local_fd, &to_local) != 0) { return -1; }
        if ((fds[1].revents & POLLOUT) && to_guest.size && forward_buffer(guest_fd, &to_guest) != 0) { return -1; }
        if ((fds[0].revents & (POLLIN | POLLHUP)) && to_guest.size == 0) {
            int read_result = receive_buffer(local_fd, &to_guest);
            if (read_result != 0) { return read_result; }
            if (guest_eof && to_guest.size != 0) { return -1; }
        }
        if (!guest_eof && (fds[1].revents & (POLLIN | POLLHUP)) && to_local.size == 0) {
            int read_result = receive_buffer(guest_fd, &to_local);
            if (read_result < 0) { return -1; }
            if (read_result == 1) {
                if (!preserve_guest_eof) { return 1; }
                guest_eof = 1;
            }
        }
        if (guest_eof && to_local.size == 0) {
            if (to_guest.size != 0 || shutdown(local_fd, SHUT_WR) != 0) { return -1; }
            return 2;
        }
    }
}

int cw_vz_prepare_control(int socket_fd) {
    struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
    struct timeval write_timeout = {.tv_sec = 1, .tv_usec = 0};
    int flags = fcntl(socket_fd, F_GETFD);
    if (flags < 0 || fcntl(socket_fd, F_SETFD, flags | FD_CLOEXEC) != 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &write_timeout, sizeof(write_timeout)) != 0) { return -1; }
    return 0;
}

int cw_vz_control_event(int socket_fd, int milliseconds) {
    if (milliseconds < 0 || milliseconds > 1000) { return -1; }
    struct pollfd fd = {.fd = socket_fd, .events = POLLIN};
    int result = poll(&fd, 1, milliseconds);
    if (result < 0 && errno == EINTR) { return 0; }
    if (result < 0 || fd.revents & (POLLERR | POLLNVAL)) { return -1; }
    if (!result) { return 0; }
    // recv without ancillary capacity discards and closes any unsolicited
    // descriptors. Every nonempty post-start message rejects the fixture.
    unsigned char byte;
    ssize_t count = recv(socket_fd, &byte, 1, MSG_DONTWAIT);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) { return 0; }
    return count == 0 ? 1 : -1;
}
