#include "CVZRunnerIPC.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

// Hybrid-vsock serving for the product VM mode, matching the Cloud Hypervisor
// protocol the Rust runner already speaks: "CONNECT <port>\n" in, "OK <n>\n"
// out, then opaque bytes in both directions.

static int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    return flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0 ? -1 : 0;
}

int cw_vz_listen_unix(const char *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = path == NULL ? 0 : strlen(path);
    if (length == 0 || length >= sizeof(address.sun_path) || path[0] != '/') { return -1; }
    memcpy(address.sun_path, path, length);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    // The socket is owner-only from creation; bind never replaces a path.
    mode_t previous = umask(0177);
    int bound = bind(fd, (struct sockaddr *)&address, sizeof(address));
    umask(previous);
    if (bound != 0 || set_cloexec(fd) != 0 || listen(fd, 64) != 0) {
        if (bound == 0) { unlink(path); }
        close(fd);
        return -1;
    }
    return fd;
}

int cw_vz_read_connect(int fd, uint32_t *port) {
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    if (port == NULL || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        return -1;
    }
    // Byte at a time: the client may send payload right after the newline.
    char line[32];
    size_t used = 0;
    while (1) {
        if (used == sizeof(line)) { return -1; }
        ssize_t count = recv(fd, &line[used], 1, 0);
        if (count < 0 && errno == EINTR) { continue; }
        if (count != 1) { return -1; }
        if (line[used] == '\n') { break; }
        used++;
    }
    static const char prefix[] = "CONNECT ";
    size_t prefix_length = sizeof(prefix) - 1;
    if (used <= prefix_length || memcmp(line, prefix, prefix_length) != 0) { return -1; }
    uint64_t value = 0;
    for (size_t index = prefix_length; index < used; index++) {
        if (line[index] < '0' || line[index] > '9') { return -1; }
        if (index == prefix_length && line[index] == '0' && used > prefix_length + 1) { return -1; }
        value = value * 10 + (uint64_t)(line[index] - '0');
        if (value > UINT32_MAX) { return -1; }
    }
    struct timeval none = {0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none)) != 0) { return -1; }
    *port = (uint32_t)value;
    return 0;
}

int cw_vz_write_all(int fd, const uint8_t *bytes, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t count = send(fd, bytes + written, size - written, 0);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { return -1; }
        written += (size_t)count;
    }
    return 0;
}

struct splice_buffer {
    uint8_t bytes[CW_VZ_BRIDGE_BUFFER_BYTES];
    size_t offset;
    size_t size;
};

static int prepare_splice(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) { return -1; }
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
}

// One direction: read from `from` into `buffer`, write to `to`. Returns 1 at
// EOF with everything forwarded, 0 to continue, -1 on error.
static int pump(int from, int to, short from_events, short to_events, struct splice_buffer *buffer,
                int *eof) {
    if (buffer->size != 0 && (to_events & (POLLOUT | POLLHUP | POLLERR))) {
        ssize_t count = send(to, buffer->bytes + buffer->offset, buffer->size - buffer->offset, 0);
        if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { return -1; }
        if (count > 0) {
            buffer->offset += (size_t)count;
            if (buffer->offset == buffer->size) { buffer->offset = buffer->size = 0; }
        }
    }
    if (!*eof && buffer->size == 0 && (from_events & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t count = recv(from, buffer->bytes, sizeof(buffer->bytes), 0);
        if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { return -1; }
        if (count == 0) {
            *eof = 1;
        } else if (count > 0) {
            buffer->size = (size_t)count;
        }
    }
    return *eof && buffer->size == 0 ? 1 : 0;
}

int cw_vz_splice(int a, int b) {
    if (a < 0 || b < 0 || a == b || prepare_splice(a) != 0 || prepare_splice(b) != 0) { return -1; }
    struct splice_buffer a_to_b = {0}, b_to_a = {0};
    int a_eof = 0, b_eof = 0, b_closed = 0, a_closed = 0;
    while (!(a_closed && b_closed)) {
        struct pollfd fds[2] = {
            {.fd = a, .events = (!a_eof && a_to_b.size == 0 ? POLLIN : 0) | (b_to_a.size ? POLLOUT : 0)},
            {.fd = b, .events = (!b_eof && b_to_a.size == 0 ? POLLIN : 0) | (a_to_b.size ? POLLOUT : 0)},
        };
        if (fds[0].events == 0) { fds[0].fd = -1; }
        if (fds[1].events == 0) { fds[1].fd = -1; }
        int result = poll(fds, 2, -1);
        if (result < 0 && errno == EINTR) { continue; }
        if (result < 0 || ((fds[0].revents | fds[1].revents) & POLLNVAL)) { return -1; }
        int forward = pump(a, b, fds[0].revents, fds[1].revents, &a_to_b, &a_eof);
        int backward = pump(b, a, fds[1].revents, fds[0].revents, &b_to_a, &b_eof);
        if (forward < 0 || backward < 0) { return -1; }
        // Half-close: an EOF is forwarded once every byte before it has been.
        if (forward == 1 && !b_closed) {
            if (shutdown(b, SHUT_WR) != 0 && errno != ENOTCONN) { return -1; }
            b_closed = 1;
        }
        if (backward == 1 && !a_closed) {
            if (shutdown(a, SHUT_WR) != 0 && errno != ENOTCONN) { return -1; }
            a_closed = 1;
        }
    }
    return 0;
}
