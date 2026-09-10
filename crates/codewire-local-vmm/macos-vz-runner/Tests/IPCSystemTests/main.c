#define _GNU_SOURCE
#include "CVZRunnerIPC.h"
#include "CVZRunnerIPCTestSupport.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *message) {
    fprintf(stderr, "macOS VZ IPC system test: %s\n", message);
    return 1;
}

static void close_all(int *descriptors, size_t count) {
    for (size_t index = 0; index < count; index++) {
        if (descriptors[index] >= 0) {
            close(descriptors[index]);
            descriptors[index] = -1;
        }
    }
}

static int open_distinct_files(int descriptors[CW_VZ_DESCRIPTOR_COUNT]) {
    for (size_t index = 0; index < CW_VZ_DESCRIPTOR_COUNT; index++) {
        descriptors[index] = -1;
    }
    for (size_t index = 0; index < CW_VZ_DESCRIPTOR_COUNT; index++) {
        char path[] = "/tmp/cw-vz-ipc-XXXXXX";
        descriptors[index] = mkstemp(path);
        if (descriptors[index] < 0 || unlink(path) != 0) {
            close_all(descriptors, CW_VZ_DESCRIPTOR_COUNT);
            return -1;
        }
    }
    return 0;
}

int main(void) {
    int sockets[2] = {-1, -1};
    int originals[CW_VZ_DESCRIPTOR_COUNT];
    int received[CW_VZ_DESCRIPTOR_COUNT];
    const uint8_t payload[] = {'{', '}'};
    if (cw_vz_fixture_socketpair(sockets) != 0 || open_distinct_files(originals) != 0) {
        return fail("could not create private stream fixture");
    }
    if (cw_vz_fixture_send_request(
            sockets[0],
            payload,
            sizeof(payload),
            originals,
            CW_VZ_DESCRIPTOR_COUNT
        ) != 0) {
        return fail("could not send descriptor frame");
    }
    if (cw_vz_receive_request(sockets[1], (uint8_t[2]){0}, 2, received) != 2) {
        return fail("private stream request was not received");
    }
    if (!cw_vz_descriptors_are_distinct_files(received)) {
        return fail("received descriptor roles are not distinct files");
    }
    for (size_t index = 0; index < CW_VZ_DESCRIPTOR_COUNT; index++) {
        if ((fcntl(received[index], F_GETFD) & FD_CLOEXEC) == 0) {
            return fail("received descriptor is not close-on-exec");
        }
    }
    close_all(originals, CW_VZ_DESCRIPTOR_COUNT);
    close_all(received, CW_VZ_DESCRIPTOR_COUNT);
    close_all(sockets, 2);

    int datagram[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, datagram) != 0 ||
        cw_vz_receive_request(datagram[1], (uint8_t[2]){0}, 2, received) !=
            CW_VZ_IPC_NOT_PRIVATE_STREAM) {
        return fail("datagram control socket was not rejected");
    }
    close_all(datagram, 2);

    int response[2] = {-1, -1};
    if (cw_vz_fixture_socketpair(response) != 0) {
        return fail("could not create response fixture");
    }
    close(response[0]);
    response[0] = -1;
    if (cw_vz_send_response(response[1], payload, sizeof(payload)) != CW_VZ_IPC_SEND_FAILED) {
        return fail("closed response peer did not fail safely");
    }
    close_all(response, 2);
    puts("macOS VZ IPC system test: OK");
    return 0;
}
