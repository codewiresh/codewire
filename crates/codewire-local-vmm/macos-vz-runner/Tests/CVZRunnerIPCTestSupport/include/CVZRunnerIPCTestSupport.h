#ifndef CODEWIRE_VZ_RUNNER_IPC_TEST_SUPPORT_H
#define CODEWIRE_VZ_RUNNER_IPC_TEST_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

int cw_vz_fixture_socketpair(int sockets[2]);
int cw_vz_fixture_send_request(
    int socket_fd,
    const uint8_t *buffer,
    size_t size,
    const int *descriptors,
    size_t descriptor_count
);
int cw_vz_fixture_descriptor_is_closed(int descriptor);

#endif
