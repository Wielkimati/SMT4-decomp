/* EU base v0; project-authored reconstruction. See resource-worker-archive-service.md. */
#include "resource_worker_backend.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static inline volatile uint32_t *command_buffer(void)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    return (volatile uint32_t *)(tls + 0x80u);
}

static inline uint32_t send_request(uint32_t handle)
{
    register uint32_t r0 __asm__("r0") = handle;
    __asm__ volatile ("svc 0x32" : "+r" (r0) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    return r0;
}

uint32_t smt4_worker_backend_archive_open(uint32_t *service, uint64_t *handle,
    uint32_t archive, uint32_t type, const uint32_t *data, uint32_t bytes)
{
    volatile uint32_t *command = command_buffer();
    command[0] = UINT32_C(0x080c00c2);
    command[3] = bytes;
    command[4] = (bytes << 14) | 2u;
    command[5] = (uint32_t)(uintptr_t)data;
    command[1] = archive;
    command[2] = type;
    uint32_t result = send_request(*service);
    if (result >> 31)
        return result;
    uint32_t low = command[2];
    uint32_t high = command[3];
    *(volatile uint64_t *)handle = ((uint64_t)high << 32) | low;
    return command[1];
}

uint32_t smt4_worker_backend_archive_close(uint32_t *service, uint64_t handle)
{
    volatile uint32_t *command = command_buffer();
    command[0] = UINT32_C(0x080e0080);
    command[1] = (uint32_t)handle;
    command[2] = (uint32_t)(handle >> 32);
    uint32_t result = send_request(*service);
    if (result >> 31)
        return result;
    return command[1];
}
