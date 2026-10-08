/* EU base v0; project-authored reconstruction. See resource-worker-file-service.md. */
#include "resource_worker_file_owner.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* Original platform instructions. TLS contents and kernel behavior are external. */
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

uint32_t smt4_worker_file_service_open(uint32_t *service, uint32_t *handle,
    uint32_t transaction, uint64_t archive, uint32_t type, uint32_t data,
    uint32_t bytes, uint32_t flags, uint32_t attributes)
{
    volatile uint32_t *command = command_buffer();
    command[0] = UINT32_C(0x080201c2);
    command[1] = transaction;
    command[2] = (uint32_t)archive;
    command[3] = (uint32_t)(archive >> 32);
    command[4] = type;
    command[5] = bytes;
    command[6] = flags;
    command[7] = attributes;
    command[8] = (bytes << 14) | 2u;
    command[9] = data;
    uint32_t result = send_request(*service);
    if (result >> 31)
        return result;
    *handle = command[3];
    return command[1];
}

uint32_t smt4_worker_file_service_close(uint32_t *handle)
{
    volatile uint32_t *command = command_buffer();
    command[0] = UINT32_C(0x08080000);
    uint32_t result = send_request(*handle);
    if (result >> 31)
        return result;
    return command[1];
}
