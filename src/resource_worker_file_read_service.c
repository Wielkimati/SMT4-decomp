/* EU base v0; project-authored recovery. See resource-worker-file-read-service.md. */
#include "resource_worker_file_methods.h"
#include "resource_worker_file_owner.h"
#include "resource_wait.h"
#include "unsigned_quotient.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_worker_file_pre_read_delay(uint32_t mode)
{
    uint32_t extra = 0;
    if (smt4_worker_file_delay_state[0] == 0)
        return;
    uint32_t enabled = smt4_worker_file_delay_state[1];
    if (enabled != 0) {
        register uint32_t query __asm__("r0") = enabled;
        __asm__ volatile ("svc 0x28" : "+r" (query) : :
                          "r1", "r2", "r3", "r12", "cc", "memory");
        if (query & 0x10u)
            extra = smt4_unsigned_quotient(mode != 0 ? 100u : 380u,
                                           (query & 15u) + 1u);
    }
    uint32_t base = *(volatile uint32_t *)(smt4_worker_file_delay_state + 0x18);
    uint32_t delay = (base + extra) & UINT32_C(0xffff);
    if (delay != 0)
        smt4_file_delay((int64_t)delay * INT64_C(1000000));
}

uint32_t smt4_worker_file_read_service(uint32_t *received, uint32_t handle,
    uint64_t cursor, uint32_t buffer, uint32_t bytes)
{
    if (handle == 0 || buffer == 0)
        return UINT32_C(0xe0e046bc);
    smt4_worker_file_pre_read_delay(1);
    uint32_t *object = (uint32_t *)(uintptr_t)handle;
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    return ((uint32_t (*)(uint32_t *, uint32_t *, uint64_t, uint32_t,
                         uint32_t))(uintptr_t)vtable[0])
        (object, received, cursor, buffer, bytes);
}

uint32_t smt4_worker_file_read_method(uint32_t *object, uint32_t *received,
    uint64_t cursor, uint32_t buffer, uint32_t bytes)
{
    uint32_t handle = smt4_worker_file_handle(object);
    return smt4_worker_file_service_read(&handle, received, cursor, buffer, bytes);
}

uint32_t smt4_worker_file_service_read(uint32_t *handle, uint32_t *received,
    uint64_t cursor, uint32_t buffer, uint32_t bytes)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x080200c2);
    command[1] = (uint32_t)cursor;
    command[2] = (uint32_t)(cursor >> 32);
    command[3] = bytes;
    command[5] = buffer;
    command[4] = (bytes << 4) | 12u;
    register uint32_t result __asm__("r0") = *handle;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    *received = command[2];
    return command[1];
}
