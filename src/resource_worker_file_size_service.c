/* EU base v0; project-authored recovery. See resource-worker-file-size-service.md. */
#include "resource_worker_file_methods.h"
#include "resource_worker_file_owner.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_file_size_service(uint64_t *size, uint32_t handle)
{
    if (size == 0 || handle == 0)
        return UINT32_C(0xe0e046bc);
    uint32_t *object = (uint32_t *)(uintptr_t)handle;
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    return ((uint32_t (*)(uint32_t *, uint64_t *))(uintptr_t)vtable[2])(object, size);
}

uint32_t smt4_worker_file_size_method(uint32_t *object, uint64_t *size)
{
    uint32_t handle = smt4_worker_file_handle(object);
    return smt4_worker_file_service_size(&handle, size);
}

uint32_t smt4_worker_file_service_size(uint32_t *handle, uint64_t *size)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x08040000);
    register uint32_t result __asm__("r0") = *handle;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    uint32_t low = command[2];
    uint32_t high = command[3];
    *(volatile uint64_t *)size = ((uint64_t)high << 32) | low;
    return command[1];
}
