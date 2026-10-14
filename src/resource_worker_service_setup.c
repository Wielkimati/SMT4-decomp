/* Project-authored EU base v0 recovery. See resource-worker-service-setup.md.
 * Original service/kernel boundary, not a proposed native service replacement. */
#include "resource_worker_service_setup.h"
#include "resource_wait.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_service_connect_port(volatile uint32_t *output, const char *name)
{
    register uint32_t result __asm__("r0") = (uint32_t)(uintptr_t)output;
    register uint32_t handle __asm__("r1") = (uint32_t)(uintptr_t)name;
    __asm__ volatile ("svc 0x2d" : "+r" (result), "+r" (handle) : :
                      "r2", "r3", "r12", "cc", "memory");
    *output = handle;
    return result;
}

uint32_t smt4_service_manager_register(void)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x00010002);
    command[1] = 0x20;
    register uint32_t result __asm__("r0") = smt4_service_manager_handle;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    return command[1];
}

uint32_t smt4_service_manager_connect(const char *name)
{
    uint32_t result;
    for (;;) {
        result = smt4_service_connect_port(&smt4_service_manager_handle, name);
        if (((int32_t)result >> 27) != -5 || ((result >> 21) & 63u) != 4u ||
            (result & 1023u) != 1018u)
            break;
        smt4_file_delay(INT64_C(500000));
    }
    if (result >> 31)
        return result;
    result = smt4_service_manager_register();
    smt4_service_manager_count = (int32_t)((uint32_t)smt4_service_manager_count + 1u);
    return result;
}

uint32_t smt4_worker_service_setup(void)
{
    smt4_worker_backend_acquire(smt4_service_manager_lock);
    uint32_t count = (uint32_t)smt4_service_manager_count;
    uint32_t result;
    if ((int32_t)count > 0) {
        smt4_service_manager_count = (int32_t)(count + 1u);
        result = UINT32_C(0x082067f9);
    } else {
        result = smt4_service_manager_connect(smt4_service_manager_name);
    }
    smt4_worker_backend_release(smt4_service_manager_lock);
    return result;
}
