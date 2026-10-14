/* Project-authored recovery, EU base v0. See resource-worker-service-startup.md.
 * r0 returns are preserved; no original C prototype or caller use is inferred. */
#include "resource_worker_service_startup.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_service_state_request(uint32_t *service, uint32_t value)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x08620040);
    command[1] = value;
    register uint32_t result __asm__("r0") = *service;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    return command[1];
}

uint32_t smt4_worker_service_publish(uint32_t pointer)
{
    smt4_worker_service_pointer = pointer;
    return pointer;
}

uint32_t smt4_worker_service_startup(void)
{
    uint32_t result = smt4_worker_service_state[1];
    if (result != 0)
        return result;
    result = smt4_worker_service_setup();
    if (result != UINT32_C(0x08a067f9) && (result >> 31))
        smt4_worker_service_diagnostic(result, UINT32_C(0x0010f5e4), 1);
    uint32_t length = smt4_worker_service_name_length(smt4_worker_service_name);
    result = smt4_worker_service_acquire(&smt4_worker_service_state[1],
        smt4_worker_service_name, length, 0);
    if (result >> 31)
        smt4_worker_service_diagnostic(result, UINT32_C(0x0010f60c), 1);
    smt4_worker_service_initialize(smt4_worker_service_state[1]);
    smt4_worker_service_state[2] = (uint32_t)(uintptr_t)smt4_worker_service_state;
    smt4_worker_service_publish((uint32_t)(uintptr_t)&smt4_worker_service_state[2]);
    uint32_t service = smt4_resource_pool_query_service();
    result = smt4_worker_service_state_request(&service, 0);
    if (result >> 31)
        return smt4_worker_service_diagnostic(result, UINT32_C(0x0010f654), 1);
    return result;
}
