/* EU base v0, ARM 0x001272d4 and 0x0011ba54. Project-authored recovery.
 * See docs/recovery/resource-worker-service-initialize.md. */
#include "resource_worker_backend.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_service_request(uint32_t *service, uint32_t value)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x08610042);
    command[1] = value;
    command[2] = 0x20u;
    register uint32_t result __asm__("r0") = *service;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    return command[1];
}

uint32_t smt4_worker_service_initialize(uint32_t service)
{
    smt4_worker_backend_state[4] = service;
    smt4_worker_service_request(&service, UINT32_C(0x040201c8));
    return 0;
}
