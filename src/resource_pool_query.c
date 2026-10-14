/* Project-authored EU base v0; see resource-pool-object-initialize.md. */
#include "resource_pool_owner.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_pool_query_service(void)
{
    volatile uint32_t *service = (volatile uint32_t *)(uintptr_t)0x0044e644;
    if (*service == 0)
        smt4_resource_pool_initialize_diagnostic(UINT32_C(0xe0a046db),
                                                 UINT32_C(0x002bbd58));
    return *service;
}

uint32_t smt4_resource_pool_query_value(uint32_t *service, uint32_t *output)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x08630000);
    register uint32_t result __asm__("r0") = *service;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    *output = command[2];
    return command[1];
}
