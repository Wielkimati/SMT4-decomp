/* Project-authored EU base v0 recovery; see resource-pool-request.md. */
#include "resource_pool_owner.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_pool_owner_request(uint32_t *service, uint32_t *handle,
    uint32_t word1, uint32_t word2, uint32_t type1, const uint32_t *data1,
    uint32_t size1, uint32_t type2, const uint32_t *data2, uint32_t size2,
    uint32_t word7, uint32_t word8)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    /* Preserve the original store order, including the two descriptor slots. */
    command[0] = UINT32_C(0x08030204);
    command[3] = type1;
    command[4] = size1;
    command[7] = word7;
    command[1] = word1;
    command[2] = word2;
    command[5] = type2;
    command[6] = size2;
    command[8] = word8;
    command[9] = (size1 << 14) | 0x802u;
    command[10] = (uint32_t)(uintptr_t)data1;
    command[11] = (size2 << 14) | 2u;
    command[12] = (uint32_t)(uintptr_t)data2;
    register uint32_t result __asm__("r0") = *service;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result & 0x80000000u)
        return result;
    /* Publication depends on the kernel result, not the service status. */
    *handle = command[3];
    return command[1];
}
