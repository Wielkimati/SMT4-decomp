/* EU ARM 0x002A88FC. See docs/recovery/resource-arbitration.md. */
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* The kernel boundary consumes r0-r5, with the timeout low word in r4.
 * Its result is returned unchanged. Kernel arbitration is not implemented here.
 * r4/r5 are temporary SVC arguments, so the C ABI must preserve their caller values.
 */
uint32_t smt4_signal_arbitrate(uint32_t handle, uint32_t *address,
                             uint32_t operation, int32_t count, int64_t timeout)
{
    register uint32_t r0 __asm__("r0") = handle;
    register uint32_t r1 __asm__("r1") = (uint32_t)(uintptr_t)address;
    register uint32_t r2 __asm__("r2") = operation;
    register uint32_t r3 __asm__("r3") = (uint32_t)count;
    register uint32_t r4 __asm__("r4") = (uint32_t)(uint64_t)timeout;
    register uint32_t r5 __asm__("r5") = (uint32_t)((uint64_t)timeout >> 32);
    __asm__ volatile ("svc 0x22"
                      : "+r" (r0), "+r" (r1), "+r" (r2), "+r" (r3),
                        "+r" (r4), "+r" (r5)
                      : : "r12", "cc", "memory");
    return r0;
}
