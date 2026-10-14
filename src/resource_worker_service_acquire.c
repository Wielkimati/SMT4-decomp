/* Project-authored EU base v0 recovery. See resource-worker-service-acquire.md.
 * Ordinary mapped little-endian RAM; no concurrent mutation or MMIO contract. */
#include "resource_worker_service_acquire.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

typedef uint32_t unaligned_word __attribute__((aligned(1), may_alias));
typedef uint32_t aligned_word __attribute__((may_alias));

void *smt4_service_name_copy(void *output, const void *name)
{
    const volatile unaligned_word *source = name;
    volatile unaligned_word *destination = output;
    uint32_t low = source[0];
    uint32_t high = source[1];
    destination[0] = low;
    destination[1] = high;
    return output;
}

uint32_t smt4_worker_service_acquire(volatile uint32_t *output,
    const char *name, uint32_t length, uint32_t flags)
{
    if (smt4_service_manager_count <= 0)
        return UINT32_C(0xd8a067f8);
    if ((int32_t)length > 8)
        return UINT32_C(0xd9006405);
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x00050100);
    smt4_service_name_copy((void *)&command[1], name);
    command[3] = length;
    command[4] = flags;
    register uint32_t result __asm__("r0") = smt4_service_manager_handle;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31)
        return result;
    *output = command[3];
    return command[1];
}

uint32_t smt4_worker_service_name_length(const char *name)
{
    uintptr_t cursor = (uintptr_t)name;
    const uintptr_t start = cursor;
    while ((cursor & 3u) != 0) {
        if (*(const volatile unsigned char *)cursor == 0)
            return (uint32_t)(cursor - start);
        ++cursor;
    }
    for (;;) {
        uint32_t word = *(const volatile aligned_word *)cursor;
        /* UQSUB8(0x01010101, word) marks exactly the zero byte lanes. */
        for (uint32_t lane = 0; lane != 4; ++lane) {
            if (((word >> (lane * 8)) & 255u) == 0)
                return (uint32_t)(cursor - start + lane);
        }
        cursor += 4;
    }
}
