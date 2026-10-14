/* Project-authored EU instruction recovery. See recovery/resource-break.md.
 * Kernel break policy and callback implementation remain external boundaries. */
#include "resource_break.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

__attribute__((noinline))
uint32_t smt4_break_svc(uint32_t reason, uint32_t word1, uint32_t word2)
{
    register uint32_t r0 __asm__("r0") = reason;
    register uint32_t r1 __asm__("r1") = word1;
    register uint32_t r2 __asm__("r2") = word2;
    __asm__ volatile ("svc 0x3c" : "+r" (r0), "+r" (r1), "+r" (r2)
                      : : "r3", "r12", "cc", "memory");
    return r0;
}

__attribute__((noinline))
uint32_t smt4_break_dispatch(uint32_t reason, uint32_t unused, uint32_t payload)
{
    (void)unused;
    smt4_break_callback callback = smt4_break_callback_slot;
    if (callback != 0) {
        smt4_break_callback_slot = 0;
        callback(reason, 0, 0, 0, 0, payload);
    }
    return smt4_break_svc(reason, 0, 0);
}

uint32_t smt4_worker_file_preclose(uint32_t unused0, uint32_t unused1, uint32_t payload)
{
    (void)unused0;
    (void)unused1;
    return smt4_break_dispatch(0, 0, payload);
}

/* Two older descriptive names for one original entry, not another contract. */
uint32_t smt4_worker_prefix_diagnostic(uint32_t, uint32_t, uint32_t)
    __attribute__((alias("smt4_worker_file_preclose")));
