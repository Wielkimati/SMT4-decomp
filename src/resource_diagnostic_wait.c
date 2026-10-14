/* EU base v0 ARM instruction recovery; no external code reused.
 * See docs/recovery/resource-diagnostic-wait.md. These are original address-space
 * contracts, not native synchronization primitives. No barriers are added. */
#include "resource_worker_diagnostic.h"
#include "resource_pool_initialize.h"
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Original 32-bit address space");

uint32_t smt4_diagnostic_wait_initialize(uint32_t state[2], uint32_t mode)
{
    smt4_resource_base_lock_initialize(state + 1);
    uint32_t value = mode != 0 ? UINT32_MAX - 1u : UINT32_MAX;
    uint32_t observed, failed;
    do {
        __asm__ volatile ("ldrex %0, [%1]" : "=&r" (observed) : "r" (state) : "memory");
        __asm__ volatile ("strex %0, %2, [%1]" : "=&r" (failed)
                          : "r" (state), "r" (value) : "memory");
    } while (failed != 0);
    return observed;
}

/* Entry captures the incoming scratch r2; C carries it explicitly across loops.
 * The pair uses AAPCS r0/r1 internally and restores original r0/r2 at entry exit. */
uint64_t smt4_diagnostic_arbitrate_words(uint32_t handle, uint32_t *state);
__asm__(
    ".pushsection .text.smt4_diagnostic_wait_entry,\"ax\",%progbits\n"
    ".align 2\n"
    ".global smt4_diagnostic_wait\n"
    ".type smt4_diagnostic_wait, %function\n"
    "smt4_diagnostic_wait:\n"
    "push {r4, lr}\n"
    "mov r1, r2\n"
    "bl smt4_diagnostic_wait_pair\n"
    "mov r2, r1\n"
    "pop {r4, pc}\n"
    ".size smt4_diagnostic_wait, .-smt4_diagnostic_wait\n"
    ".global smt4_diagnostic_arbitrate_words\n"
    ".type smt4_diagnostic_arbitrate_words, %function\n"
    "smt4_diagnostic_arbitrate_words:\n"
    "push {r4, lr}\n"
    "sub sp, sp, #8\n"
    "mov r2, #1\n"
    "mov r3, #0\n"
    "str r3, [sp]\n"
    "str r3, [sp, #4]\n"
    "bl smt4_signal_arbitrate\n"
    "mov r1, r2\n"
    "add sp, sp, #8\n"
    "pop {r4, pc}\n"
    ".size smt4_diagnostic_arbitrate_words, .-smt4_diagnostic_arbitrate_words\n"
    ".popsection\n");

uint64_t smt4_diagnostic_wait_pair(uint32_t state[2], uint32_t payload)
{
    for (;;) {
        uint32_t value = *(volatile uint32_t *)state;
        if (value == UINT32_MAX - 1u)
            return smt4_diagnostic_arbitrate_words(*(volatile uint32_t *)&smt4_arbitration_handle, state);
        if (value == 1)
            return ((uint64_t)payload << 32) | 1u;
        if (value == 0) {
            uint32_t observed, failed;
            do {
                __asm__ volatile ("ldrex %0, [%1]" : "=&r" (observed) : "r" (state) : "memory");
                if (observed != 0) {
                    __asm__ volatile ("clrex" : : : "memory");
                    break;
                }
                __asm__ volatile ("strex %0, %2, [%1]" : "=&r" (failed)
                                  : "r" (state), "r" (UINT32_MAX) : "memory");
            } while (failed != 0);
            if (observed == 0)
                return 0;
        }
        payload = (uint32_t)(smt4_diagnostic_arbitrate_words(*(volatile uint32_t *)&smt4_arbitration_handle, state) >> 32);
    }
}
