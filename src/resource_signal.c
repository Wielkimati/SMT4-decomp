/* EU ARM 0x002C4298. See docs/recovery/resource-signal.md. */
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* Retain the original LDREX/STREX loop without adding a memory barrier.
 * The loaded value is deliberately ignored: this is an unconditional exchange,
 * not a compare/exchange against the earlier mode reads. */
static void signal_exchange(uint32_t *address, uint32_t value)
{
    uint32_t observed, failed;
    do {
        __asm__ volatile ("ldrex %0, [%2]\n\tstrex %1, %3, [%2]"
                          : "=&r" (observed), "=&r" (failed)
                          : "r" (address), "r" (value) : "memory");
    } while (failed != 0);
}

void smt4_file_signal(uint32_t *signal)
{
    if (*(volatile uint32_t *)signal == UINT32_MAX) {
        signal_exchange(signal, 0);
        (void)smt4_signal_arbitrate(smt4_arbitration_handle, signal, 0, 1, 0);
    } else if (*(volatile uint32_t *)signal == UINT32_MAX - 1) {
        smt4_signal_lock_acquire(signal + 1);
        signal_exchange(signal, 1);
        (void)smt4_signal_arbitrate(smt4_arbitration_handle, signal, 0, -1, 0);
        smt4_signal_lock_release(signal + 1);
    }
}
