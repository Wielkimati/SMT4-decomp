/* EU ARM 0x001464F8 / 0x00138FC0. See docs/recovery/resource-lock.md. */
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t lock_load(uint32_t *lock)
{
    uint32_t value;
    __asm__ volatile ("ldrex %0, [%1]" : "=&r" (value) : "r" (lock) : "memory");
    return value;
}

static uint32_t lock_store(uint32_t *lock, uint32_t value)
{
    uint32_t failed;
    __asm__ volatile ("strex %0, %2, [%1]" : "=&r" (failed)
                      : "r" (lock), "r" (value) : "memory");
    return failed;
}

static void lock_clear(void)
{
    __asm__ volatile ("clrex" ::: "memory");
}

/* All arithmetic wraps in 32 bits; predicates interpret the word as signed.
 * Keep each exclusive read distinct, including the second fast attempt in
 * the slow loop. No memory barrier is inserted by these original routines. */
void smt4_signal_lock_acquire(uint32_t *lock)
{
    uint32_t value;
    for (;;) {
        value = lock_load(lock);
        if (value == 0 || value >= UINT32_C(0x80000000)) {
            lock_clear();
            break;
        }
        if (lock_store(lock, 0u - value) == 0)
            return;
    }
    for (;;) {
        value = lock_load(lock);
        if (value >= UINT32_C(0x80000000)) {
            if (lock_store(lock, value - 1u) == 0)
                break;
        } else {
            lock_clear();
            for (;;) {
                value = lock_load(lock);
                if (value == 0 || value >= UINT32_C(0x80000000)) {
                    lock_clear();
                    break;
                }
                if (lock_store(lock, 0u - value) == 0)
                    return;
            }
        }
    }
    for (;;) {
        (void)smt4_signal_arbitrate(smt4_arbitration_handle, lock, 1, 0, 0);
        for (;;) {
            value = lock_load(lock);
            if (value == 0 || value >= UINT32_C(0x80000000)) {
                lock_clear();
                break;
            }
            if (lock_store(lock, 1u - value) == 0)
                return;
        }
    }
}

void smt4_signal_lock_release(uint32_t *lock)
{
    uint32_t value;
    do {
        value = 0u - lock_load(lock);
    } while (lock_store(lock, value) != 0);
    if (value > 1u && value < UINT32_C(0x80000000))
        (void)smt4_signal_arbitrate(smt4_arbitration_handle, lock, 0, 1, 0);
}
