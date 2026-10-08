/* EU base v0: 0x002C3AFC / 0x002C3A78. Project-authored instruction recovery.
 * See docs/recovery/resource-recursive-lock.md. This is not host synchronization. */
#include "resource_recursive_lock.h"
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t current_tls(void)
{
    uint32_t value;
    /* Compiler sequencing only; the original wrappers have no hardware barrier. */
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (value) :: "memory");
    return value;
}

void smt4_worker_backend_acquire(uint32_t *lock)
{
    volatile uint32_t *words = lock;
    uint32_t tls = current_tls();
    if (tls != words[1]) {
        smt4_signal_lock_acquire(lock);
        words[1] = current_tls();
    }
    words[2] = words[2] + 1u;
}

void smt4_worker_backend_release(uint32_t *lock)
{
    volatile uint32_t *words = lock;
    uint32_t count = words[2] - 1u;
    words[2] = count;
    if (count == 0) {
        words[1] = 0;
        smt4_signal_lock_release(lock);
    }
}
