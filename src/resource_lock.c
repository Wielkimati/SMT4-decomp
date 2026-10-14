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
/* C body returns the consumed scratch word; the entry bridge publishes r2.
 * This is not a claim about the otherwise unused raw r0/r1/r3 returns. */
uint32_t smt4_signal_lock_acquire_r2(uint32_t *lock)
{
    uint32_t value;
    for (;;) {
        value = lock_load(lock);
        if (value == 0 || value >= UINT32_C(0x80000000)) {
            lock_clear();
            break;
        }
        if (lock_store(lock, 0u - value) == 0)
            return (uint32_t)(uintptr_t)lock;
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
                    return 0;
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
                return 0;
        }
    }
}

__asm__(
    ".text\n"
    ".align 2\n"
    ".arm\n"
    ".global smt4_signal_lock_acquire\n"
    ".type smt4_signal_lock_acquire, %function\n"
    "smt4_signal_lock_acquire:\n"
    "push {r4, lr}\n"
    "bl smt4_signal_lock_acquire_r2\n"
    "mov r2, r0\n"
    "pop {r4, pc}\n"
    ".size smt4_signal_lock_acquire, .-smt4_signal_lock_acquire\n"
);

/* 0x00138FC0: r2 returns the negated exclusive load, or arbitration
 * scratch r2 when the signed result exceeds one. This value is consumed by
 * file disposal followed by pool diagnostics; a void C return loses it. */
__asm__(
    ".text\n"
    ".align 2\n"
    ".arm\n"
    ".global smt4_signal_lock_release\n"
    ".type smt4_signal_lock_release, %function\n"
    "smt4_signal_lock_release:\n"
    "push {r4, lr}\n"
    "sub sp, sp, #8\n"
    "1: ldrex r1, [r0]\n"
    "rsb r2, r1, #0\n"
    "strex r1, r2, [r0]\n"
    "cmp r1, #0\n"
    "bne 1b\n"
    "cmp r2, #1\n"
    "ble 2f\n"
    "mov r1, r0\n"
    "ldr r0, =smt4_arbitration_handle\n"
    "mov r2, #0\n"
    "mov r4, r2\n"
    "mov r12, r2\n"
    "ldr r0, [r0]\n"
    "mov r3, #1\n"
    "stm sp, {r4, r12}\n"
    "bl smt4_signal_arbitrate\n"
    "2: add sp, sp, #8\n"
    "pop {r4, pc}\n"
    ".size smt4_signal_lock_release, .-smt4_signal_lock_release\n"
    ".ltorg\n"
);
