/* EU base v0 0x002C3AFC / 0x002C3A78; project-authored recovery.
 * Preserve the consumed r2 transport through recursive locks. See
 * resource-pool-object-teardown.md and resource-recursive-lock.md. */
#include "resource_recursive_lock.h"
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* Already-owned path preserves incoming r2. Otherwise the base acquire
 * supplies it; TLS is read again after that call. Count wraps. */
__asm__(
    ".text\n"
    ".align 2\n"
    ".arm\n"
    ".global smt4_worker_backend_acquire\n"
    ".type smt4_worker_backend_acquire, %function\n"
    "smt4_worker_backend_acquire:\n"
    "push {r4, lr}\n"
    "mov r4, r0\n"
    "mrc p15, 0, r0, c13, c0, 3\n"
    "ldr r1, [r4, #4]\n"
    "cmp r0, r1\n"
    "beq 1f\n"
    "mov r0, r4\n"
    "bl smt4_signal_lock_acquire\n"
    "mrc p15, 0, r0, c13, c0, 3\n"
    "str r0, [r4, #4]\n"
    "1: ldr r0, [r4, #8]\n"
    "add r0, r0, #1\n"
    "str r0, [r4, #8]\n"
    "pop {r4, pc}\n"
    ".size smt4_worker_backend_acquire, .-smt4_worker_backend_acquire\n"
    ".ltorg\n"
);

/* Nonfinal recursive release preserves r2; final release tail-calls the
 * base operation, forwarding its returned r2. Owner clears before release. */
__asm__(
    ".text\n"
    ".align 2\n"
    ".arm\n"
    ".global smt4_worker_backend_release\n"
    ".type smt4_worker_backend_release, %function\n"
    "smt4_worker_backend_release:\n"
    "ldr r1, [r0, #8]\n"
    "subs r1, r1, #1\n"
    "str r1, [r0, #8]\n"
    "bne 1f\n"
    "mov r1, #0\n"
    "str r1, [r0, #4]\n"
    "b smt4_signal_lock_release\n"
    "1: bx lr\n"
    ".size smt4_worker_backend_release, .-smt4_worker_backend_release\n"
    ".ltorg\n"
);
