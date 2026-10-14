/* EU ARM 0x002A88FC..0x002A8914, project-authored instruction recovery.
 * See resource-arbitration.md and resource-wait-return.md. The SVC boundary
 * returns r0 AND r2; ordinary C callers consume only r0. Preserve both exactly,
 * including under a kernel model that changes every argument register. */
#include "resource_signal.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");
__asm__(
    ".pushsection .text.smt4_signal_arbitrate,\"ax\",%progbits\n"
    ".align 2\n"
    ".global smt4_signal_arbitrate\n"
    ".type smt4_signal_arbitrate, %function\n"
    "smt4_signal_arbitrate:\n"
    "push {r4, r5}\n"
    "ldr r4, [sp, #8]\n"
    "ldr r5, [sp, #12]\n"
    "svc 0x22\n"
    "pop {r4, r5}\n"
    "bx lr\n"
    ".size smt4_signal_arbitrate, .-smt4_signal_arbitrate\n"
    ".popsection\n");
