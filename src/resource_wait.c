/* EU ARM 0x001181B0 and 0x002BB4F0. See docs/recovery/resource-wait.md. */
#include "resource_wait.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_file_delay(int64_t duration)
{
    if (duration >= 0x3477) {
        smt4_file_sleep(duration);
    } else {
        uint64_t scaled = (uint64_t)duration * UINT64_C(0x44a2fa85);
        smt4_file_spin((uint32_t)(scaled >> 32));
    }
}

void smt4_file_wait(uint32_t *descriptor)
{
    for (;;) {
        /* A dependency may update this word; retain each original poll. */
        uint32_t state = *(volatile uint32_t *)descriptor;
        if (state == 4 || state == 5)
            return;
        smt4_file_signal(smt4_file_wait_signal);
        smt4_file_delay(INT64_C(3000000));
    }
}
