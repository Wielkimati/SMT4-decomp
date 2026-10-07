/* Bounded worker region, not the complete thread. See resource-worker-step.md. */
#include "resource_worker.h"
#include "resource_release.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static void acquire(void)
{
    uint32_t index, handle = smt4_file_sync_handle;
    uint32_t result = smt4_file_acquire(&index, &handle, 1, 0, UINT64_MAX);
    if (result >> 31)
        smt4_file_check_result(result, 1);
}

static void release(void)
{
    uint32_t previous;
    uint32_t result = smt4_worker_unlock(&previous, smt4_file_sync_handle, 1);
    if (result >> 31)
        smt4_file_check_result(result, 1);
}

uint32_t *smt4_file_worker_step(uint32_t *d)
{
    if (d[0] == 4 || d[0] == 5) {
        acquire();
        uint32_t remaining = d[1] - d[2];
        d[1] = remaining;
        /* Signed-positive after wrapping subtraction; avoid signed overflow. */
        if (remaining == 0 || remaining >= UINT32_C(0x80000000)) {
            uint32_t *previous = (uint32_t *)(uintptr_t)d[0x140 / 4];
            uint32_t *next = (uint32_t *)(uintptr_t)d[0x13c / 4];
            if (previous)
                previous[0x13c / 4] = (uint32_t)(uintptr_t)next;
            else
                smt4_file_list_head = (uint32_t)(uintptr_t)next;
            if (next)
                next[0x140 / 4] = (uint32_t)(uintptr_t)previous;
            if (d[4] == 0 && d[3] != 0)
                smt4_resource_release(d[3]);
            d[3] = 0;
            smt4_resource_release((uint32_t)(uintptr_t)d);
            release();
            return next; /* Captured before release; never reread freed memory. */
        }
        release();
    } else {
        if (d[0x138 / 4]) {
            acquire();
            ((void (*)(char *))(uintptr_t)d[0x138 / 4])((char *)d + 0x2c);
            d[0x138 / 4] = 0;
            release();
        }
        if (d[0] == 0) {
            smt4_worker_state0_io(d);
            d[0] = 3;
            d[0x12c / 4] = 0;
        }
        if (d[0] == 3)
            d[0] = 4;
        if ((d[0] == 4 || d[0] == 5) && d[0x130 / 4]) {
            acquire();
            uint32_t context = d[0x134 / 4];
            ((void (*)(uint32_t))(uintptr_t)d[0x130 / 4])(
                context ? context : (uint32_t)(uintptr_t)d);
            release();
        }
    }
    acquire();
    uint32_t *next = (uint32_t *)(uintptr_t)d[0x13c / 4];
    release();
    return next;
}
