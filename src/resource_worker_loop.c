/* Outer EU worker loop; see docs/recovery/resource-worker-loop.md. */
#include "resource_worker_loop.h"
#include "resource_wait.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_file_worker(void)
{
    for (;;) {
        smt4_worker_event_wait(smt4_worker_event);
        if (smt4_worker_stop)
            return;
        uint32_t index, handle = smt4_file_sync_handle;
        uint32_t result = smt4_file_acquire(&index, &handle, 1, 0, UINT64_MAX);
        if (result >> 31)
            smt4_file_check_result(result, 1);
        uint32_t *node = (uint32_t *)(uintptr_t)smt4_file_list_head;
        uint32_t previous;
        result = smt4_worker_unlock(&previous, smt4_file_sync_handle, 1);
        if (result >> 31)
            smt4_file_check_result(result, 1);
        for (;;) {
            if (smt4_worker_stop)
                return;
            if (!node)
                break;
            node = smt4_file_worker_step(node);
        }
        smt4_worker_event_reset(smt4_worker_event);
        smt4_file_delay(INT64_C(3000000));
    }
}
