/* EU ARM 0x002C4BD8; see docs/recovery/resource-allocate.md. */
#include "resource_allocate.h"

void *smt4_file_allocate(uint32_t first, uint32_t second, uint32_t third,
                         uint32_t size, uint32_t fifth)
{
    smt4_resource_heap_acquire(smt4_resource_allocator_state[1]);
    void *result = smt4_resource_allocate_lower(first, second, third, size, fifth);
    if (result != 0)
        smt4_resource_allocate_zero(result, size);
    /* Lower allocation/zeroing may change the synchronization handle. */
    smt4_resource_heap_release(smt4_resource_allocator_state[1]);
    return result;
}
