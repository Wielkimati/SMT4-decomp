/* EU ARM 0x002C43B4; see docs/recovery/resource-release.md. */
#include "resource_release.h"

void smt4_resource_release(uint32_t address)
{
    smt4_resource_heap_acquire(smt4_resource_allocator_state[1]);
    uint32_t first = smt4_resource_allocator_state[0x24 / 4];
    uint32_t second = smt4_resource_allocator_state[0x28 / 4];
    /* Inclusive unsigned endpoints and 32-bit wrapping sums are intentional. */
    if (!(address >= first && address <= first + smt4_resource_allocator_state[0x34 / 4]) &&
        !(address >= second && address <= second + smt4_resource_allocator_state[0x38 / 4]))
        address = smt4_resource_release_convert(address);
    smt4_resource_heap_free(address);
    /* Reload: lower calls can change this state. */
    smt4_resource_heap_release(smt4_resource_allocator_state[1]);
}
