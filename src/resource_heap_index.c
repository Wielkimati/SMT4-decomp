/* EU ARM 0x002B3340; see docs/recovery/resource-heap-index.md. */
#include "resource_release.h"

uint32_t smt4_resource_heap_index(uint32_t raw)
{
    for (uint32_t index = 0; index < 4u; ++index) {
        uint32_t start = smt4_resource_allocator_state[7 + index];
        if (raw >= start && raw <= (uint32_t)(start + smt4_resource_allocator_state[11 + index]))
            return index;
    }
    return 0;
}
