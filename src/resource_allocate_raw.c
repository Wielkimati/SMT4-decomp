/* EU ARM 0x002B26F0; see docs/recovery/resource-allocate-raw.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void *smt4_resource_allocate_raw(uint32_t first, uint32_t second,
                                uint32_t third, uint32_t size, uint32_t fifth)
{
    (void)third;
    if (size == 0) return 0;
    uint32_t alignment = 8;
    switch (second) {
    case 0x100: alignment = 4; break;
    case 0x101: alignment = 128; break;
    case 0x103: alignment = 64; break;
    case 0x104:
    case 0x105: alignment = 16; break;
    }
    if (fifth == 0) alignment = 0u - alignment;
    /* Original reads this word on every nonzero-size route, including unknown
     * selectors. Capture once: dependencies may change the global later. */
    uint32_t base = smt4_resource_raw_state[1];
    if (first == 0x100 || first == 0x10000) {
        uint32_t heap = base + (first == 0x100 ? 0x1cu : 0x88u);
        uint32_t lock = base + (first == 0x100 ? 0x74u : 0xe0u);
        smt4_resource_heap_acquire(lock);
        void *result = smt4_resource_heap_allocate(heap, size, alignment, 0, 0, 0);
        smt4_resource_heap_release(lock);
        return result;
    }
    if (first == 0x20000 || first == 0x30000)
        return smt4_resource_fixed_allocate(first == 0x20000 ? 0x4e4100u : 0x4e411cu,
            size, first, (uint32_t)(uintptr_t)smt4_resource_raw_state);
    return 0;
}
