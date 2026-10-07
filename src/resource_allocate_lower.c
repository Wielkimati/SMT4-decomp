/* EU ARM 0x002C5544; see docs/recovery/resource-allocate-lower.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void *smt4_resource_allocate_lower(uint32_t first, uint32_t second,
                                  uint32_t third, uint32_t size, uint32_t fifth)
{
    smt4_resource_heap_acquire(smt4_resource_allocator_state[1]);
    void *result;
    if (first == 0x20000 || first == 0x30000) {
        result = smt4_resource_allocate_raw(first, second, third, size, fifth);
    } else {
        uint32_t rounded = (size + 0x13bu) & ~0x7fu;
        uint32_t *raw = smt4_resource_allocate_raw(first, second, third, rounded, fifth);
        uint32_t address = (uint32_t)(uintptr_t)raw;
        uint32_t padding = (0x80u - ((address + 0x3cu) & 0x7fu)) & 0x7fu;
        uint32_t user = address + 0x3cu + padding;
        /* Original has no failure guard. Ordinary path requires writable raw storage. */
        raw[0] = rounded;
        ((uint16_t *)raw)[2] = 0x80;
        ((uint16_t *)raw)[3] = 0;
        *(uint32_t *)(uintptr_t)(user - 4u) = address;
        smt4_resource_allocate_register(raw);
        result = (void *)(uintptr_t)user;
        smt4_resource_allocate_zero(result, size);
    }
    smt4_resource_heap_release(smt4_resource_allocator_state[1]);
    return result;
}
