/* EU ARM 0x00146AD8; see docs/recovery/resource-heap-allocate-inner.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t read_word(uint32_t address)
{
    return *(volatile uint32_t *)(uintptr_t)address;
}

void *smt4_resource_heap_allocate_inner(uint32_t subobject, uint32_t size,
                                        uint32_t alignment)
{
    uint32_t rounded = ((size == 0 ? 1u : size) + 3u) & ~3u;
    uint32_t first_fit = ~*(volatile uint16_t *)(uintptr_t)(subobject + 0x36u) & 1u;
    uint32_t selected = 0, payload = 0, smallest = UINT32_MAX;
    uint32_t reverse = alignment >> 31;
    uint32_t node = read_word(subobject + (reverse ? 0x28u : 0x24u));
    if (!reverse) {
        uint32_t mask = alignment - 1u;
        while (node != 0) {
            uint32_t start = node + 0x10u;
            uint32_t candidate = (start + alignment - 1u) & ~mask;
            uint32_t capacity = read_word(node + 4u);
            uint32_t needed = candidate - start + rounded;
            if (capacity >= needed && capacity < smallest) {
                selected = node;
                smallest = capacity;
                payload = candidate;
                if (first_fit || capacity == rounded)
                    break;
            }
            node = read_word(node + 0xcu);
        }
    } else {
        uint32_t mask = (0u - alignment) - 1u;
        while (node != 0) {
            uint32_t capacity = read_word(node + 4u);
            uint32_t start = node + 0x10u;
            uint32_t candidate = (capacity + start - rounded) & ~mask;
            /* Original BMI tests N alone, not a signed relational comparison. */
            if (((candidate - start) & 0x80000000u) == 0 && capacity < smallest) {
                selected = node;
                smallest = capacity;
                payload = candidate;
                if (first_fit || capacity == rounded)
                    break;
            }
            node = read_word(node + 8u);
        }
    }
    if (selected == 0)
        return 0;
    return smt4_resource_heap_commit_block(subobject + 0x24u, selected,
                                            payload, rounded, reverse);
}
