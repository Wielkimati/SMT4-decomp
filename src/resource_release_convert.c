/* EU ARM 0x001245F0; see docs/recovery/resource-release-convert.md. */
#include "resource_release.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_release_convert(uint32_t address)
{
    uint32_t *raw = (uint32_t *)(uintptr_t)*(uint32_t *)(uintptr_t)(address - 4u);
    uint32_t *account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
    account[6] -= 1u;
    account[7] -= raw[0];
    if ((*(uint16_t *)((uint8_t *)raw + 8) & 0xffu) < 8u) {
        uint32_t index = smt4_resource_heap_index((uint32_t)(uintptr_t)raw);
        account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
        account[15 + index] -= raw[0];
        index = smt4_resource_heap_index((uint32_t)(uintptr_t)raw);
        account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
        account[23 + index] -= raw[0] - *(uint16_t *)((uint8_t *)raw + 4) - 0x3cu;
    }
    uint32_t *node = raw + 3;
    uint32_t *previous = (uint32_t *)(uintptr_t)node[0];
    uint32_t *next = (uint32_t *)(uintptr_t)node[1];
    account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
    if (previous != 0) {
        if (next == 0) {
            account[1] = (uint32_t)(uintptr_t)previous;
            previous[1] = 0;
        } else {
            previous[1] = (uint32_t)(uintptr_t)next;
            next[0] = (uint32_t)(uintptr_t)previous;
        }
    } else if (next != 0) {
        account[0] = (uint32_t)(uintptr_t)next;
        next[0] = 0;
    } else {
        account[1] = 0;
        account[0] = 0;
    }
    if (account[2] == (uint32_t)(uintptr_t)node)
        account[2] = 0;
    *(uint16_t *)((uint8_t *)raw + 8) = 0;
    return (uint32_t)(uintptr_t)raw;
}
