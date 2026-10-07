/* EU ARM 0x002B260C; see docs/recovery/resource-allocate-register.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_resource_allocate_register(void *address)
{
    uint32_t *raw = address;
    uint32_t *account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
    account[6] += 1u;
    account[7] += raw[0];
    if ((*(uint16_t *)((uint8_t *)account + 0x38) & 0xffu) < 8u) {
        uint32_t index = smt4_resource_heap_index((uint32_t)(uintptr_t)raw);
        account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
        account[15 + index] += raw[0];
        index = smt4_resource_heap_index((uint32_t)(uintptr_t)raw);
        account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
        account[23 + index] += raw[0] - *(uint16_t *)((uint8_t *)raw + 4) - 0x3cu;
    }
    uint32_t *node = raw + 3;
    account = (uint32_t *)(uintptr_t)smt4_resource_allocator_state[2];
    if (account[0] != 0) {
        uint32_t *tail = (uint32_t *)(uintptr_t)account[1];
        node[0] = (uint32_t)(uintptr_t)tail;
        account[1] = (uint32_t)(uintptr_t)node;
        tail[1] = (uint32_t)(uintptr_t)node;
        node[1] = 0;
    } else {
        account[1] = (uint32_t)(uintptr_t)node;
        account[0] = (uint32_t)(uintptr_t)node;
        node[1] = 0;
        node[0] = 0;
    }
    *(uint16_t *)((uint8_t *)raw + 8) = *(uint16_t *)((uint8_t *)account + 0x38);
}
