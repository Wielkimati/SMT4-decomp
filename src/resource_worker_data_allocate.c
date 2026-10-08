/* EU ARM 0x002BF7EC; see docs/recovery/resource-worker-data-allocate.md. */
#include "resource_allocate.h"
#include "resource_worker_io.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_data_allocate(uint32_t first, uint32_t second, uint32_t third,
                                   uint32_t size, uint32_t alignment, uint32_t direction)
{
    smt4_resource_heap_acquire(smt4_resource_allocator_state[1]);
    if (alignment < 128u)
        alignment = 128u;
    uint32_t raw_size = (size + alignment + alignment + 0x3bu) & (0u - alignment);
    uint32_t *raw = smt4_resource_allocate_raw(first, second, third, raw_size, direction);
    /* The original has no null-result guard and truncates only after sizing. */
    uint32_t address = (uint32_t)(uintptr_t)raw;
    raw[0] = raw_size;
    ((uint16_t *)raw)[2] = (uint16_t)alignment;
    ((uint16_t *)raw)[3] = 0;
    uint32_t low = (uint16_t)alignment;
    uint32_t mask = low - 1u;
    uint32_t padding = (low - ((address + 0x3cu) & mask)) & mask;
    uint32_t user = address + 0x3cu + padding;
    *(uint32_t *)(uintptr_t)(user - 4u) = address;
    smt4_resource_allocate_register(raw);
    smt4_resource_allocate_zero((void *)(uintptr_t)user, size);
    smt4_resource_heap_release(smt4_resource_allocator_state[1]);
    return user;
}
