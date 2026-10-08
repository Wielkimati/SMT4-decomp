/* EU ARM 0x00144978; see docs/recovery/resource-fixed-allocate.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t read_word(uint32_t address)
{
    return *(volatile uint32_t *)(uintptr_t)address;
}

static void write_word(uint32_t address, uint32_t value)
{
    *(volatile uint32_t *)(uintptr_t)address = value;
}

void *smt4_resource_fixed_allocate(uint32_t object, uint32_t size,
                                   uint32_t third, uint32_t fourth)
{
    (void)third;
    (void)fourth;
    uint32_t node = read_word(object + 12u);
    while (node != 0) {
        uint32_t available = read_word(node + 4u);
        /* First fit tests the requested size, before rounding (even at zero). */
        if (available >= size) {
            uint32_t rounded = (size + 127u) & ~127u;
            if (available != rounded) {
                uint32_t allocated = (uint32_t)(uintptr_t)
                    smt4_resource_allocate_lower(0x100, 0x100, 0, 0x10, 1);
                /* No null-result guard in the original. Preserve initialization
                 * and reloads across the potentially recursive allocation. */
                write_word(allocated, 0);
                write_word(allocated + 4u, 0);
                write_word(allocated + 8u, 0);
                write_word(allocated + 12u, 0);
                write_word(allocated, read_word(node));
                write_word(allocated + 4u, rounded);
                write_word(node, read_word(node) + rounded);
                write_word(node + 4u, read_word(node + 4u) - rounded);
                uint32_t bytes = read_word(object + 24u);
                uint32_t allocated_size = read_word(allocated + 4u);
                write_word(object + 24u, bytes - allocated_size);
                smt4_resource_fixed_insert(object, allocated);
                return (void *)(uintptr_t)read_word(allocated);
            }
            write_word(object + 24u, read_word(object + 24u) - available);
            uint32_t previous = read_word(node + 8u);
            uint32_t next = read_word(node + 12u);
            write_word(previous ? previous + 12u : object + 12u, next);
            write_word(next ? next + 8u : object + 16u, previous);
            write_word(node + 8u, 0);
            write_word(node + 12u, 0);
            write_word(object + 20u, read_word(object + 20u) - 1u);
            smt4_resource_fixed_insert(object, node);
            return (void *)(uintptr_t)read_word(node);
        }
        node = read_word(node + 12u);
    }
    return 0;
}
