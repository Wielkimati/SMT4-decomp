/* EU ARM 0x0014F608; see docs/recovery/resource-heap-commit-block.md. */
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

static void write_half(uint32_t address, uint32_t value)
{
    *(volatile uint16_t *)(uintptr_t)address = (uint16_t)value;
}

/* Insert after previous, or at the head when previous is null. */
static void insert(uint32_t lists, uint32_t node, uint32_t previous)
{
    uint32_t next = read_word(previous ? previous + 12u : lists);
    write_word(previous ? previous + 12u : lists, node);
    write_word(node + 12u, next);
    write_word(next ? next + 8u : lists + 4u, node);
}

static void free_fragment(uint32_t lists, uint32_t node, uint32_t extent,
                          uint32_t previous)
{
    write_half(node, 0x4652u);
    write_half(node + 2u, 0);
    write_word(node + 12u, 0);
    write_word(node + 8u, previous);
    write_word(node + 4u, extent - 16u);
    insert(lists, node, previous);
}

void *smt4_resource_heap_commit_block(uint32_t lists, uint32_t block,
                                      uint32_t payload, uint32_t rounded_size,
                                      uint32_t reverse)
{
    uint32_t capacity = read_word(block + 4u);
    uint32_t old_flags = *(volatile uint16_t *)(uintptr_t)(block + 2u);
    uint32_t end = block + 16u + capacity;
    uint32_t allocated_end = payload + rounded_size;
    uint32_t header = payload - 16u;
    uint32_t origin = block - ((old_flags >> 8) & 0x7fu);
    uint32_t previous = read_word(block + 8u);
    uint32_t next = read_word(block + 12u);
    write_word(previous ? previous + 12u : lists, next);
    write_word(next ? next + 8u : lists + 4u, previous);

    uint32_t allocated_start = header;
    uint32_t prefix = header - origin;
    if (prefix >= 20u &&
        (reverse != 0 || *(volatile uint8_t *)(uintptr_t)(lists + 20u) != 0)) {
        free_fragment(lists, origin, prefix, previous);
        previous = origin;
    } else {
        allocated_start = origin;
    }
    uint32_t suffix = end - allocated_end;
    if (suffix >= 20u &&
        (reverse != 1 || *(volatile uint8_t *)(uintptr_t)(lists + 20u) != 0)) {
        free_fragment(lists, allocated_end, suffix, previous);
    } else {
        allocated_end = end;
    }

    uint32_t clear_flags = read_word(lists - 4u);
    uint32_t extent = allocated_end - allocated_start;
    if ((clear_flags & 1u) != 0) {
        /* Original clears whole words only, including absorbed padding/header. */
        uint32_t words = extent >> 2;
        for (uint32_t i = 0; i < words; ++i)
            write_word(allocated_start + i * 4u, 0);
    }

    write_half(header, 0x5544u);
    write_word(header + 8u, 0);
    write_word(header + 4u, allocated_end - header - 16u);
    write_word(header + 12u, 0);
    uint32_t flags = ((reverse << 15) & ~0x7f00u) |
                     (((header - allocated_start) & 0x7fu) << 8);
    write_half(header + 2u, flags);
    uint32_t group = *(volatile uint16_t *)(uintptr_t)(lists + 16u);
    flags = (flags & ~0xffu) | (group & 0xffu);
    write_half(header + 2u, flags);
    uint32_t used_tail = read_word(lists + 12u);
    write_word(header + 8u, used_tail);
    insert(lists + 8u, header, used_tail);
    return (void *)(uintptr_t)payload;
}
