/* EU ARM 0x0014699C / 0x002B33D8; see docs/recovery/resource-heap-free.md. */
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

static void unlink(uint32_t lists, uint32_t previous, uint32_t next)
{
    write_word(previous ? previous + 12u : lists, next);
    write_word(next ? next + 8u : lists + 4u, previous);
}

uint32_t smt4_resource_heap_free_inner(uint32_t subobject, uint32_t payload)
{
    uint32_t node = payload - 16u;
    uint32_t lists = subobject + 0x24u;
    uint32_t metadata = *(volatile uint16_t *)(uintptr_t)(node + 2u);
    uint32_t capacity = read_word(node + 4u);
    uint32_t end = node + 16u + capacity;
    uint32_t origin = node - ((metadata >> 8) & 0x7fu);
    uint32_t previous = read_word(node + 8u);
    uint32_t next = read_word(node + 12u);
    unlink(lists + 8u, previous, next);

    uint32_t right = read_word(lists);
    uint32_t left = 0;
    while (right != 0 && origin > right) {
        left = right;
        right = read_word(right + 12u);
    }
    if (right != 0 && end == right) {
        capacity = read_word(right + 4u);
        end = right + 16u + capacity;
        previous = read_word(right + 8u);
        next = read_word(right + 12u);
        unlink(lists, previous, next);
    }
    if (left != 0) {
        capacity = read_word(left + 4u);
        if (left + 16u + capacity == origin) {
            previous = read_word(left + 8u);
            origin = left;
            next = read_word(left + 12u);
            unlink(lists, previous, next);
            left = previous;
        }
    }
    uint32_t extent = end - origin;
    if (extent >= 16u) {
        *(volatile uint16_t *)(uintptr_t)origin = 0x4652u;
        *(volatile uint16_t *)(uintptr_t)(origin + 2u) = 0;
        write_word(origin + 4u, extent - 16u);
        write_word(origin + 8u, left);
        write_word(origin + 12u, 0);
        next = read_word(left ? left + 12u : lists);
        write_word(left ? left + 12u : lists, origin);
        write_word(origin + 12u, next);
        write_word(next ? next + 8u : lists + 4u, origin);
    }
    /* Observed r0: insertion predecessor. No consumed return meaning is known. */
    return left;
}

uint32_t smt4_resource_heap_free_counted(uint32_t heap, uint32_t payload)
{
    smt4_resource_heap_free_inner(heap + 0x18u, payload);
    uint32_t count = read_word(heap + 0x54u) - 1u;
    write_word(heap + 0x54u, count);
    return count;
}
