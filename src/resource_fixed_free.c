/* EU ARM 0x00138354 / 0x002C3928; see docs/recovery/resource-fixed-free.md. */
#include "resource_release.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t read_word(uint32_t address)
{
    return *(volatile uint32_t *)(uintptr_t)address;
}

static void write_word(uint32_t address, uint32_t value)
{
    *(volatile uint32_t *)(uintptr_t)address = value;
}

uint32_t smt4_resource_fixed_insert(uint32_t list, uint32_t node)
{
    uint32_t previous = read_word(list + 4u);
    if (previous == 0) {
        write_word(list, node);
        write_word(list + 4u, node);
        write_word(node + 8u, 0);
        write_word(node + 12u, 0);
    } else {
        uint32_t key = read_word(node);
        while (key <= read_word(previous)) {
            previous = read_word(previous + 8u);
            if (previous == 0)
                break;
        }
        if (previous != 0) {
            uint32_t next = read_word(previous + 12u);
            write_word(previous + 12u, node);
            write_word(node + 8u, previous);
            write_word(node + 12u, next);
            write_word(next ? next + 8u : list + 4u, node);
        } else {
            write_word(node + 8u, 0);
            write_word(node + 12u, read_word(list));
            write_word(list, node);
            write_word(read_word(node + 12u) + 8u, node);
        }
    }
    write_word(list + 8u, read_word(list + 8u) + 1u);
    /* Observed unchanged r0, not a claim about the original C return type. */
    return list;
}

static void unlink_record(uint32_t list, uint32_t node)
{
    uint32_t previous = read_word(node + 8u);
    uint32_t next = read_word(node + 12u);
    write_word(previous ? previous + 12u : list, next);
    write_word(next ? next + 8u : list + 4u, previous);
    write_word(node + 8u, 0);
    write_word(node + 12u, 0);
    write_word(list + 8u, read_word(list + 8u) - 1u);
}

void smt4_resource_fixed_free(uint32_t object, uint32_t address)
{
    uint32_t node = read_word(object);
    while (node != 0) {
        if (read_word(node) == address)
            break;
        node = read_word(node + 12u);
    }
    /* No missing-record guard: the original dereferences node+8 even at zero. */
    unlink_record(object, node);
    uint32_t bytes = read_word(object + 24u);
    uint32_t size = read_word(node + 4u);
    write_word(object + 24u, bytes + size);
    smt4_resource_fixed_insert(object + 12u, node);

    uint32_t right = node ? read_word(node + 12u) : 0;
    if (right != 0) {
        size = read_word(node + 4u);
        uint32_t start = read_word(node);
        uint32_t right_start = read_word(right);
        if (start + size == right_start) {
            write_word(node + 4u, read_word(right + 4u) + size);
            unlink_record(object + 12u, right);
            smt4_resource_release(right);
        }
    }
    /* Reload after metadata release, which may recursively affect pool state. */
    uint32_t left = read_word(node + 8u);
    uint32_t next = left ? read_word(left + 12u) : 0;
    if (next != 0) {
        size = read_word(left + 4u);
        uint32_t start = read_word(left);
        uint32_t next_start = read_word(next);
        if (start + size == next_start) {
            write_word(left + 4u, size + read_word(next + 4u));
            unlink_record(object + 12u, next);
            smt4_resource_release(next);
        }
    }
}
