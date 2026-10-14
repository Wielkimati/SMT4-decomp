/* EU ARM 0x00139F54, 0x002C3B9C and shared body 0x002C4B88.
 * Project-authored recovery; see docs/recovery/resource-clear.md.
 * Volatile accesses retain the observed destination write widths/order.
 * These are original memory operations, not checked native services. */
#include "resource_clear.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_worker_backend_clear(uint32_t *start, uint32_t end, uint32_t value)
{
    uint32_t address = (uint32_t)(uintptr_t)start;
    while (address != end) {
        *(volatile uint32_t *)(uintptr_t)address = value;
        address += 4u;
    }
}

/* Consumed aligned entry at 0x002C4B88; not a saved separate function.
 * The tail uses the low halfword/byte of value, without byte replication. */
void smt4_resource_fill_words(uint32_t address, uint32_t count, uint32_t value)
{
    while (count >= 32u) {
        for (uint32_t i = 0; i < 8u; ++i) {
            *(volatile uint32_t *)(uintptr_t)address = value;
            address += 4u;
        }
        count -= 32u;
    }
    while (count >= 4u) {
        *(volatile uint32_t *)(uintptr_t)address = value;
        address += 4u;
        count -= 4u;
    }
    if ((count & 2u) != 0) {
        *(volatile uint16_t *)(uintptr_t)address = (uint16_t)value;
        address += 2u;
    }
    if ((count & 1u) != 0)
        *(volatile uint8_t *)(uintptr_t)address = (uint8_t)value;
}

void smt4_resource_aligned_zero(void *destination, uint32_t count)
{
    smt4_resource_fill_words((uint32_t)(uintptr_t)destination, count, 0);
}

void smt4_resource_allocate_zero(void *destination, uint32_t count)
{
    uint32_t address = (uint32_t)(uintptr_t)destination;
    if (count < 4u) {
        while (count != 0) {
            *(volatile uint8_t *)(uintptr_t)address = 0;
            ++address;
            --count;
        }
        return;
    }
    uint32_t residue = address & 3u;
    if (residue != 0) {
        uint32_t prefix = 4u - residue;
        if (prefix != 2u) {
            *(volatile uint8_t *)(uintptr_t)address = 0;
            ++address;
        }
        count -= prefix;
        if (prefix >= 2u) {
            *(volatile uint16_t *)(uintptr_t)address = 0;
            address += 2u;
        }
    }
    smt4_resource_fill_words(address, count, 0);
}
