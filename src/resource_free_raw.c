/* EU ARM 0x001244E8; see docs/recovery/resource-free-raw.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t read_word(uint32_t address)
{
    return *(volatile uint32_t *)(uintptr_t)address;
}

static int contains(uint32_t base, uint32_t offset, uint32_t address)
{
    uint32_t start = read_word(base + offset);
    /* Preserve the short-circuit read and wrapped end, not a wrapped interval. */
    return start <= address && address < start + read_word(base + offset + 4u);
}

void smt4_resource_heap_free(uint32_t address)
{
    uint32_t base = smt4_resource_raw_state[1];
    uint32_t heap, lock;
    if (contains(base, 0x14u, address)) {
        heap = base + 0x1cu;
        lock = base + 0x74u;
    } else if (contains(base, 0x80u, address)) {
        heap = base + 0x88u;
        lock = base + 0xe0u;
    } else if (contains(base, 0xecu, address)) {
        smt4_resource_fixed_free(0x4e4100u, address);
        return;
    } else if (contains(base, 0xf8u, address)) {
        smt4_resource_fixed_free(0x4e411cu, address);
        return;
    } else {
        return;
    }
    smt4_resource_heap_acquire(lock);
    smt4_resource_heap_free_counted(heap, address);
    smt4_resource_heap_release(lock);
}
