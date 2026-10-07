/* EU ARM 0x002C3A98; see docs/recovery/resource-heap-allocate.md. */
#include "resource_allocate.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void *smt4_resource_heap_allocate(uint32_t heap, uint32_t size, uint32_t alignment,
                                  uint32_t fourth, uint32_t fifth, uint32_t sixth)
{
    uint32_t subobject = heap + 0x18u;
    smt4_resource_heap_configure_fourth(subobject, fourth);
    smt4_resource_heap_configure_fifth(subobject, fifth);
    smt4_resource_heap_configure_sixth(subobject, sixth);
    void *result = smt4_resource_heap_allocate_inner(subobject, size, alignment);
    if (result != 0) {
        volatile uint32_t *count = (volatile uint32_t *)(uintptr_t)(heap + 0x54u);
        *count = *count + 1u;
    }
    return result;
}
