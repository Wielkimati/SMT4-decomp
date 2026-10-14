/* EU base v0; instruction-backed contract: resource-registry-initialize.md. */
#include "resource_array_initialize.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_array_initialize(uint32_t base, smt4_array_constructor constructor,
                               uint32_t stride, uint32_t count)
{
    if (constructor != 0) {
        uint32_t cursor = base;
        while (count != 0) {
            --count;
            constructor(cursor);
            cursor += stride;
        }
    }
    return base;
}
