/* EU base v0; instruction-backed contract: resource-registry-initialize.md. */
#include "resource_worker_prefix.h"
#include "resource_array_initialize.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_prefix_record_initialize(uint32_t address)
{
    uint32_t *record = (uint32_t *)(uintptr_t)address;
    record[0] = 0;
    record[1] = 0;
    record[2] = 0;
    return address;
}

uint32_t smt4_worker_prefix_initialize(void)
{
    return smt4_array_initialize((uint32_t)(uintptr_t)smt4_worker_prefix_table,
                               smt4_worker_prefix_record_initialize, 16, 32);
}
