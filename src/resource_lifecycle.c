/* EU ARM lifecycle wrappers. Evidence/limits: docs/recovery/resource-lifecycle.md.
 * Reconstructed from instructions; the file I/O/allocation backend is external.
 */
#include "resource_lifecycle.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

/* EU 0x00297714. A null backend result still returns 1. */
uint32_t resource_load_if_dynamic(uint32_t resource_id)
{
    if (resource_id >= 67)
        return 0;
    uint8_t *entry = smt4_table_resource_registry + resource_id * 16;
    if (read32(entry + 4))
        return 1;
    if (entry[12])
        return 0;
    uint32_t address = smt4_resource_load(read32(entry), entry + 8, 0);
    write32(entry + 4, address);
    return 1;
}

/* EU 0x0033C844. Scheduling/completion semantics belong to the backend. */
uint32_t resource_request_if_dynamic(uint32_t resource_id)
{
    if (resource_id >= 67)
        return 0;
    uint8_t *entry = smt4_table_resource_registry + resource_id * 16;
    if (read32(entry + 4))
        return 1;
    if (entry[12])
        return 0;
    smt4_resource_request(read32(entry), entry + 4, 0, resource_load_complete, entry);
    return 1;
}

/* EU 0x002A49E0. Preserve stale size, path, policy and reserved bytes. */
uint32_t resource_release_if_dynamic(uint32_t resource_id)
{
    if (resource_id >= 67)
        return 0;
    uint8_t *entry = smt4_table_resource_registry + resource_id * 16;
    uint32_t address = read32(entry + 4);
    if (!address)
        return 1;
    if (entry[12])
        return 0;
    smt4_resource_release(address);
    write32(entry + 4, 0);
    return 1;
}

/* EU 0x0019F990. No null, policy, magic, or index validation. */
void resource_load_complete(uint32_t address, uint8_t *entry, uint32_t size)
{
    write32(entry + 4, address);
    write32(entry + 8, size);
}
