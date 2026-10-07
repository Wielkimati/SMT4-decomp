/* Reconstructed from the EU ARM helpers documented in docs/recovery/tbcr-access.md.
 * No loader is implemented here. The registry remains external.
 */
#include "tbcr_access.h"
#include "unsigned_quotient.h"
#include "resource_lifecycle.h"

/* This unit models original 32-bit addresses, including modular additions.
 * A host adaptation must explicitly replace this address/registry boundary.
 */
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires the original 32-bit address space");

static uint32_t read_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* EU 0x002AC358. Header offsets and pointer additions are uint32 modulo 2^32. */
const void *tbcr_select_section(const void *container, uint32_t section_index)
{
    const uint8_t *base = container;
    if (!base || read_u32le(base) != UINT32_C(0x52434254))
        return 0;
    if (section_index >= read_u32le(base + 8))
        return 0;

    uint32_t address = (uint32_t)(uintptr_t)base;
    uint32_t slot = address + UINT32_C(12) + section_index * UINT32_C(4);
    uint32_t section_address = address + read_u32le(base + 4) +
                              read_u32le((const uint8_t *)(uintptr_t)slot);
    const uint8_t *section = (const uint8_t *)(uintptr_t)section_address;
    if (!section || read_u32le(section) != UINT32_C(0x314C4254))
        return 0;
    return section;
}

/* EU 0x002C0EF0. The header's +0x0C word does not select the payload. */
const uint8_t *tbl1_payload(const void *section)
{
    const uint8_t *bytes = section;
    if (!bytes || read_u32le(bytes) != UINT32_C(0x314C4254))
        return 0;
    return (const uint8_t *)(uintptr_t)((uint32_t)(uintptr_t)bytes + UINT32_C(16));
}

/* EU 0x002C0EA0. Zero divisor returns zero without entering division. */
uint32_t tbl1_entry_count(const void *section)
{
    const uint8_t *bytes = section;
    if (!bytes || read_u32le(bytes) != UINT32_C(0x314C4254))
        return 0;
    uint32_t entry_size = read_u32le(bytes + 8);
    if (!entry_size)
        return 0;
    return smt4_unsigned_quotient(read_u32le(bytes + 4), entry_size);
}

/* EU 0x002C0F18. Registry entries retain their original 16-byte serialized layout. */
const void *resource_select_tbcr_section(uint32_t resource_id,
                                         uint32_t section_index)
{
    const void *container = 0;
    if (resource_id < 67) {
        uint32_t address = read_u32le(smt4_table_resource_registry + resource_id * 16 + 4);
        container = (const void *)(uintptr_t)address;
    }
    return tbcr_select_section(container, section_index);
}
