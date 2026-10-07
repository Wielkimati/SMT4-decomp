/* Behavioral reconstruction from EU ARM instructions at 0x002883E8.
 * Reference SHA-256 and instruction evidence: docs/tbcr-consumers-eu.md.
 * Helper implementations can be selected by the comparison build.
 */
#include "nkm_sort_index.h"
#include "tbcr_access.h"

uint32_t nkm_sort_index_lookup(uint32_t index)
{
    const void *section = resource_select_tbcr_section(1, 2);
    const uint8_t *payload = tbl1_payload(section);
    uint32_t count = tbl1_entry_count(section);
    uint32_t offset = index < count ? index * UINT32_C(4) : 0;

    /* Explicit little-endian halfword; the upper half of a record is ignored. */
    return (uint32_t)payload[offset] | ((uint32_t)payload[offset + 1] << 8);
}
