/* Behavioral reconstruction of EU ARM 0x001A0EA4..0x001A0F1C.
 * Evidence and supported memory: docs/recovery/nkm-section3.md.
 */
#include "nkm_sort_index.h"
#include "tbcr_access.h"

uint32_t nkm_section3_pair_lookup(uint32_t key)
{
    const void *section = resource_select_tbcr_section(1, 3);
    const uint8_t *payload = tbl1_payload(section);

    /* The original calls the count helper before each attempted record. */
    for (uint32_t index = 0; index < tbl1_entry_count(section); ++index) {
        uint32_t offset = index * UINT32_C(4);
        uint32_t candidate = (uint32_t)payload[offset]
                           | ((uint32_t)payload[offset + 1] << 8);
        if (candidate == key) {
            uint32_t value = (uint32_t)payload[offset + 2]
                           | ((uint32_t)payload[offset + 3] << 8);
            return value != 0 ? value : UINT32_C(50);
        }
    }
    return UINT32_C(50);
}
