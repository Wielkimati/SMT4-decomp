#ifndef SMT4_TBCR_ACCESS_H
#define SMT4_TBCR_ACCESS_H

#include <stdint.h>

/* Original loaded-memory helpers, not a bounded file parser.
 * See docs/recovery/tbcr-access.md for alignment/lifetime/address preconditions.
 */
const void *tbcr_select_section(const void *container, uint32_t section_index);
const uint8_t *tbl1_payload(const void *section);
uint32_t tbl1_entry_count(const void *section);
const void *resource_select_tbcr_section(uint32_t resource_id,
                                         uint32_t section_index);

#endif
