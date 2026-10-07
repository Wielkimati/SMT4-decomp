#ifndef SMT4_NKM_SORT_INDEX_H
#define SMT4_NKM_SORT_INDEX_H

#include <stdint.h>

/* EU 0x002883E8; descriptive name, original return meaning unknown.
 * Requires a loaded resource 1 / section 2 and readable selected halfword.
 * See docs/recovery/nkm-sort-index.md for the supported memory contract.
 */
uint32_t nkm_sort_index_lookup(uint32_t index);

/* EU 0x001A0EA4; full-width key compared with u16 section-3 keys.
 * First matching value, or 50 for no match / zero first value.
 * See docs/recovery/nkm-section3.md for memory and empty-resource behavior.
 */
uint32_t nkm_section3_pair_lookup(uint32_t key);

#endif
