#ifndef SMT4_TABLE_RESOURCE_COPY_H
#define SMT4_TABLE_RESOURCE_COPY_H
#include <stdint.h>
#include "resource_aligned_copy.h"
/* EU ARM 0x002C6048. Void consumed contract, not memcpy's
 * return value. Ordinary nonoverlapping, nonwrapping original-address spans.
 * Reuses the aligned entry declared above. Unaligned LDRs
 * require the original ARM alignment environment; see the recovery report.
 */
void smt4_table_reload_copy(uint32_t destination, uint32_t source, uint32_t size);
#endif
