#ifndef SMT4_RESOURCE_ALIGNED_COPY_H
#define SMT4_RESOURCE_ALIGNED_COPY_H
#include <stdint.h>
/* EU 0x002BCFAC: both pointers word aligned; returns destination end.
 * Full batches load before storing, not a memmove contract. Existing name
 * retained for diagnostic ABI compatibility. See both caller recovery reports.
 */
void *smt4_diagnostic_copy(void *output, const volatile void *input, uint32_t bytes);
#endif
