#ifndef SMT4_RESOURCE_WORKER_PREFIX_H
#define SMT4_RESOURCE_WORKER_PREFIX_H
#include "resource_worker_file_open.h"

/* EU 0x0044E650; removal compares/clears word +8 after disposal returns. */
extern uint32_t smt4_worker_backend_state[5];
extern const uint8_t smt4_worker_prefix_fallback[8]; /* EU 0x00407FBC */
void smt4_worker_prefix_diagnostic(void); /* 0x002BCE9C; may not return */

/* Names end at NUL or colon within the first eight readable bytes. Longer
 * names enter the diagnostic; any returning continuation uses private data.
 * Backend/vtable storage must be valid if removal invokes slot +0x30. */
uint32_t smt4_worker_prefix_register(const uint8_t *name, uint32_t backend,
                                   uint32_t flag, uint32_t retain); /* 0x002B5E70 */
uint32_t smt4_worker_prefix_remove(const uint8_t *name); /* 0x002C4054 */
#endif
