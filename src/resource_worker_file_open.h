#ifndef SMT4_RESOURCE_WORKER_FILE_OPEN_H
#define SMT4_RESOURCE_WORKER_FILE_OPEN_H
#include "resource_worker_io.h"

/* EU 0x004D43E0: 32 records, key low/high, backend address, two byte flags
 * at +12/+13 and two preserved bytes at +14/+15.
 * The runtime registry and backend objects must already be initialized. */
extern uint32_t smt4_worker_prefix_table[32][4];
uint32_t smt4_worker_path_backend(const uint16_t *path); /* ARM 0x002B5CA0 */
uint32_t smt4_worker_utf16_length(const uint16_t *text); /* Thumb 0x002B5C8C */

/* Open 0x002BB944 consumes a readable prefix (up to eight units), and a
 * terminated suffix when a backend is found. Failure preserves *handle.
 * The virtual backend must write its output on a nonnegative status. */
#endif
