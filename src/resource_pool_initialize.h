#ifndef SMT4_RESOURCE_POOL_INITIALIZE_H
#define SMT4_RESOURCE_POOL_INITIALIZE_H
#include <stdint.h>

/* Original address-space contracts. Nonzero alignment and rounded stride;
 * caller supplies mapped storage for every node reached by unsigned iteration.
 * No allocation, validation, clearing of payloads or locking is performed. */
void smt4_resource_pool_initialize(uint32_t *pool, uint32_t element_bytes,
    uint32_t storage, uint32_t storage_bytes, uint32_t alignment,
    uint32_t options); /* EU 0x002A4EB4 */
void smt4_resource_recursive_lock_initialize(uint32_t *lock); /* 0x002C3B54 */
void smt4_resource_base_lock_initialize(uint32_t *lock); /* 0x00138F44 */
#endif
