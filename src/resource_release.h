#ifndef SMT4_RESOURCE_RELEASE_H
#define SMT4_RESOURCE_RELEASE_H
#include "resource_lifecycle.h"

/* EU 0x00465120; opaque allocator state, original 32-bit words. */
extern uint32_t smt4_resource_allocator_state[15];
/* Synchronization remains an external boundary. */
void smt4_resource_heap_acquire(uint32_t handle);
void smt4_resource_heap_release(uint32_t handle);
uint32_t smt4_resource_release_convert(uint32_t address);
/* EU 0x002B3340; four ordered inclusive u32 ranges, unmatched returns zero.
 * Older conversion checker modes retain their explicit selector models. */
uint32_t smt4_resource_heap_index(uint32_t raw);
/* EU 0x001244E8: ordered half-open raw ranges; older checkers model this router.
 * Void interface: callers do not consume the final scratch r0 value. */
void smt4_resource_heap_free(uint32_t address);
/* EU 0x00138354: used-record removal and right-then-left free coalescing.
 * Recursive metadata release is an external boundary in the direct checker. */
void smt4_resource_fixed_free(uint32_t object, uint32_t address);
/* EU 0x002C3928: unsigned key order; new records precede equal keys.
 * Returns the observed unchanged list address; consumed meaning is unknown. */
uint32_t smt4_resource_fixed_insert(uint32_t list, uint32_t node);
#endif
