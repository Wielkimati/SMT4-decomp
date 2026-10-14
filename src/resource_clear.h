#ifndef SMT4_RESOURCE_CLEAR_H
#define SMT4_RESOURCE_CLEAR_H
#include <stdint.h>
/* Word-aligned mapped storage; end must be reachable by u32 increments of 4.
 * No ordering/length validation; zero-length calls do not access destination. */
void smt4_worker_backend_clear(uint32_t *start, uint32_t end, uint32_t value);
/* Aligned shared body, with low-halfword/low-byte tail stores. */
void smt4_resource_fill_words(uint32_t address, uint32_t count, uint32_t value);
/* EU 0x002C4B84 aligned zero entry; result register is unconsumed. */
void smt4_resource_aligned_zero(void *destination, uint32_t count);
/* Exact byte count, including unaligned starts; result register is unconsumed. */
void smt4_resource_allocate_zero(void *destination, uint32_t count);
#endif
