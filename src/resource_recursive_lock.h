#ifndef SMT4_RESOURCE_RECURSIVE_LOCK_H
#define SMT4_RESOURCE_RECURSIVE_LOCK_H
#include <stdint.h>

/* Original three aligned u32 words: base lock, TLS owner, recursion count.
 * No owner validation on release and no saturation on count wrap. */
void smt4_worker_backend_acquire(uint32_t *lock); /* EU ARM 0x002C3AFC */
void smt4_worker_backend_release(uint32_t *lock); /* EU ARM 0x002C3A78 */
#endif
