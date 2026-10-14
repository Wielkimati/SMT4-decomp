#ifndef SMT4_RESOURCE_RECURSIVE_LOCK_H
#define SMT4_RESOURCE_RECURSIVE_LOCK_H
#include <stdint.h>

/* Original three aligned u32 words: base lock, TLS owner, recursion count.
 * No owner validation on release and no saturation on count wrap.
 * Raw ARM ABI: already-owned acquire and nonfinal release preserve r2.
 * Base calls supply r2 otherwise: acquire yields the lock address on initial
 * fast success, zero on slow success. Other scratch returns are not claimed.
 * See resource-lock.md and resource-pool-object-teardown.md. */
void smt4_worker_backend_acquire(uint32_t *lock); /* EU ARM 0x002C3AFC */
void smt4_worker_backend_release(uint32_t *lock); /* EU ARM 0x002C3A78 */
#endif
