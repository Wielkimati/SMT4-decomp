#ifndef SMT4_RESOURCE_SIGNAL_H
#define SMT4_RESOURCE_SIGNAL_H
#include <stdint.h>

/* EU ARM 0x002C4298. The first word and the lock at +4 must be aligned. */
void smt4_file_signal(uint32_t *signal);

/* Recovered in resource_lock.c; original 32-bit address space. */
void smt4_signal_lock_acquire(uint32_t *lock);
void smt4_signal_lock_release(uint32_t *lock);
/* Argument marshalling recovered in resource_arbitration.c; SVC/kernel remains
 * a platform boundary. Earlier isolated checkers still intercept this wrapper. */
extern uint32_t smt4_arbitration_handle;
uint32_t smt4_signal_arbitrate(uint32_t handle, uint32_t *address,
                             uint32_t operation, int32_t count, int64_t timeout);
#endif
