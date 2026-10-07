#ifndef SMT4_RESOURCE_WORKER_H
#define SMT4_RESOURCE_WORKER_H
#include "resource_create.h"

/* Adapted single-node region of EU worker 0x00113D58, starting at 0x00113DE8.
 * Returns the next descriptor at the 0x00113DD4 loop boundary. This is not
 * the worker's thread-entry ABI. Requires valid original 32-bit addresses. */
uint32_t *smt4_file_worker_step(uint32_t *descriptor);

/* Separately recovered in resource_worker_io.c: 0x00113E80 through arrival
 * at 0x00114070. Existing step/completion checkers still model this boundary;
 * the dedicated I/O checker executes it with explicit lower-call models. */
void smt4_worker_state0_io(uint32_t *descriptor);
/* The worker supplies r2=1 to the shared release helper. */
uint32_t smt4_worker_unlock(uint32_t *previous, uint32_t handle, uint32_t count);
#endif
