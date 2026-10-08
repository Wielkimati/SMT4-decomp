#ifndef SMT4_RESOURCE_WORKER_IO_H
#define SMT4_RESOURCE_WORKER_IO_H
#include <stdint.h>

/* Adapted internal region [0x00113E80,0x00114070), with allocation branches
 * at 0x00114098..0x00114130. Valid 32-bit objects and bounded converted paths
 * are required; this is neither a thread entry nor a filesystem implementation. */
void smt4_worker_state0_io(uint32_t *descriptor);

extern const uint32_t smt4_worker_file_construction[4];
extern uint32_t smt4_worker_io_lock_handle;
extern uint32_t smt4_worker_io_busy;
/* EU 0x002C244C: forwards to aligned allocation with fixed route words. */
uint32_t *smt4_worker_object_allocate(uint32_t bytes);
#include "resource_worker_path.h"
uint32_t smt4_worker_file_open(uint32_t *handle, const uint16_t *path, uint32_t mode);
/* EU 0x002BF7EC, recovered variable-alignment wrapper. Older worker checks
 * still model it. The fifth word is alignment; the second is a raw route option. */
uint32_t smt4_worker_data_allocate(uint32_t first, uint32_t second, uint32_t third,
                                  uint32_t size, uint32_t alignment, uint32_t direction);
void smt4_worker_io_acquire(uint32_t handle);
void smt4_worker_io_release(uint32_t handle);
void smt4_worker_file_preclose(uint32_t handle);
void smt4_worker_file_close(uint32_t handle);
#endif
