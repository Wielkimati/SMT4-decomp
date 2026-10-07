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
uint32_t *smt4_worker_object_allocate(uint32_t bytes);
void smt4_worker_path_reset(uint32_t state[2]);
uint32_t smt4_worker_path_measure(const char *path, uint32_t limit, uint32_t state[2]);
uint32_t smt4_worker_path_convert(uint16_t *out, const char *path, uint32_t bytes, uint32_t state[2]);
uint32_t smt4_worker_file_open(uint32_t *handle, const uint16_t *path, uint32_t mode);
uint32_t smt4_worker_data_allocate(uint32_t type, uint32_t alignment, uint32_t zero,
                                  uint32_t size, uint32_t parameter, uint32_t direction);
void smt4_worker_io_acquire(uint32_t handle);
void smt4_worker_io_release(uint32_t handle);
void smt4_worker_file_preclose(uint32_t handle);
void smt4_worker_file_close(uint32_t handle);
#endif
