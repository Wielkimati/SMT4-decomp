#ifndef SMT4_RESOURCE_CREATE_H
#define SMT4_RESOURCE_CREATE_H
#include "resource_sync.h"

/* Unrecovered boundaries, bound to EU addresses by the comparison linker. */
extern uint32_t smt4_file_sync_handle;
extern uint32_t smt4_file_list_head;
extern const char smt4_file_path_format[];
uint32_t smt4_file_acquire(uint32_t *index, const uint32_t *handles,
                           uint32_t count, uint32_t wait_all, uint64_t timeout);
uint32_t smt4_file_release(uint32_t *previous, uint32_t handle);
void smt4_file_check_result(uint32_t result, uint32_t negative);
void *smt4_file_allocate(uint32_t first, uint32_t second, uint32_t third,
                         uint32_t size, uint32_t fifth);
void smt4_file_clear(void *destination, uint32_t size);
int32_t smt4_file_path_length(const char *path);
char *smt4_file_path_copy(char *destination, const char *source);
#endif
