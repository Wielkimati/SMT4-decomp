#ifndef SMT4_RESOURCE_CREATE_H
#define SMT4_RESOURCE_CREATE_H
#include "resource_sync.h"

/* Original globals, bound to EU addresses by the comparison linker. */
extern uint32_t smt4_file_sync_handle;
extern uint32_t smt4_file_list_head;
extern const char smt4_file_path_format[];
/* Recovered in resource_create_sync.c; SVC r1 is published even on failure. */
uint32_t smt4_file_acquire(uint32_t *index, const uint32_t *handles,
                           uint32_t count, uint32_t wait_all, uint64_t timeout);
uint32_t smt4_file_release(uint32_t *previous, uint32_t handle);
/* The result dispatcher ignores word two and transports caller LR to diagnostics. */
uint32_t smt4_file_check_result(uint32_t result, uint32_t unused);
/* Remaining constructor dependencies; some have separate recovered source. */
void *smt4_file_allocate(uint32_t first, uint32_t second, uint32_t third,
                         uint32_t size, uint32_t fifth);
void smt4_file_clear(void *destination, uint32_t size);
int32_t smt4_file_path_length(const char *path);
/* Recovered ARM 0x002BF8C0: NUL-inclusive copy, returns destination.
 * Both addresses aligned: word reads/stores, byte stores in the final word.
 * Otherwise: byte reads/stores throughout. No bounds/overlap checks. */
char *smt4_file_path_copy(char *destination, const char *source);
#endif
