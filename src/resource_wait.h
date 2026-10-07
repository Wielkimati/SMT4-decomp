#ifndef SMT4_RESOURCE_WAIT_H
#define SMT4_RESOURCE_WAIT_H
#include "resource_sync.h"

/* EU ARM 0x002BB4F0: signed duration, with modulo-2^64 short-delay scaling. */
void smt4_file_delay(int64_t duration);

/* Signal is recovered separately; timing boundaries remain unrecovered. */
extern uint32_t smt4_file_wait_signal[];
void smt4_file_signal(uint32_t *signal);
void smt4_file_sleep(int64_t duration);
void smt4_file_spin(uint32_t count);
#endif
