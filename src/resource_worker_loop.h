#ifndef SMT4_RESOURCE_WORKER_LOOP_H
#define SMT4_RESOURCE_WORKER_LOOP_H
#include "resource_worker.h"

/* EU 0x00113D58 outer control flow. Node processing is the separately
 * reconstructed region; lower event/synchronization calls remain dependencies. */
void smt4_file_worker(void);
extern volatile uint8_t smt4_worker_stop;
extern uint32_t smt4_worker_event[];
void smt4_worker_event_wait(uint32_t *event);
void smt4_worker_event_reset(uint32_t *event);
#endif
