#ifndef SMT4_RESOURCE_WORKER_SERVICE_ACQUIRE_H
#define SMT4_RESOURCE_WORKER_SERVICE_ACQUIRE_H
#include <stdint.h>

extern volatile int32_t smt4_service_manager_count; /* EU 0x00471B90 */
extern volatile uint32_t smt4_service_manager_handle; /* EU 0x00471BA4 */
/* ARM 0x002C1590, noncontiguous tail 0x0012954C. Signed length comparison. */
uint32_t smt4_worker_service_acquire(volatile uint32_t *output,
    const char *name, uint32_t length, uint32_t flags);
/* ARM 0x002ADBA4. Both words are captured before either store. */
void *smt4_service_name_copy(void *output, const void *name);
/* ARM 0x002C32E4. Requires mapped bytes through the final aligned word. */
uint32_t smt4_worker_service_name_length(const char *name);
#endif
