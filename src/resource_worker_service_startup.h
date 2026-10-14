#ifndef SMT4_RESOURCE_WORKER_SERVICE_STARTUP_H
#define SMT4_RESOURCE_WORKER_SERVICE_STARTUP_H
#include "resource_worker_backend.h"
#include "resource_pool_owner.h" /* Reuse the recovered 0x002BBD3C accessor. */
#include "resource_worker_service_acquire.h"
#include "resource_worker_service_setup.h"

/* EU original storage: +4 is both the startup guard and acquired service. */
extern volatile uint32_t smt4_worker_service_state[]; /* 0x0044E640 */
extern volatile uint32_t smt4_worker_service_pointer; /* 0x00471A68 */
extern const char smt4_worker_service_name[]; /* 0x00407FB3: fs:USER */
uint32_t smt4_worker_service_startup(void); /* ARM 0x0010F5B8 */
uint32_t smt4_worker_service_state_request(uint32_t *service, uint32_t value); /* 0x0011BA80 */
uint32_t smt4_worker_service_publish(uint32_t pointer); /* 0x0011BAB0 */

/* Recovered separately as smt4_worker_diagnostic; optional diagnostic mode
 * links this consumed alias. Startup supplies r2=1, which the wrapper ignores;
 * the accessor only establishes r0 and r1. Lower wait behavior remains open. */
uint32_t smt4_worker_service_diagnostic(uint32_t result, uint32_t site,
    uint32_t negative); /* 0x002BBD70, same boundary as backend diagnostic */
#endif
