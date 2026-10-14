#ifndef SMT4_RESOURCE_WORKER_SERVICE_SETUP_H
#define SMT4_RESOURCE_WORKER_SERVICE_SETUP_H
#include "resource_worker_service_acquire.h"
#include "resource_recursive_lock.h"

extern uint32_t smt4_service_manager_lock[]; /* EU 0x004E9BA8 */
extern const char smt4_service_manager_name[]; /* EU 0x0040B6E4 */
uint32_t smt4_worker_service_setup(void); /* ARM 0x002C15C4 */
uint32_t smt4_service_manager_connect(const char *name); /* 0x0011CD48 */
uint32_t smt4_service_manager_register(void); /* 0x00129510 */
/* 0x001382CC: publishes kernel r1 even when the status is negative. */
uint32_t smt4_service_connect_port(volatile uint32_t *output, const char *name);
#endif
