#ifndef SMT4_RESOURCE_WORKER_BACKEND_H
#define SMT4_RESOURCE_WORKER_BACKEND_H
#include "resource_worker_prefix.h"

/* Original 32-bit layouts, not native service replacements. Pool offsets:
 * +14 options, +18 element bytes, +24 free head, +2c used count, +30 lock.
 * Backend: +0 vtable, +4 service word, +8/+c archive handle low/high. */
extern uint32_t smt4_worker_backend_pool[]; /* EU 0x004D431C */
extern const uint32_t smt4_worker_backend_vtable[]; /* EU 0x004209F8 */
uint32_t *smt4_worker_backend_pool_take(uint32_t *pool); /* 0x002B5D6C */
uint32_t smt4_worker_backend_create(uint32_t **output, uint32_t archive); /* 0x003568C8 */
uint32_t smt4_worker_backend_service(uint32_t *object); /* 0x0023A004 */
uint32_t *smt4_worker_backend_teardown(uint32_t *object); /* 0x0035674C */
void smt4_worker_backend_dispose(uint32_t *object); /* 0x003562D0 */
uint32_t smt4_worker_backend_register(const uint8_t *name); /* 0x00354DEC */

/* Recovered IPC wrappers; TLS and kernel behavior remain platform boundaries.
 * Nonnegative kernel return publishes the handle even on service failure. */
uint32_t smt4_worker_backend_archive_open(uint32_t *service, uint64_t *handle,
    uint32_t archive, uint32_t type, const uint32_t *data, uint32_t bytes); /* 0x002ADBE8 */
uint32_t smt4_worker_backend_archive_close(uint32_t *service, uint64_t handle); /* 0x002ADBB8 */
#include "resource_recursive_lock.h"
/* Unrecovered boundary. Diagnostic normal return is conditional. */
void smt4_worker_backend_diagnostic(uint32_t result, uint32_t site); /* 0x002BBD70 */
#include "resource_clear.h" /* Recovered EU 0x00139F54 word fill. */
#endif
