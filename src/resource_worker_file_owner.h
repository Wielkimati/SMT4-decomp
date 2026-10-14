#ifndef SMT4_RESOURCE_WORKER_FILE_OWNER_H
#define SMT4_RESOURCE_WORKER_FILE_OWNER_H
#include "resource_worker_backend.h"

/* Original file object: +0 vtable, +4 OS handle. No native host pointers. */
extern uint32_t smt4_worker_file_pool[]; /* EU 0x004D4358 */
extern const uint32_t smt4_worker_file_vtable[]; /* EU 0x00420998 */
uint32_t smt4_worker_backend_file_open(uint32_t *backend, uint32_t **output,
    const uint32_t descriptor[3], uint32_t flags); /* 0x003565A0 */
uint32_t smt4_worker_file_handle(uint32_t *object); /* 0x00239CD0 */
uint32_t smt4_worker_file_read_method(uint32_t *object, uint32_t *received,
    uint64_t cursor, uint32_t buffer, uint32_t bytes); /* 0x003564A8 */
/* Publishes count after nonnegative kernel status, even on service failure.
 * TLS and SVC remain external; no buffer/count validation is added. */
uint32_t smt4_worker_file_service_read(uint32_t *handle, uint32_t *received,
    uint64_t cursor, uint32_t buffer, uint32_t bytes); /* 0x00356D04 */
uint32_t smt4_worker_file_size_method(uint32_t *object, uint64_t *size); /* 0x003DFCA8 */
/* Writes both output words after nonnegative kernel status, including a negative
 * service result. Negative kernel status preserves output. TLS/SVC external. */
uint32_t smt4_worker_file_service_size(uint32_t *handle, uint64_t *size); /* 0x00356DE8 */
/* Raw ARM entries also carry incoming/returned scratch r2 through teardown,
 * close IPC and recursive pool return; see the pool teardown report. C return
 * types expose r0 only. Register-sensitive callers use the assembly entries. */
uint32_t *smt4_worker_file_teardown(uint32_t *object, uint32_t unused, uint32_t payload); /* 0x00356578 */
void smt4_worker_file_dispose(uint32_t *object, uint32_t unused, uint32_t payload); /* 0x00356438 */

/* Recovered IPC wrappers; TLS acquisition and kernel services remain external.
 * The uint64_t archive parameter is stack
 * aligned under the original ARM ABI; r3 is unused padding. */
uint32_t smt4_worker_file_service_open(uint32_t *service, uint32_t *handle,
    uint32_t transaction, uint64_t archive, uint32_t type, uint32_t data,
    uint32_t bytes, uint32_t flags, uint32_t attributes); /* 0x00356C28 */
uint32_t smt4_worker_file_service_close(uint32_t *handle); /* 0x00356D5C */
/* Close additionally returns kernel scratch r2 unchanged. */
#endif
