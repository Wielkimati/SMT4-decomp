#ifndef SMT4_RESOURCE_WORKER_FILE_METHODS_H
#define SMT4_RESOURCE_WORKER_FILE_METHODS_H
#include <stdint.h>

/* EU vtable 0x004208B0 slots +0x24/+0x0C/+0x28. Valid original objects.
 * Size requires a written lower output if the diagnostic returns. */
uint64_t smt4_worker_file_size(uint32_t *object); /* 0x003DFC54 */
void smt4_worker_file_seek(uint32_t *object, uint64_t offset, uint32_t origin); /* 0x00354F70 */
uint32_t smt4_worker_file_read(uint32_t *object, uint32_t *count,
                               uint32_t buffer, uint32_t bytes); /* 0x00354F9C */

/* Recovered size/cache and seek/position contracts; see the position report.
 * handle[0] is tagged; [1:2] is cursor low/high; [3:4] is size cache low/high.
 * Valid word-aligned five-word storage, separate aligned size output.
 * The seek r1 word
 * duplicates origin; the lower routine ignores it (AAPCS alignment gap). */
uint32_t smt4_worker_file_size_lower(uint32_t *handle, uint64_t *size); /* 0x002BB8EC */
uint32_t smt4_worker_file_seek_lower(uint32_t *handle, uint32_t origin_register,
                                     uint64_t offset, uint32_t origin); /* 0x002ACA78 */
uint32_t smt4_worker_file_position(uint32_t *handle, uint32_t unused,
                                   uint64_t position); /* 0x00146458 tail entry */
/* Recovered null-check/virtual size dispatch through vtable +8. The handle is
 * an untagged concrete object address, not the kernel handle at object+4.
 * The lower cache layer consumes output only on a nonnegative result. */
uint32_t smt4_worker_file_size_service(uint64_t *size, uint32_t handle); /* 0x002A8914 */
/* Recovered loop: valid separate object/count storage. Successful services
 * write received; failure preserves caller count and earlier cursor progress.
 * Buffer/count arithmetic wraps in 32 bits; cursor increments sign-extend
 * each received word. Termination depends on service responses. */
uint32_t smt4_worker_file_read_lower(uint32_t *handle, uint32_t *count,
                                     uint32_t buffer, uint32_t bytes); /* 0x002BB864 */
/* Recovered read dispatch: rejects null handle/buffer, delays before vtable +0.
 * r0/r1 count/handle, r2/r3 cursor, stack buffer/bytes. Count must be writable
 * if the concrete IPC returns a nonnegative kernel result. */
uint32_t smt4_worker_file_read_service(uint32_t *received, uint32_t handle,
                                       uint64_t cursor, uint32_t buffer,
                                       uint32_t bytes); /* 0x002A4E54 */
extern volatile uint8_t smt4_worker_file_delay_state[]; /* EU 0x0044E650 */
void smt4_worker_file_pre_read_delay(uint32_t mode); /* 0x002ADC48 */
void smt4_worker_file_diagnostic(uint32_t result, uint32_t original_site); /* 0x002BBD70 */
#endif
