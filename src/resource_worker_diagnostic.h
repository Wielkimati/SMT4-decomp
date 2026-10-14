#ifndef SMT4_RESOURCE_WORKER_DIAGNOSTIC_H
#define SMT4_RESOURCE_WORKER_DIAGNOSTIC_H
#include <stdint.h>
#include "resource_aligned_copy.h"

/* Project-authored EU base v0 contracts, not native service replacements.
 * Record is exactly 128 bytes; unknown payload bytes are preserved. */
typedef struct {
    uint8_t type, flags;
    uint16_t magic;
    uint32_t result, site, process;
    uint8_t unknown[112];
} smt4_diagnostic_record;
extern volatile smt4_diagnostic_record smt4_diagnostic_global; /* 0x004D4200 */
extern volatile uint32_t smt4_diagnostic_handle; /* 0x0044E608 */
extern const uint32_t smt4_diagnostic_constants[3]; /* 0x00407F9C */
extern uint32_t smt4_diagnostic_lock[]; /* 0x004D4280 */
uint32_t smt4_worker_diagnostic(uint32_t result, uint32_t site); /* 0x002BBD70; r2 ignored */
uint32_t smt4_diagnostic_deliver(volatile smt4_diagnostic_record *record); /* 0x002AD7E8 */
/* Original entry additionally returns r2: final release r2 for types 2/5,
 * wait r2 otherwise. Ordinary C callers consume only r0; assembly callers
 * must capture r2 before any subsequent C call. See resource-delivery-return.md. */
uint32_t smt4_diagnostic_process(volatile uint32_t *output, uint32_t handle); /* 0x00144900 */
uint32_t smt4_diagnostic_request(volatile uint32_t *service,
    const volatile smt4_diagnostic_record *record); /* 0x00146964 */
/* Recovered in resource_diagnostic_wait.c; exclusive outcomes and kernel
 * arbitration remain external. Initializer returns the last exchanged word. */
uint32_t smt4_diagnostic_wait_initialize(uint32_t state[2], uint32_t mode); /* 0x002C5470 */
/* Also returns r2: incoming r2 for state one, zero after successful zero
 * exchange, otherwise the last arbitration r2. See resource-wait-return.md. */
uint32_t smt4_diagnostic_wait(uint32_t state[2]); /* 0x002C367C */
#endif
