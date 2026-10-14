#ifndef SMT4_RESOURCE_WORKER_PREFIX_H
#define SMT4_RESOURCE_WORKER_PREFIX_H
#include "resource_worker_file_open.h"

/* EU 0x0044E650; removal compares/clears word +8 after disposal returns. */
extern uint32_t smt4_worker_backend_state[5];
extern const uint8_t smt4_worker_prefix_fallback[8]; /* EU 0x00407FBC */
#include "resource_break.h"

/* EU 0x003561F0..0x00356204: clear +0/+4/+8; preserve +12..+15.
 * The receiver is word-aligned and has at least twelve writable bytes. */
uint32_t smt4_worker_prefix_record_initialize(uint32_t address);
/* Adapted startup slice 0x003F3570..0x003F3584 of 0x003F3568: construct
 * 32 records at 0x004D43E0, stride 16, and retain the helper's r0 result.
 * This does not recover the enclosing pool/lock/destructor startup. */
uint32_t smt4_worker_prefix_initialize(void);

/* Names end at NUL or colon within the first eight readable bytes. Longer
 * names enter the diagnostic; any returning continuation uses private data.
 * Backend/vtable storage must be valid if removal invokes slot +0x30. */
uint32_t smt4_worker_prefix_register(const uint8_t *name, uint32_t backend,
                                   uint32_t flag, uint32_t retain); /* 0x002B5E70 */
uint32_t smt4_worker_prefix_remove(const uint8_t *name); /* 0x002C4054 */
#endif
