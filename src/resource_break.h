#ifndef SMT4_RESOURCE_BREAK_H
#define SMT4_RESOURCE_BREAK_H
#include <stdint.h>

/* EU 0x0044E450. Captured and cleared before invoking the six-word callback. */
typedef void (*smt4_break_callback)(uint32_t, uint32_t, uint32_t, uint32_t,
                                    uint32_t, uint32_t);
extern smt4_break_callback volatile smt4_break_callback_slot;

/* EU ARM 0x002AD90C. r1 is ignored; incoming r2 becomes callback word six.
 * Return is the SVC r0 if the modeled/platform service returns. */
uint32_t smt4_break_dispatch(uint32_t reason, uint32_t unused, uint32_t payload);
/* EU ARM 0x002BCE9C. Forces reason zero, preserving the incoming r2 payload.
 * The historical preclose/prefix names denote this same diagnostic entry. */
uint32_t smt4_worker_file_preclose(uint32_t unused0, uint32_t unused1, uint32_t payload);
uint32_t smt4_worker_prefix_diagnostic(uint32_t unused0, uint32_t unused1, uint32_t payload);
/* EU ARM 0x001526B4..0x001526BC: SVC 0x3C then BX LR. */
uint32_t smt4_break_svc(uint32_t reason, uint32_t word1, uint32_t word2);
#endif
