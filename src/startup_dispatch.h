#ifndef SMT4_STARTUP_DISPATCH_H
#define SMT4_STARTUP_DISPATCH_H
#include <stdint.h>

/* Original entries: Thumb 0x00100cb8 and ARM 0x00102338. */
void smt4_startup_dispatch_relative(void);
void smt4_startup_dispatch_absolute(void);

/* Parameterized comparison adapters for the same loops, not original entries.
 * Addresses are original 32-bit values; callbacks must preserve the ARM ABI.
 * No validity, null-target, or termination checks are added. */
void smt4_startup_dispatch_relative_range(uint32_t cursor, uint32_t end);
void smt4_startup_dispatch_absolute_range(uint32_t cursor, uint32_t end);
#endif
