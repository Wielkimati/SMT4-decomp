#ifndef SMT4_UNSIGNED_QUOTIENT_H
#define SMT4_UNSIGNED_QUOTIENT_H

#include <stdint.h>

/* EU 0x002C6C64: only the consumed r0 quotient contract is reconstructed.
 * Precondition: divisor != 0. Other original result registers are not modeled.
 */
uint32_t smt4_unsigned_quotient(uint32_t dividend, uint32_t divisor);

#endif
