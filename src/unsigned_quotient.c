/* Behavioral reconstruction of EU 0x002C6C64 and its shift/subtract body.
 * See docs/recovery/unsigned-quotient.md for original ranges and scope.
 * The original skips leading zero quotient bits and unrolls subtraction;
 * this loop expresses the same nonzero-divisor quotient without library calls.
 */
#include "unsigned_quotient.h"

uint32_t smt4_unsigned_quotient(uint32_t dividend, uint32_t divisor)
{
    uint32_t quotient = 0;
    for (uint32_t bit = 32; bit != 0;) {
        --bit;
        /* Compare before shifting the divisor, as in the original RSBS.
         * A successful comparison proves the left shift cannot lose bits.
         */
        if ((dividend >> bit) >= divisor) {
            dividend -= divisor << bit;
            quotient |= UINT32_C(1) << bit;
        }
    }
    return quotient;
}
