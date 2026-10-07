/* Consumed positive remainder from EU 0x002C61B0's shift/subtract body.
 * This C function returns only the remainder, in r0 rather than original r1.
 * The rebuilt caller uses that C interface; no binary-compatible ABI is claimed.
 */
#include "resource_order.h"

uint32_t smt4_resource_order_remainder(uint32_t dividend, uint32_t divisor)
{
    for (uint32_t bit = 32; bit != 0;) {
        --bit;
        if ((dividend >> bit) >= divisor)
            dividend -= divisor << bit;
    }
    return dividend;
}
