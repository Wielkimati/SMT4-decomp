/* Instruction-derived EU 0x0029706C. See docs/recovery/resource-order.md. */
#include "resource_order.h"

uint32_t smt4_resource_order_index(uint32_t lower, uint32_t upper)
{
    if ((int32_t)lower > (int32_t)upper) {
        uint32_t saved = lower;
        lower = upper;
        upper = saved;
    }
    uint32_t width = upper - lower + 1;
    uint32_t state = smt4_resource_order_state * UINT32_C(0x41c64e6d) + UINT32_C(0x3039);
    smt4_resource_order_state = state;
    return lower + smt4_resource_order_remainder(state >> 16, width);
}
