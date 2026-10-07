#ifndef SMT4_RESOURCE_ORDER_H
#define SMT4_RESOURCE_ORDER_H
#include <stdint.h>

/* Original state word at EU 0x004651C0; supplied by the original-address link. */
extern uint32_t smt4_resource_order_state;
/* EU 0x0029706C, validated consumed domain: lower=1..33, upper=66. */
uint32_t smt4_resource_order_index(uint32_t lower, uint32_t upper);
/* Consumed r1 result of EU 0x002C61B0, returned through C r0 here.
 * Validated domain: dividend=0..65535, divisor=34..66. No signed/zero ABI claim.
 */
uint32_t smt4_resource_order_remainder(uint32_t dividend, uint32_t divisor);
#endif
