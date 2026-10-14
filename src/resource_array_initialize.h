#ifndef SMT4_RESOURCE_ARRAY_INITIALIZE_H
#define SMT4_RESOURCE_ARRAY_INITIALIZE_H
#include <stdint.h>

/* EU Thumb 0x002C5FAC..0x002C5FCE. Constructor return values are ignored.
 * Addresses advance with 32-bit wrapping. Null constructor skips all elements;
 * a nonnull constructor is called count times, including when stride is zero.
 * Callback bodies must obey the original callee-saved register convention. */
typedef uint32_t (*smt4_array_constructor)(uint32_t address);
uint32_t smt4_array_initialize(uint32_t base, smt4_array_constructor constructor,
                               uint32_t stride, uint32_t count);
#endif
