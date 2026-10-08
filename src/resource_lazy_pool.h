#ifndef SMT4_RESOURCE_LAZY_POOL_H
#define SMT4_RESOURCE_LAZY_POOL_H
#include <stdint.h>
/* EU 0x002C0128 (Thumb): plain word guard, not an atomic runtime guard. */
uint32_t smt4_resource_static_guard(uint32_t *guard);
/* EU 0x00146284: lazy static 16-element pool, serialized by outer lock. */
uint32_t *smt4_resource_lazy_pool_take(void);
#endif
