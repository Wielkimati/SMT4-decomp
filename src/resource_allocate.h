#ifndef SMT4_RESOURCE_ALLOCATE_H
#define SMT4_RESOURCE_ALLOCATE_H
#include "resource_create.h"
#include "resource_release.h"

/* EU 0x002C5544: special routing and aligned allocation metadata. */
void *smt4_resource_allocate_lower(uint32_t first, uint32_t second,
                                  uint32_t third, uint32_t size, uint32_t fifth);
/* EU 0x002B26F0 and 0x002B260C: lower heap routing/accounting are modeled. */
void *smt4_resource_allocate_raw(uint32_t first, uint32_t second,
                                uint32_t third, uint32_t size, uint32_t fifth);
void smt4_resource_allocate_register(void *raw);
/* EU 0x002C3B9C: zero byte count bytes; result is not consumed. */
void smt4_resource_allocate_zero(void *address, uint32_t count);
#endif
