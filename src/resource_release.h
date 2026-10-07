#ifndef SMT4_RESOURCE_RELEASE_H
#define SMT4_RESOURCE_RELEASE_H
#include "resource_lifecycle.h"

/* EU 0x00465120; opaque allocator state, original 32-bit words. */
extern uint32_t smt4_resource_allocator_state[15];
/* Synchronization, heap selection and raw free remain external boundaries. */
void smt4_resource_heap_acquire(uint32_t handle);
void smt4_resource_heap_release(uint32_t handle);
uint32_t smt4_resource_release_convert(uint32_t address);
/* EU 0x002B3340; modeled by the conversion checker. */
uint32_t smt4_resource_heap_index(uint32_t raw);
void smt4_resource_heap_free(uint32_t address);
#endif
