#ifndef SMT4_RESOURCE_ALLOCATE_H
#define SMT4_RESOURCE_ALLOCATE_H
#include "resource_create.h"
#include "resource_release.h"

/* EU 0x002C5544: special routing and aligned allocation metadata. */
void *smt4_resource_allocate_lower(uint32_t first, uint32_t second,
                                  uint32_t third, uint32_t size, uint32_t fifth);
/* EU 0x002B26F0: raw heap routing; older checkers retain their models. */
void *smt4_resource_allocate_raw(uint32_t first, uint32_t second,
                                uint32_t third, uint32_t size, uint32_t fifth);
/* EU 0x00465170: separate routing state, +4 holds the heap object address. */
extern volatile uint32_t smt4_resource_raw_state[2];
/* EU 0x002C3A98: six-word wrapper, directly recovered. Older checkers model it. */
void *smt4_resource_heap_allocate(uint32_t heap, uint32_t size, uint32_t alignment,
                                  uint32_t fourth, uint32_t fifth, uint32_t sixth);
/* Directly recovered setters; existing wrapper/retained checkers still model them.
 * EU 0x00146CE0: replace u16 at +0x34, return old zero-extended u16.
 * EU 0x00146CF0: replace bit 0 of u16 at +0x36, return old bit 0.
 * EU 0x00146D10: replace byte at +0x38, return old sign-extended byte as u32.
 * Names retain wrapper argument positions; option meanings remain unknown. */
uint32_t smt4_resource_heap_configure_fourth(uint32_t subobject, uint32_t value);
uint32_t smt4_resource_heap_configure_fifth(uint32_t subobject, uint32_t value);
uint32_t smt4_resource_heap_configure_sixth(uint32_t subobject, uint32_t value);
/* EU 0x00146AD8 remains an explicit allocator model. */
void *smt4_resource_heap_allocate_inner(uint32_t subobject, uint32_t size,
                                         uint32_t alignment);
/* EU 0x00144978 remains modeled. Preserve r2/r3 without claiming consumption. */
void *smt4_resource_fixed_allocate(uint32_t object, uint32_t size,
                                   uint32_t third, uint32_t fourth);
/* EU 0x002B260C: append raw header and update allocation accounting.
 * Older allocation checker modes retain their registration models. */
void smt4_resource_allocate_register(void *raw);
/* EU 0x002C3B9C: zero byte count bytes; result is not consumed. */
void smt4_resource_allocate_zero(void *address, uint32_t count);
#endif
