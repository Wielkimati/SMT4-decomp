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
/* EU 0x00146AD8: bounded block selection; older checkers retain their model. */
void *smt4_resource_heap_allocate_inner(uint32_t subobject, uint32_t size,
                                         uint32_t alignment);
/* EU 0x0014F608: selected-block splitting, lists, metadata and optional clearing.
 * Directly recovered; older arithmetic-only selection checks retain a model. */
void *smt4_resource_heap_commit_block(uint32_t lists, uint32_t block,
                                      uint32_t payload, uint32_t rounded_size,
                                      uint32_t reverse);
/* EU 0x0014699C: unlink allocation, insert/coalesce its physical extent.
 * Return preserves observed r0 (insertion predecessor), not a known status. */
uint32_t smt4_resource_heap_free_inner(uint32_t subobject, uint32_t payload);
/* EU 0x002B33D8: call inner free then decrement +0x54 modulo u32; return count. */
uint32_t smt4_resource_heap_free_counted(uint32_t heap, uint32_t payload);
/* EU 0x00144978: first-fit fixed pool, then 128-byte rounding and record split.
 * r2/r3 are unused; older checkers retain their fixed-allocation model. */
void *smt4_resource_fixed_allocate(uint32_t object, uint32_t size,
                                   uint32_t third, uint32_t fourth);
/* EU 0x002B260C: append raw header and update allocation accounting.
 * Older allocation checker modes retain their registration models. */
void smt4_resource_allocate_register(void *raw);
#include "resource_clear.h" /* EU 0x002C3B9C and consumed 0x002C4B88. */
#endif
