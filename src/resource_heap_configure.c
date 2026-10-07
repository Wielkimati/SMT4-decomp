#include "resource_allocate.h"

/* Original-address arithmetic and accesses, not a native host object layout. */
uint32_t smt4_resource_heap_configure_fourth(uint32_t subobject, uint32_t value)
{
    volatile uint16_t *field = (volatile uint16_t *)(uintptr_t)(subobject + 0x34u);
    uint32_t previous = *field;
    *field = (uint16_t)value;
    return previous;
}

uint32_t smt4_resource_heap_configure_fifth(uint32_t subobject, uint32_t value)
{
    volatile uint16_t *field = (volatile uint16_t *)(uintptr_t)(subobject + 0x36u);
    uint32_t previous = *field;
    *field = (uint16_t)((previous & 0xfffeu) | (value & 1u));
    return previous & 1u;
}

uint32_t smt4_resource_heap_configure_sixth(uint32_t subobject, uint32_t value)
{
    volatile uint8_t *field = (volatile uint8_t *)(uintptr_t)(subobject + 0x38u);
    uint32_t previous = *field;
    *field = (uint8_t)value;
    return (previous & 0x80u) != 0 ? previous | 0xffffff00u : previous;
}
