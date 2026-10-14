/* Project-authored EU ARM recovery. See docs/recovery/table-resource-reload.md.
 * Ordinary original-address storage; no concurrency/MMIO or native service claim.
 */
#include "table_resource_reload.h"
#include "resource_lifecycle.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* EU 0x0025B9D8: STRB truncates without boolean normalization. */
void smt4_table_reload_state_set(uint32_t value)
{
    *(volatile uint8_t *)UINT32_C(0x00465040) = (uint8_t)value;
}
/* EU 0x0025B9E8: LDRSB, including negative nonzero states. */
int32_t smt4_table_reload_state_get(void)
{
    uint32_t value = *(volatile uint8_t *)UINT32_C(0x00465040);
    return value < 128 ? (int32_t)value : (int32_t)value - 256;
}
/* EU 0x002C5890: no original bounds check. */
uint32_t smt4_table_reload_gate(uint32_t index)
{
    uint32_t address = UINT32_C(0x00446da0) + index * 4u;
    return *(volatile uint32_t *)(uintptr_t)address;
}
/* EU 0x0025C848..0x0025C8F4, void: incidental r0 is not an output. */
void smt4_table_resource_reload(uint32_t id)
{
    if (smt4_table_reload_gate(2) != 0 || id >= 67)
        return;
    volatile uint32_t *entry = (volatile uint32_t *)(smt4_table_resource_registry + id * 16);
    if (entry[1] == 0)
        return;
    int was_enabled = smt4_table_reload_state_get() != 0;
    smt4_table_reload_state_set(1);
    uint32_t size;
    uint32_t replacement = smt4_resource_load(entry[0], (uint8_t *)&size, 0);
    if (entry[2] == size) {
        smt4_table_reload_copy(entry[1], replacement, size);
        smt4_resource_release(replacement);
    } else {
        smt4_resource_release(entry[1]);
        entry[1] = replacement;
        entry[2] = size;
    }
    if (!was_enabled)
        smt4_table_reload_state_set(0);
}
