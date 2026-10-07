/* EU ARM 0x0033C8A0. See docs/recovery/resource-bulk.md.
 * Index selection and synchronous orchestration are recovered in separate units;
 * actual worker/file I/O remains external.
 */
#include "resource_lifecycle.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* EU 0x0029706C: consumed contract is inclusive [lower, upper], 1 <= lower <= 33,
 * upper == 66. The original helper advances global PRNG state on every call.
 */
extern uint32_t smt4_resource_order_index(uint32_t lower, uint32_t upper);

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write32(uint8_t *p, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i)
        p[i] = (uint8_t)(value >> (8 * i));
}

uint32_t resource_load_bulk(void)
{
    uint8_t order[67];
    for (uint32_t i = 0; i < 67; ++i)
        order[i] = (uint8_t)i;
    for (uint32_t i = 0; i < 33; ++i) {
        uint32_t other = smt4_resource_order_index(i + 1, 66);
        uint8_t saved = order[i];
        order[i] = order[other];
        order[other] = saved;
    }
    for (uint32_t i = 0; i < 67; ++i) {
        uint8_t *entry = smt4_table_resource_registry + order[i] * 16;
        if (!read32(entry + 4) && entry[12]) {
            uint32_t address = smt4_resource_load(read32(entry), entry + 8, 0);
            write32(entry + 4, address);
        }
    }
    return 1;
}
