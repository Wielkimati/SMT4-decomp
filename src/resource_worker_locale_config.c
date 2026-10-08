/* EU base v0; instruction-backed contracts, not an identified library source. */
#include "resource_worker_locale_config.h"
#include "resource_worker_locale_bootstrap.h"
#include "resource_worker_path.h"

uint8_t *smt4_worker_locale_query(uint8_t *output, uint32_t mask)
{
    if ((mask & (mask - 1u)) != 0) {
        uint8_t *cursor = output;
        *cursor++ = '*';
        const volatile uint32_t *context = (const volatile uint32_t *)smt4_worker_locale_context();
        for (uint32_t i = 0; i < 5; ++i) {
            uint32_t value = context[i];
            for (uint32_t digit = 0; digit < 8; ++digit) {
                uint32_t nibble = value >> 28;
                *cursor++ = (uint8_t)(nibble + (nibble < 10 ? 0x30u : 0x57u));
                value <<= 4;
            }
        }
        *cursor = 0;
        return output;
    }
    uint32_t value;
    if (mask == 1)
        value = ((const volatile uint32_t *)smt4_worker_locale_context())[0];
    else if (mask == 2)
        value = ((const volatile uint32_t *)smt4_worker_locale_context())[1];
    else if (mask == 4)
        value = ((const volatile uint32_t *)smt4_worker_locale_context())[2];
    else if (mask == 8)
        value = ((const volatile uint32_t *)smt4_worker_locale_context())[3];
    else if (mask == 16)
        value = ((const volatile uint32_t *)smt4_worker_locale_context())[4];
    else
        return 0;
    if (value == 0)
        return (uint8_t *)smt4_worker_locale_default_name;
    uint32_t base = value & ~UINT32_C(3);
    uint32_t relative = *(const uint32_t *)(uintptr_t)(base - 4u);
    return (uint8_t *)(uintptr_t)(base + relative);
}

uint8_t *smt4_worker_locale_set_name(uint8_t *output, uint32_t mask,
                                   const uint8_t *name)
{
    uint32_t value;
    const uint32_t fixed = (uint32_t)(uintptr_t)smt4_worker_locale_fixed_table;
    if (mask & 2u) {
        value = smt4_worker_locale_select_bytes(fixed, name);
        if (value == 0) return 0;
        ((volatile uint32_t *)smt4_worker_locale_context())[1] = value + 1u;
    }
    if (mask & 1u) {
        if (fixed == 0) return 0;
        ((volatile uint32_t *)smt4_worker_locale_context())[0] = fixed;
    }
    if (mask & 4u) {
        if (fixed == 0) return 0;
        ((volatile uint32_t *)smt4_worker_locale_context())[2] = fixed;
    }
    if (mask & 8u) {
        value = smt4_worker_locale_select_other(fixed, name);
        if (value == 0) return 0;
        ((volatile uint32_t *)smt4_worker_locale_context())[3] = value;
    }
    if (mask & 16u) {
        if (fixed == 0) return 0;
        ((volatile uint32_t *)smt4_worker_locale_context())[4] = fixed;
    }
    return smt4_worker_locale_query(output, mask);
}

uint8_t *smt4_worker_locale_configure(uint8_t *output, uint32_t mask,
                                    const uint8_t *name)
{
    if (mask == 0 || mask >= 32u)
        return 0;
    if (name != 0) {
        if (*name != '*')
            return smt4_worker_locale_set_name(output, mask, name);
        const volatile uint8_t *cursor = name + 1;
        for (uint32_t i = 0; i < 5; ++i) {
            uint32_t value = 0;
            for (uint32_t digit = 0; digit < 8; ++digit) {
                uint32_t byte = *cursor++;
                value = (value << 4) | (byte - (byte < 0x3au ? 0x30u : 0x57u));
            }
            if (mask & (1u << i))
                ((volatile uint32_t *)smt4_worker_locale_context())[i] = value;
        }
    }
    return smt4_worker_locale_query(output, mask);
}
