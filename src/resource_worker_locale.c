/* EU base v0. Instruction-backed contracts: recovery/resource-worker-locale.md. */
#include "resource_worker_locale.h"

static int32_t signed_half(uint32_t value)
{
    return (int32_t)(value & 0x7fffu) - (int32_t)(value & 0x8000u);
}

uint32_t smt4_worker_locale_map(int32_t index)
{
    if (index >= 0x2f0) {
        if (index < 0x582)
            return 0xffff;
        index = signed_half((uint32_t)index - 0x292u);
    }
    if ((uint32_t)index >= 7150u)
        return 0xffff;
    return smt4_worker_locale_mapping[index];
}

uint32_t smt4_worker_locale_decode(uint16_t *out, uint32_t byte,
                                  uint32_t state[2])
{
    uint32_t lead = state[0];
    if (lead != 0) {
        if (byte - 0x40u >= 0x3fu && byte - 0x80u >= 0x7du)
            return UINT32_MAX;
        uint32_t row = lead - (lead < 0xe0u ? 0x81u : 0xc1u);
        uint32_t column = byte - (byte < 0x80u ? 0x40u : 0x41u);
        uint32_t unit = smt4_worker_locale_map(signed_half(row * 188u + column));
        if (unit == 0xffff)
            return UINT32_MAX;
        *out = (uint16_t)unit;
        state[0] = 0;
        return 1;
    }
    if (byte - 0x81u <= 0x1eu || byte - 0xe0u <= 0x0fu) {
        state[0] = byte;
        return UINT32_MAX - 1u;
    }
    if (byte >= 0xf0u || byte == 0x80u || byte == 0xa0u)
        return UINT32_MAX;
    if (byte == 0x5cu)
        byte = 0xa5;
    else if (byte == 0x7eu)
        byte = 0x203e;
    else if (byte - 0xa1u <= 0x3eu)
        byte += 0xfec0u;
    *out = (uint16_t)byte;
    return 1;
}
