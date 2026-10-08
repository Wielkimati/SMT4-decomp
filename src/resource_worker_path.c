/* EU base v0. Instruction-backed contracts: recovery/resource-worker-path.md. */
#include "resource_worker_path.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_path_is_initial(const uint32_t state[2])
{
    return state == 0 || state[0] == 0;
}

uint32_t *smt4_worker_path_state_slot(uint32_t ignored, uint32_t slot)
{
    (void)ignored;
    return (uint32_t *)((uintptr_t)smt4_worker_path_states + slot * 8u);
}

uint32_t *smt4_worker_path_error(void)
{
    return &smt4_worker_path_error_storage;
}

uint8_t *smt4_worker_locale_context(void)
{
    return smt4_worker_locale_storage;
}

uint32_t *smt4_worker_locale_slot(void)
{
    return (uint32_t *)(smt4_worker_locale_context() + 4);
}

uint32_t smt4_worker_path_decode_byte(uint16_t *out, uint32_t byte, uint32_t state[2])
{
    const uint8_t *locale = (const uint8_t *)(uintptr_t)*smt4_worker_locale_slot();
    if (locale[0x101] == 1) {
        /* The original word load is at packed offset 0x103. Preserve its
         * little-endian value without imposing C alignment on the table. */
        uint32_t relative = (uint32_t)locale[0x103] |
            (uint32_t)locale[0x104] << 8 | (uint32_t)locale[0x105] << 16 |
            (uint32_t)locale[0x106] << 24;
        uintptr_t target = (uintptr_t)locale + 0x103u + relative;
        return ((uint32_t (*)(uint16_t *, uint32_t, uint32_t *))target)(out, byte, state);
    }
    if (locale[byte] == 0)
        return UINT32_MAX;
    *out = (uint16_t)byte;
    return 1;
}

uint32_t smt4_worker_path_convert(uint16_t *out, const char *path,
                                  uint32_t limit, uint32_t state[2])
{
    const uint8_t *input = (const uint8_t *)path;
    uint8_t zero = 0;
    uint32_t consumed = 0;
    if (input == 0) {
        input = &zero;
        limit = 1;
        out = 0;
    }
    if (state == 0)
        state = smt4_worker_path_state_slot(0, 5);
    while (limit != 0) {
        uint16_t unit;
        --limit;
        uint32_t result = smt4_worker_path_decode_byte(&unit, *input++, state);
        ++consumed;
        if (result == UINT32_MAX) {
            *smt4_worker_path_error() = 4;
            return UINT32_MAX;
        }
        if (result == UINT32_MAX - 1u)
            continue;
        if (out != 0)
            *out = unit;
        return unit == 0 ? 0 : consumed;
    }
    return UINT32_MAX - 1u;
}

uint32_t smt4_worker_path_measure(const char *path, uint32_t limit, uint32_t state[2])
{
    if (state == 0)
        state = smt4_worker_path_state_slot(0, 4);
    return smt4_worker_path_convert(0, path, limit, state);
}
