/* EU base v0. Instruction-backed contracts: resource-worker-prefix.md. */
#include "resource_worker_prefix.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint64_t normalized_key(const uint8_t *name)
{
    uint8_t normalized[8];
    uint32_t i;
    for (i = 0; i < 8; ++i) {
        uint32_t byte = name[i];
        if (byte == 0 || byte == 0x3a) {
            normalized[i] = 0x3a;
            break;
        }
        normalized[i] = (uint8_t)byte;
    }
    const uint8_t *text = normalized;
    if (i == 8) {
        smt4_worker_prefix_diagnostic();
        text = smt4_worker_prefix_fallback;
    }
    uint32_t low = 0, high = 0;
    for (i = 0; i < 8; ++i) {
        uint32_t byte = text[i];
        if (byte == 0x3a)
            return ((uint64_t)high << 32) | low;
        uint32_t sign = 0u - (byte >> 7);
        high = (high << 8) | (low >> 24) | sign;
        low = (low << 8) | byte | (sign << 8);
    }
    return 0;
}

uint32_t smt4_worker_prefix_register(const uint8_t *name, uint32_t backend,
                                   uint32_t flag, uint32_t retain)
{
    uint64_t key = normalized_key(name);
    if (key == 0)
        return UINT32_C(0xe0e046bc);
    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t *record = smt4_worker_prefix_table[i];
        /* Vacancy wins even if this record or a later one has the same key. */
        if (record[2] == 0) {
            record[0] = (uint32_t)key;
            record[1] = (uint32_t)(key >> 32);
            record[2] = backend;
            ((uint8_t *)record)[12] = (uint8_t)flag;
            ((uint8_t *)record)[13] = (uint8_t)retain;
            return 0;
        }
        if (record[0] == (uint32_t)key && record[1] == (uint32_t)(key >> 32))
            return UINT32_C(0xc82044b4);
    }
    return UINT32_C(0xd8604659);
}

uint32_t smt4_worker_prefix_remove(const uint8_t *name)
{
    uint64_t key = normalized_key(name);
    /* Unlike registration and resolution, zero keys are searched. */
    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t *record = smt4_worker_prefix_table[i];
        if (record[0] != (uint32_t)key || record[1] != (uint32_t)(key >> 32))
            continue;
        uint32_t backend = record[2];
        uint32_t retain = ((uint8_t *)record)[13];
        record[2] = 0;
        record[0] = 0;
        record[1] = 0;
        if (backend == 0)
            return UINT32_C(0xc8804465);
        if (retain == 0) {
            const uint32_t *object = (const uint32_t *)(uintptr_t)backend;
            const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
            ((void (*)(uint32_t))(uintptr_t)vtable[0x30 / 4])(backend);
            if (smt4_worker_backend_state[2] == backend)
                smt4_worker_backend_state[2] = 0;
        }
        return 0;
    }
    return UINT32_C(0xc8804465);
}
