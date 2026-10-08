/* EU base v0; original addresses and bounded contracts in the open report. */
#include "resource_worker_file_open.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_worker_utf16_length(const uint16_t *text)
{
    uint32_t length = 0;
    while (*text != 0) {
        ++length;
        ++text;
    }
    return length;
}

uint32_t smt4_worker_path_backend(const uint16_t *path)
{
    uint32_t low = 0, high = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        uint32_t unit = path[i];
        if (unit == 0x3a) {
            if ((low | high) == 0)
                return 0;
            for (uint32_t entry = 0; entry < 32; ++entry)
                if (smt4_worker_prefix_table[entry][0] == low &&
                    smt4_worker_prefix_table[entry][1] == high)
                    return smt4_worker_prefix_table[entry][2];
            return 0;
        }
        uint32_t byte = unit & 0xffu;
        uint32_t sign = 0u - (byte >> 7);
        high = (high << 8) | (low >> 24) | sign;
        low = (low << 8) | byte | (sign << 8);
    }
    return 0;
}

uint32_t smt4_worker_file_open(uint32_t *handle, const uint16_t *path, uint32_t mode)
{
    uint32_t backend = smt4_worker_path_backend(path);
    if (backend == 0)
        return UINT32_C(0xc8804465);
    while (*path++ != 0x3a) {}
    /* Original descriptor order is type, pointer, byte length including NUL. */
    uint32_t descriptor[3] = {4, (uint32_t)(uintptr_t)path,
                             (smt4_worker_utf16_length(path) + 1u) * 2u};
    const uint32_t *object = (const uint32_t *)(uintptr_t)backend;
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    uint32_t opened;
    uint32_t result = ((uint32_t (*)(uint32_t, uint32_t *, const uint32_t *, uint32_t))
                       (uintptr_t)vtable[0])(backend, &opened, descriptor, mode);
    if (!(result >> 31))
        *handle = opened;
    return result;
}
