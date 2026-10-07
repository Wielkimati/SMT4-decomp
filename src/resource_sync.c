/* Reconstructed from EU instructions, not decompiler output.
 * Contract and intercepted dependencies: docs/recovery/resource-sync.md.
 */
#include "resource_sync.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* EU 0x002C5E90. The original treats path as a format in the direct branch. */
uint32_t smt4_resource_load_sync(uint32_t path, uint8_t *size, uint32_t flags,
                                uint32_t parameter)
{
    char formatted[256];
    smt4_resource_clear(formatted, 256);
    if (smt4_resource_path_mode || smt4_resource_path_has_prefix(path))
        smt4_resource_format(formatted, (const char *)(uintptr_t)path);
    else
        smt4_resource_format(formatted, smt4_resource_path_format,
                             (const char *)(uintptr_t)path);

    uint32_t *descriptor = smt4_file_create(formatted, 0);
    smt4_file_set_flags(descriptor, (flags & 1u) | ((flags & 2u) << 3));
    smt4_file_set_parameter(descriptor, parameter);
    smt4_file_wait(descriptor);
    if (smt4_file_failed(descriptor)) {
        if (size)
            *(uint32_t *)size = 0;
        smt4_file_mark_cleanup(descriptor);
        return 0;
    }
    uint32_t length = size ? descriptor[6] : 0;
    uint32_t data = descriptor[3];
    if (size)
        *(uint32_t *)size = length;
    descriptor[3] = 0;
    smt4_file_mark_cleanup(descriptor);
    return data;
}

/* EU 0x002C3344 sets the fourth argument to 4 then tail-calls the backend. */
uint32_t smt4_resource_load(uint32_t path, uint8_t *size, uint32_t flags)
{
    return smt4_resource_load_sync(path, size, flags, 4);
}
