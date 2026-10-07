/* EU ARM 0x002B0494. See docs/recovery/resource-create.md for bounded evidence. */
#include "resource_create.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t *smt4_file_create(const char *path, uint32_t mode)
{
    uint32_t index, previous;
    uint32_t handle = smt4_file_sync_handle;
    uint32_t result = smt4_file_acquire(&index, &handle, 1, 0, UINT64_MAX);
    if (result >> 31)
        smt4_file_check_result(result, 1);

    uint32_t *descriptor = smt4_file_allocate(0x100, 0x100, 0, 0x144, 1);
    smt4_file_clear(descriptor, 0x144);
    uint32_t tail = smt4_file_list_head;
    if (!tail) {
        smt4_file_list_head = (uint32_t)(uintptr_t)descriptor;
    } else {
        uint32_t *node = (uint32_t *)(uintptr_t)tail;
        while (node[0x13c / 4])
            node = (uint32_t *)(uintptr_t)node[0x13c / 4];
        node[0x13c / 4] = (uint32_t)(uintptr_t)descriptor;
        descriptor[0x140 / 4] = (uint32_t)(uintptr_t)node;
    }

    int32_t length = smt4_file_path_length(path);
    if (length > 8)
        length = 8;
    int prefixed = 0;
    for (int32_t i = 0; i < length; ++i) {
        if (path[i] == ':') {
            prefixed = 1;
            break;
        }
    }
    char *stored_path = (char *)descriptor + 0x2c;
    if (prefixed)
        smt4_file_path_copy(stored_path, path);
    else
        smt4_resource_format(stored_path, smt4_file_path_format, path);

    descriptor[0] = 0;
    ((uint8_t *)descriptor)[0x20] = (uint8_t)mode;
    descriptor[3] = 0;
    descriptor[4] = 0;
    descriptor[5] = 0;
    descriptor[6] = 0;
    descriptor[10] = 0x80;
    descriptor[0x12c / 4] = 0;
    descriptor[1] = 1;
    descriptor[2] = 0;
    result = smt4_file_release(&previous, smt4_file_sync_handle);
    if (result >> 31)
        smt4_file_check_result(result, 1);
    return descriptor;
}
