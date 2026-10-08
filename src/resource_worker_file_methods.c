/* Project-authored recovery from the pinned EU ARM image. See
 * docs/recovery/resource-worker-file-methods.md; lower services remain external. */
#include "resource_worker_file_methods.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint64_t smt4_worker_file_size(uint32_t *object)
{
    uint64_t size;
    uint32_t result = smt4_worker_file_size_lower(object + 1, &size);
    if (result >> 31)
        smt4_worker_file_diagnostic(result, 0x003DFC70);
    return size;
}

void smt4_worker_file_seek(uint32_t *object, uint64_t offset, uint32_t origin)
{
    uint32_t result = smt4_worker_file_seek_lower(object + 1, origin, offset, origin);
    if (result >> 31)
        smt4_worker_file_diagnostic(result, 0x00354F8C);
}

uint32_t smt4_worker_file_read(uint32_t *object, uint32_t *count,
                               uint32_t buffer, uint32_t bytes)
{
    return smt4_worker_file_read_lower(object + 1, count, buffer, bytes);
}
