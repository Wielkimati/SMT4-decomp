/* Project-authored EU recovery. See docs/recovery/resource-worker-file-position.md.
 * Five words at object+4: tagged handle, cursor low/high, size cache low/high.
 * Word accesses retain the original four-byte field alignment. */
#include "resource_worker_file_methods.h"

static uint64_t pair(const uint32_t *words)
{
    return (uint64_t)words[0] | ((uint64_t)words[1] << 32);
}

static uint32_t refresh(uint32_t *handle, uint64_t *size)
{
    uint32_t result = smt4_worker_file_size_service(size, handle[0] & ~UINT32_C(1));
    if (result >> 31) {
        handle[3] = 0;
        handle[4] = 0;
    } else {
        handle[3] = (uint32_t)*size;
        handle[4] = (uint32_t)(*size >> 32);
    }
    return result;
}

uint32_t smt4_worker_file_size_lower(uint32_t *handle, uint64_t *size)
{
    uint64_t value;
    uint32_t result = refresh(handle, &value);
    if (!(result >> 31))
        *size = value;
    return result;
}

uint32_t smt4_worker_file_position(uint32_t *handle, uint32_t unused,
                                   uint64_t position)
{
    (void)unused; /* AAPCS gap in r1, not an input to the original helper. */
    if (position >> 63)
        return UINT32_C(0xE0E046C1);
    /* Original SUBS/SBCS + signed branches compare signed 64-bit values.
     * Biasing both representations avoids signed-overflow arithmetic in C. */
    const uint64_t sign = UINT64_C(1) << 63;
    if ((position ^ sign) >= (pair(handle + 3) ^ sign)) {
        uint64_t size;
        uint32_t result = refresh(handle, &size);
        if (result >> 31)
            return result;
        if ((size ^ sign) < (position ^ sign))
            return UINT32_C(0xE0E046C1);
    }
    handle[1] = (uint32_t)position;
    handle[2] = (uint32_t)(position >> 32);
    return 0;
}

uint32_t smt4_worker_file_seek_lower(uint32_t *handle, uint32_t origin_register,
                                     uint64_t offset, uint32_t origin)
{
    (void)origin_register;
    if (origin == 1) {
        offset += pair(handle + 1); /* Original modulo-2^64 ADDS/ADC. */
    } else if (origin == 2) {
        uint64_t size;
        uint32_t result = refresh(handle, &size);
        if (result >> 31)
            return result;
        offset += size;
    } else if (origin != 0) {
        return UINT32_C(0xE0E046BD);
    }
    return smt4_worker_file_position(handle, 0, offset);
}
