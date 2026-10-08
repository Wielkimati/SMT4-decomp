/* Project-authored EU recovery of 0x002BB864, [0x002BB864,0x002BB8EC).
 * See docs/recovery/resource-worker-file-read.md. */
#include "resource_worker_file_methods.h"

uint32_t smt4_worker_file_read_lower(uint32_t *handle, uint32_t *count,
                                     uint32_t buffer, uint32_t bytes)
{
    uint32_t total = 0;
    while (bytes != 0) {
        uint32_t received;
        uint64_t cursor = (uint64_t)handle[1] | ((uint64_t)handle[2] << 32);
        uint32_t result = smt4_worker_file_read_service(&received,
            handle[0] & ~UINT32_C(1), cursor, buffer, bytes);
        if (result >> 31)
            return result; /* Keep prior progress, but do not publish count. */
        total += received;
        uint32_t low = handle[1];
        handle[1] = low + received;
        /* ADDS / ADC ..., received ASR #31: signed 32-bit increment. */
        handle[2] += (0u - (received >> 31)) + (handle[1] < low);
        if (received == bytes || received == 0)
            break;
        buffer += received;
        bytes -= received;
    }
    *count = total;
    return 0;
}
