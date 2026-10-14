/* Project-authored EU base v0 instruction recovery, ARM 0x002B0674.
 * See docs/recovery/resource-path-prefix.md. Ordinary stable mapped RAM. */
#include "resource_sync.h"
#include "resource_worker_service_acquire.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_path_has_prefix(uint32_t path)
{
    /* The original computes the complete length before inspecting any colon.
     * Reuse ARM 0x002C32E4, including its aligned-word read extent. */
    uint32_t length = smt4_worker_service_name_length((const char *)(uintptr_t)path);
    if (length == 0 || (length & UINT32_C(0x80000000)) != 0)
        return 0;
    if (length > 8)
        length = 8;
    const volatile unsigned char *bytes = (const volatile unsigned char *)(uintptr_t)path;
    for (uint32_t index = 0; index < length; ++index) {
        if (bytes[index] == ':')
            return 1;
    }
    return 0;
}
