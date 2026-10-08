/* EU ARM 0x002C244C; see docs/recovery/resource-worker-object-allocate.md. */
#include "resource_allocate.h"
#include "resource_worker_io.h"

uint32_t *smt4_worker_object_allocate(uint32_t bytes)
{
    /* The original's diagnostic arguments end in a NOP, with no call. */
    return smt4_resource_allocate_lower(0x100, 0x100, 0, bytes, 1);
}
