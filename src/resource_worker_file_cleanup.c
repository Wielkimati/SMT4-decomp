/* EU reference identity and bounded evidence: resource-worker-file-cleanup.md.
 * Project-authored reconstruction; original 32-bit object/vtable addresses. */
#include "resource_worker_file_cleanup.h"
#include "resource_worker_io.h"
#include "resource_lifecycle.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_worker_file_close(uint32_t backend)
{
    if (backend != 0) {
        const uint32_t *object = (const uint32_t *)(uintptr_t)backend;
        const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
        ((void (*)(uint32_t))(uintptr_t)vtable[0x2c / 4])(backend);
    }
}

uint32_t *smt4_worker_file_cleanup_shared(uint32_t *object)
{
    if (object[1] & ~UINT32_C(1)) {
        if (object[1] & 1)
            smt4_worker_file_preclose(object[1]);
        smt4_worker_file_close(object[1] & ~UINT32_C(1));
        object[1] = 0;
    }
    return object;
}

uint32_t *smt4_worker_file_cleanup(uint32_t *object)
{
    return smt4_worker_file_cleanup_shared(object);
}

void smt4_worker_object_release(uint32_t *object)
{
    if (object != 0)
        smt4_resource_release((uint32_t)(uintptr_t)object);
}

void smt4_worker_file_destroy(uint32_t *object)
{
    smt4_worker_object_release(smt4_worker_file_cleanup_shared(object));
}
