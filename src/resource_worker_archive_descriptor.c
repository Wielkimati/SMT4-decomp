/* EU descriptor construction, archive creation and prefix registration.
 * See resource-worker-archive-descriptor.md for original extents and limits. */
#include "resource_worker_backend.h"
#include <stddef.h>
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");
_Static_assert(sizeof(smt4_archive_descriptor) == 12, "Original descriptor layout");
_Static_assert(offsetof(smt4_archive_descriptor, low) == 4 &&
               offsetof(smt4_archive_descriptor, high) == 8, "Descriptor words");

smt4_archive_descriptor *smt4_worker_archive_descriptor_make(
    smt4_archive_descriptor *output, uint32_t selector, uint32_t low,
    uint32_t high)
{
    output->reserved = 0;
    output->selector = (uint8_t)selector;
    output->zero = 0;
    output->low = low;
    output->high = high;
    return output;
}

uint32_t smt4_worker_backend_create_descriptor(uint32_t **output,
                                              const uint32_t *descriptor)
{
    uint32_t service = smt4_worker_backend_state[4];
    uint64_t handle;
    uint32_t result = smt4_worker_backend_archive_open(&service, &handle,
                                                     7, 2, descriptor, 12);
    if (result >> 31)
        return result;
    service = smt4_worker_backend_state[4];
    uint32_t *object = smt4_worker_backend_pool_take(smt4_worker_backend_pool);
    if (object != 0) {
        object[0] = (uint32_t)(uintptr_t)smt4_worker_backend_vtable;
        object[2] = (uint32_t)handle;
        object[3] = (uint32_t)(handle >> 32);
        object[1] = service;
    }
    *output = object;
    if (object == 0) {
        service = smt4_worker_backend_state[4];
        smt4_worker_backend_archive_close(&service, handle);
        return UINT32_C(0xd8604659);
    }
    return 0;
}

uint32_t smt4_worker_backend_register_descriptor(const uint8_t *name,
                                                uint32_t identifier)
{
    smt4_archive_descriptor descriptor;
    smt4_worker_archive_descriptor_make(&descriptor, 0, identifier, 0);
    uint32_t *object;
    uint32_t result = smt4_worker_backend_create_descriptor(&object,
        (const uint32_t *)&descriptor);
    if (!(result >> 31)) {
        result = smt4_worker_prefix_register(name, (uint32_t)(uintptr_t)object,
                                            0, 0);
        if (result >> 31) {
            const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
            ((void (*)(uint32_t *))(uintptr_t)vtable[0x30 / 4])(object);
        }
    }
    return result;
}
