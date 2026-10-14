/* Project-authored EU base v0 recovery; see resource-pool-alternate.md. */
#include "resource_pool_owner.h"
#include "resource_lazy_pool.h"
#include "resource_worker_backend.h"
#include "resource_clear.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_pool_wrap_handle(uint32_t *object,
    uint32_t **output, uint32_t handle)
{
    (void)object; /* The original method does not dereference its receiver. */
    uint32_t *file = smt4_worker_backend_pool_take(
        (uint32_t *)(uintptr_t)0x004d4358);
    if (file == 0) {
        register uint32_t r0 __asm__("r0") = handle;
        __asm__ volatile ("svc 0x23" : "+r" (r0) : :
                          "r1", "r2", "r3", "r12", "cc", "memory");
        return 0xd8604659;
    }
    volatile uint32_t *w = file;
    w[0] = 0x00420998;
    w[1] = handle;
    *output = file;
    return 0;
}

static void dispose(uint32_t *object, uint32_t offset)
{
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    ((void (*)(uint32_t *))(uintptr_t)vtable[offset / 4])(object);
}

uint32_t smt4_resource_pool_alternate_create(uint32_t **output,
    uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e,
    const uint32_t *descriptor)
{
    uint32_t *object = smt4_resource_lazy_pool_take();
    if (object == 0)
        return 0xd8604659;
    smt4_resource_aligned_zero(object, 0x130);
    object = smt4_resource_pool_object_construct(object);
    if (object == 0)
        return 0xd8604659;
    /* Original sp+0x30 contains its own address; the request exposes one byte
     * of that word. Preserve the self-reference, not the adjacent literal 1.
     * Actual stack addresses are relocated in the rebuilt comparison. */
    uint32_t data = (uint32_t)(uintptr_t)&data;
    uint32_t handle = 0;
    uint32_t service = *(volatile uint32_t *)(uintptr_t)0x0044e660;
    uint32_t result = smt4_resource_pool_owner_request(&service, &handle,
        0, 3, 1, &data, 1, 2, descriptor, 12, 1, 0);
    if ((result & 0x80000000u) == 0) {
        uint32_t *file = 0;
        const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
        result = ((uint32_t (*)(uint32_t *, uint32_t **, uint32_t))
            (uintptr_t)vtable[0x3c / 4])(object, &file, handle);
        if ((result & 0x80000000u) == 0) {
            result = smt4_resource_pool_owner_initialize(object, file, a, b, c, d, e);
            if ((result & 0x80000000u) != 0)
                dispose(file, 0x2c);
            else
                result = 0;
        }
    }
    if ((result & 0x80000000u) != 0) {
        dispose(object, 0x30);
        return result;
    }
    *output = object;
    return 0;
}
