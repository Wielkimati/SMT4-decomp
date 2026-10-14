/* Project-authored EU base v0 recovery; see resource-pool-owner.md. */
#include "resource_pool_owner.h"
#include "resource_lazy_pool.h"
#include "resource_worker_backend.h"
#include "resource_clear.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t *smt4_resource_pool_object_construct(uint32_t *object)
{
    volatile uint32_t *w = object;
    w[1] = 0;
    w[2] = 0;
    for (unsigned i = 8; i <= 27; ++i)
        w[i] = 0;
    for (unsigned i = 47; i <= 51; ++i)
        w[i] = 0;
    w[55] = 0;
    w[58] = 0;
    w[59] = 0;
    w[60] = UINT32_MAX;
    w[62] = 0;
    w[46] = 0x00420b9c;
    for (unsigned i = 63; i <= 66; ++i)
        w[i] = 0;
    w[70] = 0;
    w[73] = 0;
    w[74] = 0;
    w[75] = UINT32_MAX;
    w[3] = 0;
    w[61] = 0x00420b9c;
    w[4] = 0;
    w[5] = 0;
    w[6] = 0;
    w[0] = 0x00420a3c;
    w[7] = 0;
    return object;
}

static void dispose(uint32_t *object, uint32_t offset)
{
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    ((void (*)(uint32_t *))(uintptr_t)vtable[offset / 4])(object);
}

static void close_handle(uint32_t handle)
{
    register uint32_t r0 __asm__("r0") = handle;
    __asm__ volatile ("svc 0x23" : "+r" (r0) : : "r1", "r2", "r3", "r12", "cc", "memory");
}

uint32_t smt4_resource_pool_owner_create(uint32_t **output,
    const uint32_t *descriptor, uint32_t a, uint32_t b,
    uint32_t c, uint32_t d, uint32_t e)
{
    uint32_t *object = smt4_resource_lazy_pool_take();
    if (object == 0)
        return 0xd8604659;
    smt4_resource_aligned_zero(object, 0x130);
    object = smt4_resource_pool_object_construct(object);
    if (object == 0)
        return 0xd8604659;
    /* The original constructor leaves r12 == -1. The caller preserves its
     * upper 24 bits while inserting the descriptor byte, so the request's
     * three padding bytes are deterministically FF on this concrete path. */
    uint32_t data1[4] = {descriptor[0], descriptor[1],
                        0xffffff00u | (descriptor[2] & 0xffu), a};
    uint32_t data2[5] = {0, descriptor[3], 0, 0, 0};
    uint32_t handle = 0;
    uint32_t service = *(volatile uint32_t *)(uintptr_t)0x0044e660;
    uint32_t result = smt4_resource_pool_owner_request(&service, &handle, 0,
        0x2345678a, 2, data1, 16, 2, data2, 20, 1, 0);
    if ((result & 0x80000000u) == 0) {
        uint32_t *file = smt4_worker_backend_pool_take((uint32_t *)(uintptr_t)0x004d4358);
        if (file == 0) {
            close_handle(handle);
            result = 0xd8604659;
        } else {
            file[0] = 0x00420998;
            file[1] = handle;
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
