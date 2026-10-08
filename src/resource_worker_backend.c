/* EU base v0; instruction-backed ownership contracts in resource-worker-backend.md. */
#include "resource_worker_backend.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t *smt4_worker_backend_pool_take(uint32_t *pool)
{
    smt4_worker_backend_acquire(pool + 0x30 / 4);
    uint32_t *object = (uint32_t *)(uintptr_t)pool[0x24 / 4];
    if (object != 0) {
        pool[0x24 / 4] = object[0];
        pool[0x2c / 4] += 1u;
        if (pool[0x14 / 4] & 1u)
            smt4_worker_backend_clear(object,
                (uint32_t)(uintptr_t)object + pool[0x18 / 4], 0);
    }
    smt4_worker_backend_release(pool + 0x30 / 4);
    return object;
}

uint32_t smt4_worker_backend_create(uint32_t **output, uint32_t archive)
{
    uint32_t data[2];
    data[0] = (uint32_t)(uintptr_t)data;
    data[1] = 1;
    uint32_t service = smt4_worker_backend_state[4];
    uint64_t handle;
    uint32_t result = smt4_worker_backend_archive_open(&service, &handle,
                                                     archive, 1, data, 1);
    if (result >> 31)
        return result; /* Caller output is untouched on service failure. */
    service = smt4_worker_backend_state[4];
    uint32_t *object = smt4_worker_backend_pool_take(smt4_worker_backend_pool);
    if (object != 0) {
        object[0] = (uint32_t)(uintptr_t)smt4_worker_backend_vtable;
        object[2] = (uint32_t)handle;
        object[3] = (uint32_t)(handle >> 32);
        object[1] = service; /* Captured before taking the pool lock. */
    }
    *output = object;
    if (object == 0) {
        service = smt4_worker_backend_state[4];
        smt4_worker_backend_archive_close(&service, handle);
        return UINT32_C(0xd8604659);
    }
    return 0;
}

uint32_t smt4_worker_backend_service(uint32_t *object)
{
    if (object[1] == 0)
        smt4_worker_backend_diagnostic(UINT32_C(0xe0a046da), 0x0023a020);
    return object[1];
}

uint32_t *smt4_worker_backend_teardown(uint32_t *object)
{
    object[0] = (uint32_t)(uintptr_t)smt4_worker_backend_vtable;
    uint64_t handle = ((uint64_t)object[3] << 32) | object[2];
    if (handle != 0) {
        uint32_t service = smt4_worker_backend_service(object);
        smt4_worker_backend_archive_close(&service, handle);
        object[2] = 0;
        object[3] = 0;
    }
    object[1] = 0;
    return object;
}

void smt4_worker_backend_dispose(uint32_t *object)
{
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    ((void (*)(uint32_t *))(uintptr_t)vtable[0x34 / 4])(object);
    uint32_t *pool = smt4_worker_backend_pool;
    smt4_worker_backend_acquire(pool + 0x30 / 4);
    object[0] = pool[0x24 / 4];
    pool[0x24 / 4] = (uint32_t)(uintptr_t)object;
    pool[0x2c / 4] -= 1u;
    smt4_worker_backend_release(pool + 0x30 / 4);
}

uint32_t smt4_worker_backend_register(const uint8_t *name)
{
    if (smt4_worker_backend_state[2] != 0)
        return UINT32_C(0xc92044e7);
    uint32_t *object;
    uint32_t result = smt4_worker_backend_create(&object, 4);
    if (!(result >> 31)) {
        result = smt4_worker_prefix_register(name, (uint32_t)(uintptr_t)object, 0, 0);
        if (!(result >> 31))
            smt4_worker_backend_state[2] = (uint32_t)(uintptr_t)object;
        else {
            const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
            ((void (*)(uint32_t *))(uintptr_t)vtable[0x30 / 4])(object);
        }
    }
    return result;
}
