/* EU base v0; project-authored reconstruction. See resource-worker-file-owner.md. */
#include "resource_worker_file_owner.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* Original SVC 0x23 sites; the kernel's behavior remains external. */
static inline void close_handle(uint32_t handle)
{
    register uint32_t r0 __asm__("r0") = handle;
    __asm__ volatile ("svc 0x23" : "+r" (r0) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
}

uint32_t smt4_worker_backend_file_open(uint32_t *backend, uint32_t **output,
    const uint32_t descriptor[3], uint32_t flags)
{
    if (descriptor[2] > 512u)
        return UINT32_C(0xe0e046bf);
    uint32_t handle = 0;
    uint32_t service = smt4_worker_backend_service(backend);
    uint64_t archive = ((uint64_t)backend[3] << 32) | backend[2];
    uint32_t result = smt4_worker_file_service_open(&service, &handle, 0,
        archive, descriptor[0], descriptor[1], descriptor[2], flags, 0);
    if (result >> 31)
        return result;
    uint32_t *object = smt4_worker_backend_pool_take(smt4_worker_file_pool);
    if (object != 0) {
        object[1] = handle;
        object[0] = (uint32_t)(uintptr_t)smt4_worker_file_vtable;
    }
    *output = object;
    if (object == 0) {
        close_handle(handle);
        return UINT32_C(0xd8604659);
    }
    return 0;
}

uint32_t smt4_worker_file_handle(uint32_t *object)
{
    if (object[1] == 0)
        smt4_worker_backend_diagnostic(UINT32_C(0xe0a046da), 0x00239cec);
    return object[1];
}

uint32_t *smt4_worker_file_teardown(uint32_t *object)
{
    if (object[1] != 0) {
        close_handle(object[1]);
        object[1] = 0;
    }
    return object;
}

void smt4_worker_file_dispose(uint32_t *object)
{
    if (object[1] != 0) {
        uint32_t handle = smt4_worker_file_handle(object);
        smt4_worker_file_service_close(&handle);
    }
    const uint32_t *vtable = (const uint32_t *)(uintptr_t)object[0];
    ((void (*)(uint32_t *))(uintptr_t)vtable[0x30 / 4])(object);
    uint32_t *pool = smt4_worker_file_pool;
    smt4_worker_backend_acquire(pool + 0x30 / 4);
    object[0] = pool[0x24 / 4];
    pool[0x24 / 4] = (uint32_t)(uintptr_t)object;
    pool[0x2c / 4] -= 1u;
    smt4_worker_backend_release(pool + 0x30 / 4);
}
