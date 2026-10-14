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

/* 0x00356578: r2 is unchanged for a zero handle; otherwise it is the
 * kernel-returned scratch word. Clearing the handle must not overwrite it. */
__asm__(
    ".text\n"
    ".align 2\n"
    ".arm\n"
    ".global smt4_worker_file_teardown\n"
    ".type smt4_worker_file_teardown, %function\n"
    "smt4_worker_file_teardown:\n"
    "push {r4, lr}\n"
    "add r4, r0, #4\n"
    "ldr r0, [r0, #4]\n"
    "cmp r0, #0\n"
    "beq 1f\n"
    "svc 0x23\n"
    "mov r0, #0\n"
    "str r0, [r4]\n"
    "1: sub r0, r4, #4\n"
    "pop {r4, pc}\n"
    ".size smt4_worker_file_teardown, .-smt4_worker_file_teardown\n"
    ".ltorg\n"
);

/* 0x00356438: retain r2 across virtual-target lookup and node publication.
 * Nested locks preserve teardown/close output; an uncontended final release
 * produces one. The returned value reaches the owning object diagnostics. */
__asm__(
    ".text\n"
    ".align 2\n"
    ".arm\n"
    ".global smt4_worker_file_dispose\n"
    ".type smt4_worker_file_dispose, %function\n"
    "smt4_worker_file_dispose:\n"
    "push {r3, r4, r5, r6, r7, lr}\n"
    "mov r5, r0\n"
    "ldr r0, [r0, #4]\n"
    "cmp r0, #0\n"
    "beq 1f\n"
    "mov r0, r5\n"
    "bl smt4_worker_file_handle\n"
    "str r0, [sp]\n"
    "mov r0, sp\n"
    "bl smt4_worker_file_service_close\n"
    "1: ldr r0, [r5]\n"
    "ldr r1, [r0, #48]\n"
    "mov r0, r5\n"
    "blx r1\n"
    "ldr r6, =smt4_worker_file_pool\n"
    "add r4, r6, #48\n"
    "mov r0, r4\n"
    "bl smt4_worker_backend_acquire\n"
    "ldr r0, [r6, #36]\n"
    "str r0, [r5]\n"
    "str r5, [r6, #36]\n"
    "ldr r0, [r6, #44]\n"
    "sub r0, r0, #1\n"
    "str r0, [r6, #44]\n"
    "mov r0, r4\n"
    "pop {r3, r4, r5, r6, r7, lr}\n"
    "b smt4_worker_backend_release\n"
    ".size smt4_worker_file_dispose, .-smt4_worker_file_dispose\n"
    ".ltorg\n"
);
