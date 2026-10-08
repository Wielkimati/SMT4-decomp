/* Project-authored EU base v0 recovery; see resource-lazy-pool.md. */
#include "resource_lazy_pool.h"
#include "resource_pool_initialize.h"
#include "resource_worker_backend.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_static_guard(uint32_t *guard)
{
    volatile uint32_t *word = guard;
    if (*word != 0)
        return 0;
    *word = 1;
    return 1;
}

uint32_t *smt4_resource_lazy_pool_take(void)
{
    uint32_t *outer = (uint32_t *)(uintptr_t)0x004d43d0;
    uint32_t *pool = (uint32_t *)(uintptr_t)0x004d42e0;
    volatile uint32_t *words = pool;
    volatile uint32_t *state = (uint32_t *)(uintptr_t)0x0044e650;
    smt4_worker_backend_acquire(outer);
    if ((state[3] & 1u) == 0 &&
        smt4_resource_static_guard((uint32_t *)(state + 3)) != 0) {
        words[1] = 0;
        words[2] = 0;
        words[3] = 0;
        words[4] = 0;
        words[5] = 0;
        words[9] = 0;
        words[12] = 0;
        words[0] = 0x00420b9c;
        words[14] = UINT32_MAX;
        words[13] = 0;
        smt4_resource_pool_initialize(pool, 0x130, 0x00430940, 0x1300, 4, 0);
        smt4_resource_recursive_lock_initialize(pool + 12);
        /* Original registration/finalization sites are MOV r0,r0 NOPs. */
        __asm__ volatile ("mov r0, r0\n\tmov r0, r0" ::: "memory");
    }
    state[1] = (uint32_t)(uintptr_t)pool;
    uint32_t *result = smt4_worker_backend_pool_take(pool);
    smt4_worker_backend_release(outer);
    return result;
}
