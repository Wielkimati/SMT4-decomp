/* EU base v0 instruction recovery; resource-global-startup.md.
 * Project-authored names and source, not original symbols. */
#include "resource_global_startup.h"
#include "resource_pool_initialize.h"
#include "resource_worker_prefix.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static void construct_pool(uint32_t address, uint32_t element,
                           uint32_t storage, uint32_t bytes)
{
    volatile uint32_t *pool = (uint32_t *)(uintptr_t)address;
    pool[0x04 / 4] = 0;
    pool[0x08 / 4] = 0;
    pool[0x0c / 4] = 0;
    pool[0x10 / 4] = 0;
    pool[0x14 / 4] = 0;
    pool[0x24 / 4] = 0;
    pool[0x30 / 4] = 0;
    pool[0x34 / 4] = 0;
    pool[0x38 / 4] = UINT32_MAX;
    pool[0] = UINT32_C(0x00420b9c);
    smt4_resource_pool_initialize((uint32_t *)(uintptr_t)address,
                                  element, storage, bytes, 4, 0);
    smt4_resource_recursive_lock_initialize(
        (uint32_t *)(uintptr_t)(address + 0x30));
}

uint32_t smt4_resource_global_startup(void)
{
    smt4_worker_prefix_initialize();
    *(volatile uint32_t *)(uintptr_t)UINT32_C(0x0044e660) = 0;
    *(volatile uint32_t *)(uintptr_t)UINT32_C(0x004d43d0) = 0;
    smt4_resource_recursive_lock_initialize(
        (uint32_t *)(uintptr_t)UINT32_C(0x004d43d0));
    construct_pool(UINT32_C(0x004d431c), 16, UINT32_C(0x004306c0), 256);
    construct_pool(UINT32_C(0x004d4358), 8, UINT32_C(0x004307c0), 256);
    construct_pool(UINT32_C(0x004d4394), 8, UINT32_C(0x004308c0), 128);
    /* The three intervening sites are NOPs. Tail 0x00225E68 is BX LR:
     * no destructor-registration side effect, and r0 remains the last pool. */
    return UINT32_C(0x004d4394);
}
