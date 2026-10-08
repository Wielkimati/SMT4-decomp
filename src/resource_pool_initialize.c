/* EU base v0 instruction recovery. See docs/recovery/resource-pool-initialize.md.
 * Project-authored; descriptive names are not original symbols. */
#include "resource_pool_initialize.h"
#include "unsigned_quotient.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

void smt4_resource_pool_initialize(uint32_t *pool, uint32_t element_bytes,
    uint32_t storage, uint32_t storage_bytes, uint32_t alignment, uint32_t options)
{
    volatile uint32_t *words = pool;
    words[0x14 / 4] = options;
    uint32_t stride = smt4_unsigned_quotient(element_bytes + alignment - 1u,
                                           alignment) * alignment;
    words[0x18 / 4] = stride;
    uint32_t start = smt4_unsigned_quotient(storage + alignment - 1u,
                                          alignment) * alignment;
    words[0x1c / 4] = start;
    uint32_t bytes = smt4_unsigned_quotient(storage + storage_bytes - start,
                                          stride) * stride;
    words[0x20 / 4] = bytes;
    uint32_t node = bytes + start - stride;
    uint32_t head = 0;
    words[0x2c / 4] = 0;
    words[0x28 / 4] = alignment;
    if (start <= node) {
        do {
            *(volatile uint32_t *)(uintptr_t)node = head;
            uint32_t next_stride = words[0x18 / 4];
            uint32_t next_start = words[0x1c / 4];
            head = node;
            node -= next_stride;
            if (next_start > node)
                break;
        } while (1);
    }
    words[0x24 / 4] = head;
}

void smt4_resource_base_lock_initialize(uint32_t *lock)
{
    uint32_t observed, failed;
    do {
        __asm__ volatile ("ldrex %0, [%1]" : "=&r" (observed) : "r" (lock) : "memory");
        __asm__ volatile ("strex %0, %2, [%1]" : "=&r" (failed)
                          : "r" (lock), "r" (1u) : "memory");
    } while (failed != 0);
}

void smt4_resource_recursive_lock_initialize(uint32_t *lock)
{
    volatile uint32_t *words = lock;
    smt4_resource_base_lock_initialize(lock);
    words[1] = 0;
    words[2] = 0;
}
