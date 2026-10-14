/* EU base v0; project-authored recovery. See recovery/startup-dispatch.md. */
#include "startup_dispatch.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* Linker-bound table boundaries, not words containing pointers. */
extern const uint32_t smt4_startup_relative_begin[];
extern const uint32_t smt4_startup_relative_end[];
extern const uint32_t smt4_startup_absolute_begin[];
extern const uint32_t smt4_startup_absolute_end[];
typedef void (*startup_callback)(void);

void smt4_startup_dispatch_relative_range(uint32_t cursor, uint32_t end)
{
    while (cursor != end) {
        uint32_t offset = *(const volatile uint32_t *)(uintptr_t)cursor;
        startup_callback callback = (startup_callback)(uintptr_t)(cursor + offset);
        callback();
        cursor += 4u;
    }
}

void smt4_startup_dispatch_absolute_range(uint32_t cursor, uint32_t end)
{
    while (cursor < end) {
        startup_callback callback = (startup_callback)(uintptr_t)
            *(const volatile uint32_t *)(uintptr_t)cursor;
        callback();
        cursor += 4u;
    }
}

void smt4_startup_dispatch_relative(void)
{
    smt4_startup_dispatch_relative_range((uint32_t)(uintptr_t)smt4_startup_relative_begin,
                                       (uint32_t)(uintptr_t)smt4_startup_relative_end);
}

void smt4_startup_dispatch_absolute(void)
{
    smt4_startup_dispatch_absolute_range((uint32_t)(uintptr_t)smt4_startup_absolute_begin,
                                       (uint32_t)(uintptr_t)smt4_startup_absolute_end);
}
