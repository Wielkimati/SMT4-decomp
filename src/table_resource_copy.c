/* Project-authored EU instruction recovery; docs/recovery/table-resource-copy.md.
 * Access grouping is intentional. PLD cache hints have no claimed observable
 * effect in this ordinary-memory contract; fault/timing/MMIO are excluded.
 */
#include "table_resource_copy.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");
typedef uint32_t word_alias __attribute__((__may_alias__));
#define BYTE(at) (*(volatile uint8_t *)(uintptr_t)(at))
#define WORD(at) (*(volatile word_alias *)(uintptr_t)(at))

/* Express the original unaligned word access without an unaligned C lvalue
 * or an implementation that silently substitutes four byte accesses. */
static inline uint32_t load_unaligned(uint32_t source)
{
    uint32_t value;
    __asm__ volatile ("ldr %0, [%1]" : "=r" (value) : "r" (source) : "memory");
    return value;
}

/* EU 0x002C6048..0x002C60D0. Unsigned sizes; no overlap/error policy added. */
void smt4_table_reload_copy(uint32_t d, uint32_t s, uint32_t n)
{
    if (n > 3) {
        uint32_t residue = d & 3;
        if (residue != 0) {
            uint8_t a = BYTE(s++), b = 0;
            if (residue <= 2) b = BYTE(s++);
            BYTE(d++) = a;
            if (residue < 2) a = BYTE(s++);
            if (residue <= 2) BYTE(d++) = b;
            n -= 4 - residue;
            if (residue < 2) BYTE(d++) = a;
        }
        if ((s & 3) == 0) {
            smt4_diagnostic_copy((void *)(uintptr_t)d, (const volatile void *)(uintptr_t)s, n);
            return;
        }
        while (n >= 8) {
            uint32_t a = load_unaligned(s), b = load_unaligned(s + 4);
            WORD(d) = a; WORD(d + 4) = b;
            s += 8; d += 8; n -= 8;
        }
        if (n & 4) {
            uint32_t a = load_unaligned(s); WORD(d) = a;
            s += 4; d += 4;
        }
    }
    uint8_t a = 0, b = 0, c = 0;
    if (n & 2) { a = BYTE(s++); b = BYTE(s++); }
    if (n & 1) c = BYTE(s);
    if (n & 2) { BYTE(d++) = a; BYTE(d++) = b; }
    if (n & 1) BYTE(d) = c;
}
