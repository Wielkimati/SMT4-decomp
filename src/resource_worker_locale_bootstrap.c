/* EU base v0. Instruction evidence: recovery/resource-worker-locale-bootstrap.md. */
#include "resource_worker_locale_bootstrap.h"
#include "resource_worker_path.h"

static uint32_t read_word(const volatile uint8_t *p)
{
    uint32_t a = p[0], b = p[1], c = p[2], d = p[3];
    return a | b << 8 | c << 16 | d << 24;
}

uint32_t smt4_worker_locale_name_compare(const uint8_t *left, const uint8_t *right)
{
    if (((uintptr_t)left | (uintptr_t)right) & 3u) {
        for (;;) {
            uint32_t a = *left++, b = *right++;
            if (a == 0 || a != b)
                return a - b;
        }
    }
    for (;;) {
        uint32_t a = read_word(left), b = read_word(right);
        left += 4;
        right += 4;
        for (uint32_t shift = 0; shift < 32; shift += 8) {
            uint32_t x = (a >> shift) & 255u, y = (b >> shift) & 255u;
            if (x != y) {
                /* Original SUBS of shifted words, followed by RRX with its
                 * unsigned no-borrow carry. Equal lower bytes cancel. */
                uint32_t difference = (y - x) << 24;
                return (difference >> 1) | (y > x ? UINT32_C(0x80000000) : 0);
            }
            if (x == 0)
                return 0;
        }
    }
}

uint32_t smt4_worker_locale_select_bytes(uint32_t ignored, const uint8_t *name)
{
    (void)ignored;
    if (name != 0 && *name != 0 &&
        smt4_worker_locale_name_compare(smt4_worker_locale_byte_name, name) != 0)
        return 0;
    return (uint32_t)(uintptr_t)smt4_worker_locale_byte_table;
}

uint32_t smt4_worker_locale_select_other(uint32_t ignored, const uint8_t *name)
{
    (void)ignored;
    if (name != 0 && *name != 0 &&
        smt4_worker_locale_name_compare(smt4_worker_locale_other_name, name) != 0)
        return 0;
    return (uint32_t)(uintptr_t)smt4_worker_locale_other_table;
}

void smt4_worker_locale_bootstrap(void)
{
    uint32_t *context = (uint32_t *)smt4_worker_locale_context();
    context[1] = smt4_worker_locale_select_bytes(0, 0) + 1u;
    context[3] = smt4_worker_locale_select_other(0, 0);
}
