/* Existing EU 0x002BCFAC recovery, shared by diagnostics and table reload.
 * Extracted without body changes from resource_worker_diagnostic.c.
 * Provenance and domains: docs/recovery/resource-worker-diagnostic.md and
 * docs/recovery/table-resource-copy.md.
 */
#include "resource_aligned_copy.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Original 32-bit address space");

void *smt4_diagnostic_copy(void *output, const volatile void *input, uint32_t bytes)
{
    volatile uint32_t *out = output;
    const volatile uint32_t *in = input;
    uint32_t batch[8];
    while (bytes >= 32) {
        for (unsigned i = 0; i < 8; ++i) batch[i] = in[i];
        for (unsigned i = 0; i < 8; ++i) out[i] = batch[i];
        in += 8; out += 8; bytes -= 32;
    }
    for (unsigned words = 4; words != 0; words >>= 1) {
        if (bytes & (words * 4)) {
            for (unsigned i = 0; i < words; ++i) batch[i] = in[i];
            for (unsigned i = 0; i < words; ++i) out[i] = batch[i];
            in += words; out += words;
        }
    }
    const volatile uint8_t *tail_in = (const volatile uint8_t *)in;
    volatile uint8_t *tail_out = (volatile uint8_t *)out;
    uint16_t half = 0;
    uint8_t byte = 0;
    if (bytes & 2) { half = *(const volatile uint16_t *)tail_in; tail_in += 2; }
    if (bytes & 1) byte = *tail_in;
    if (bytes & 2) { *(volatile uint16_t *)tail_out = half; tail_out += 2; }
    if (bytes & 1) *tail_out++ = byte;
    return (void *)tail_out;
}
