/* Project-authored EU ARM 0x002BF8C0..0x002BF924 (exclusive).
 * See docs/recovery/resource-path-copy.md. Ordinary mapped little-endian RAM. */
#include "resource_create.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");
typedef uint32_t aligned_word __attribute__((may_alias));

char *smt4_file_path_copy(char *destination, const char *source)
{
    volatile unsigned char *output = (volatile unsigned char *)destination;
    const volatile unsigned char *input = (const volatile unsigned char *)source;
    if ((((uintptr_t)output | (uintptr_t)input) & 3u) == 0) {
        for (;;) {
            uint32_t word = *(const volatile aligned_word *)input;
            input += 4;
            if ((word & 255u) != 0 && ((word >> 8) & 255u) != 0 &&
                ((word >> 16) & 255u) != 0 && (word >> 24) != 0) {
                *(volatile aligned_word *)output = word;
                output += 4;
            } else {
                for (;;) {
                    unsigned char byte = (unsigned char)word;
                    *output++ = byte;
                    if (byte == 0)
                        return destination;
                    word >>= 8;
                }
            }
        }
    }
    for (;;) {
        unsigned char byte = *input++;
        *output++ = byte;
        if (byte == 0)
            return destination;
    }
}
