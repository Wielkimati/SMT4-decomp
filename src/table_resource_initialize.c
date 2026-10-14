/* EU ARM 0x003F05F0, two code intervals separated by literals/strings.
 * Project-authored instruction recovery. See docs/recovery/table-resource-initialize.md.
 * Path values bind private strings in the pinned EU image; no strings copied.
 */
#include <stdint.h>
#include "resource_lifecycle.h"
#include "table_resource_initialize.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static const struct { uint32_t path; uint8_t policy; } initial[67] = {
    { UINT32_C(0x003f0918), 1 }, /* 0 */
    { UINT32_C(0x003f0930), 1 }, /* 1 */
    { UINT32_C(0x003f0948), 1 }, /* 2 */
    { UINT32_C(0x003f0960), 1 }, /* 3 */
    { UINT32_C(0x003f097c), 1 }, /* 4 */
    { UINT32_C(0x003f0994), 1 }, /* 5 */
    { UINT32_C(0x003f09ac), 1 }, /* 6 */
    { UINT32_C(0x003f09c4), 1 }, /* 7 */
    { UINT32_C(0x003f09e0), 1 }, /* 8 */
    { UINT32_C(0x003f09f4), 1 }, /* 9 */
    { UINT32_C(0x003f0a0c), 1 }, /* 10 */
    { UINT32_C(0x003f0a28), 1 }, /* 11 */
    { UINT32_C(0x003f0a44), 1 }, /* 12 */
    { UINT32_C(0x003f0a58), 0 }, /* 13 */
    { UINT32_C(0x003f0a78), 0 }, /* 14 */
    { UINT32_C(0x003f0a94), 1 }, /* 15 */
    { UINT32_C(0x003f0aac), 1 }, /* 16 */
    { UINT32_C(0x003f0ac4), 1 }, /* 17 */
    { UINT32_C(0x003f0ae0), 1 }, /* 18 */
    { UINT32_C(0x003f0afc), 1 }, /* 19 */
    { UINT32_C(0x003f0b18), 0 }, /* 20 */
    { UINT32_C(0x003f0b34), 0 }, /* 21 */
    { UINT32_C(0x003f0b4c), 1 }, /* 22 */
    { UINT32_C(0x003f0b6c), 1 }, /* 23 */
    { UINT32_C(0x003f0b80), 1 }, /* 24 */
    { UINT32_C(0x003f0b94), 1 }, /* 25 */
    { UINT32_C(0x003f0ba8), 1 }, /* 26 */
    { UINT32_C(0x003f0bbc), 1 }, /* 27 */
    { UINT32_C(0x003f0bd8), 1 }, /* 28 */
    { UINT32_C(0x003f0bf8), 1 }, /* 29 */
    { UINT32_C(0x003f0c18), 1 }, /* 30 */
    { UINT32_C(0x003f0c34), 1 }, /* 31 */
    { UINT32_C(0x003f0c48), 1 }, /* 32 */
    { UINT32_C(0x003f0c60), 0 }, /* 33 */
    { UINT32_C(0x003f0c80), 0 }, /* 34 */
    { UINT32_C(0x003f0c9c), 1 }, /* 35 */
    { UINT32_C(0x003f0f50), 0 }, /* 36 */
    { UINT32_C(0x003f0f68), 0 }, /* 37 */
    { UINT32_C(0x003f0f88), 0 }, /* 38 */
    { UINT32_C(0x003f0fb0), 0 }, /* 39 */
    { UINT32_C(0x003f0fd8), 0 }, /* 40 */
    { UINT32_C(0x003f0ff8), 1 }, /* 41 */
    { UINT32_C(0x003f1014), 1 }, /* 42 */
    { UINT32_C(0x003f102c), 1 }, /* 43 */
    { UINT32_C(0x003f1048), 1 }, /* 44 */
    { UINT32_C(0x003f1064), 1 }, /* 45 */
    { UINT32_C(0x003f107c), 1 }, /* 46 */
    { UINT32_C(0x003f1098), 1 }, /* 47 */
    { UINT32_C(0x003f10b4), 1 }, /* 48 */
    { UINT32_C(0x003f10d0), 1 }, /* 49 */
    { UINT32_C(0x003f10ec), 1 }, /* 50 */
    { UINT32_C(0x003f110c), 0 }, /* 51 */
    { UINT32_C(0x003f1124), 0 }, /* 52 */
    { UINT32_C(0x003f1144), 0 }, /* 53 */
    { UINT32_C(0x003f1160), 0 }, /* 54 */
    { UINT32_C(0x003f1178), 0 }, /* 55 */
    { UINT32_C(0x003f1190), 0 }, /* 56 */
    { UINT32_C(0x003f11a8), 0 }, /* 57 */
    { UINT32_C(0x003f11c0), 0 }, /* 58 */
    { UINT32_C(0x003f11d8), 1 }, /* 59 */
    { UINT32_C(0x003f11fc), 0 }, /* 60 */
    { UINT32_C(0x003f1218), 0 }, /* 61 */
    { UINT32_C(0x003f1238), 1 }, /* 62 */
    { UINT32_C(0x003f1258), 1 }, /* 63 */
    { UINT32_C(0x003f1274), 1 }, /* 64 */
    { UINT32_C(0x003f1288), 1 }, /* 65 */
    { UINT32_C(0x003f129c), 1 }, /* 66 */
};

void smt4_table_resource_initialize(void)
{
    volatile uint32_t *ancillary = (volatile uint32_t *)UINT32_C(0x00446518);
    ancillary[0] = UINT32_MAX;
    ancillary[1] = UINT32_MAX;
    ancillary[2] = 0;
    ancillary[3] = 0;
    for (uint32_t i = 0; i < 67; ++i) {
        volatile uint32_t *words = (volatile uint32_t *)(smt4_table_resource_registry + i * 16);
        volatile uint8_t *bytes = smt4_table_resource_registry + i * 16;
        words[0] = initial[i].path;
        bytes[12] = initial[i].policy;
        words[1] = 0;
        words[2] = 0;
    }
}
