/* Project-authored EU ARM 0x001284A8 recovery; no external code reused.
 * See docs/recovery/resource-result-diagnostic.md. Delivery has an explicit r0/r2 entry contract; ordinary C return
 * declarations alone do not describe the consumed r2. */
#include "resource_worker_diagnostic.h"
#include <stddef.h>
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Original 32-bit addresses");
_Static_assert(sizeof(smt4_diagnostic_record) == 128, "Diagnostic record size");
_Static_assert(offsetof(smt4_diagnostic_record, flags) == 1, "Flags byte");
_Static_assert(offsetof(smt4_diagnostic_record, magic) == 2, "Magic halfword");
_Static_assert(offsetof(smt4_diagnostic_record, result) == 4, "Result word");
_Static_assert(offsetof(smt4_diagnostic_record, site) == 8, "Site word");

/* C body of the entry below, not another original routine. Volatile stores
 * preserve the producer's order, which differs from worker entry 0x002BBD70. */
volatile smt4_diagnostic_record *smt4_result_diagnostic_record(
    uint32_t result, uint32_t type, uint32_t site)
{
    smt4_diagnostic_global.flags = 0;
    smt4_diagnostic_global.type = (uint8_t)type;
    smt4_diagnostic_global.magic = UINT16_C(0xBCA3);
    smt4_diagnostic_global.site = site;
    smt4_diagnostic_global.result = result;
    return &smt4_diagnostic_global;
}

/* Original entry ABI: r0=result, r1=type, r2=site; delivery's returned r0 AND
 * r2 pass through. Restore the entry LR/SP before the tail branch so neither
 * a C epilogue nor an implicit caller-scratch assumption loses returned r2.
 * This bridge and the C body together implement ONE original contract. */
__asm__(
    ".pushsection .text.smt4_file_result_diagnostic,\"ax\",%progbits\n"
    ".align 2\n"
    ".global smt4_file_result_diagnostic\n"
    ".type smt4_file_result_diagnostic, %function\n"
    "smt4_file_result_diagnostic:\n"
    "push {r4, lr}\n"
    "bl smt4_result_diagnostic_record\n"
    "pop {r4, lr}\n"
    "b smt4_diagnostic_deliver\n"
    ".size smt4_file_result_diagnostic, .-smt4_file_result_diagnostic\n"
    ".popsection\n");
