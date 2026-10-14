/* Project-authored EU instruction recovery. See recovery/resource-create-sync.md.
 * SVC outcomes, diagnostic delivery and break policy remain external boundaries. */
#include "resource_create.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* ARM 0x002C4350. The timeout words occupy SVC r0 and r4. */
uint32_t smt4_file_acquire(uint32_t *index, const uint32_t *handles,
                         uint32_t count, uint32_t wait_all, uint64_t timeout)
{
    register uint32_t r0 __asm__("r0") = (uint32_t)timeout;
    register const uint32_t *r1 __asm__("r1") = handles;
    register uint32_t r2 __asm__("r2") = count;
    register uint32_t r3 __asm__("r3") = wait_all;
    register uint32_t r4 __asm__("r4") = (uint32_t)(timeout >> 32);
    __asm__ volatile ("svc 0x25" : "+r" (r0), "+r" (r1), "+r" (r2),
                      "+r" (r3), "+r" (r4) : : "r12", "cc", "memory");
    *index = (uint32_t)(uintptr_t)r1;
    return r0;
}

/* ARM 0x002C54A4. Both wrappers publish r1 even on failure. */
uint32_t smt4_file_release(uint32_t *previous, uint32_t handle)
{
    register uint32_t r0 __asm__("r0") = (uint32_t)(uintptr_t)previous;
    register uint32_t r1 __asm__("r1") = handle;
    __asm__ volatile ("svc 0x16" : "+r" (r0), "+r" (r1)
                      : : "r2", "r3", "r12", "cc", "memory");
    *previous = r1;
    return r0;
}

extern volatile const uint8_t smt4_file_result_kernel_flag;
extern volatile const int8_t smt4_file_result_debug_flag;
uint32_t smt4_file_result_break(uint32_t unused0, uint32_t unused1, uint32_t payload);

/* ABI adapter, not another original routine: collect diagnostic r0 and r2 in
 * the standard 64-bit return pair. A real C call keeps SP eight-byte aligned;
 * an inline BL alone does not tell GCC that its leaf frame needs that alignment. */
uint64_t smt4_file_result_diagnostic_words(uint32_t result, uint32_t zero, uint32_t caller);
__asm__(
    ".pushsection .text.smt4_file_result_diagnostic_words,\"ax\",%progbits\n"
    ".align 2\n"
    ".global smt4_file_result_diagnostic_words\n"
    ".type smt4_file_result_diagnostic_words, %function\n"
    "smt4_file_result_diagnostic_words:\n"
    "push {r4, lr}\n"
    "bl smt4_file_result_diagnostic\n"
    "mov r1, r2\n"
    "pop {r4, pc}\n"
    ".size smt4_file_result_diagnostic_words, .-smt4_file_result_diagnostic_words\n"
    ".popsection\n");

/* ARM 0x002C54BC. The nominal second argument is overwritten by classification.
 * Diagnostic word three is this entry's caller LR, not its internal call site.
 * On the disabled class -1 branch the diagnostic's returned r2 reaches break. */
__attribute__((noinline))
uint32_t smt4_file_check_result(uint32_t result, uint32_t unused)
{
    (void)unused;
    uint32_t caller = (uint32_t)(uintptr_t)__builtin_return_address(0);
    uint32_t enabled = smt4_file_result_kernel_flag & 1u;
    enabled |= (uint32_t)(int32_t)smt4_file_result_debug_flag;
    int32_t classification = (int32_t)(result >> 27);
    if (result >> 31)
        classification -= 32;
    if (enabled && (classification == -7 || classification == 1))
        return result;
    uint32_t payload = enabled; /* Zero on the disabled non-diagnostic branch. */
    if (enabled || classification == -1) {
        uint64_t words = smt4_file_result_diagnostic_words(result, 0, caller);
        if (enabled)
            return (uint32_t)words;
        payload = (uint32_t)(words >> 32);
    }
    return smt4_file_result_break(0, 0, payload);
}
