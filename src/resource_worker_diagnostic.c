/* EU base v0; original instruction evidence and bounded comparisons:
 * docs/recovery/resource-worker-diagnostic.md. No external code reused. */
#include "resource_worker_diagnostic.h"
#include "resource_worker_service_setup.h"
#include "resource_wait.h"
#include <stddef.h>
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Original 32-bit address space");
_Static_assert(sizeof(smt4_diagnostic_record) == 128, "Diagnostic wire size");
_Static_assert(offsetof(smt4_diagnostic_record, process) == 12, "Process word");

uint32_t smt4_diagnostic_process(volatile uint32_t *output, uint32_t handle)
{
    register uint32_t result __asm__("r0") = (uint32_t)(uintptr_t)output;
    register uint32_t value __asm__("r1") = handle;
    __asm__ volatile ("svc 0x35" : "+r" (result), "+r" (value) : :
                      "r2", "r3", "r12", "cc", "memory");
    *output = value;
    return result;
}

uint32_t smt4_diagnostic_request(volatile uint32_t *service,
    const volatile smt4_diagnostic_record *record)
{
    uintptr_t tls;
    __asm__ volatile ("mrc p15, 0, %0, c13, c0, 3" : "=r" (tls));
    volatile uint32_t *command = (volatile uint32_t *)(tls + 0x80u);
    command[0] = UINT32_C(0x00010800);
    smt4_diagnostic_copy((void *)&command[1], record, 128);
    register uint32_t result __asm__("r0") = *service;
    __asm__ volatile ("svc 0x32" : "+r" (result) : :
                      "r1", "r2", "r3", "r12", "cc", "memory");
    if (result >> 31) return result;
    return command[1];
}

/* Internal AAPCS adapters capture the lower calls' r0/r2 immediately. They
 * describe consumed registers, not newly recovered release/wait behavior. */
uint64_t smt4_diagnostic_release_words(uint32_t *lock);
uint64_t smt4_diagnostic_wait_words(uint32_t state[2]);
__asm__(
    ".pushsection .text.smt4_diagnostic_adapters,\"ax\",%progbits\n"
    ".align 2\n"
    ".global smt4_diagnostic_release_words\n"
    ".type smt4_diagnostic_release_words, %function\n"
    "smt4_diagnostic_release_words:\n"
    "push {r4, lr}\n"
    "bl smt4_worker_backend_release\n"
    "mov r1, r2\n"
    "pop {r4, pc}\n"
    ".size smt4_diagnostic_release_words, .-smt4_diagnostic_release_words\n"
    ".global smt4_diagnostic_wait_words\n"
    ".type smt4_diagnostic_wait_words, %function\n"
    "smt4_diagnostic_wait_words:\n"
    "push {r4, lr}\n"
    "bl smt4_diagnostic_wait\n"
    "mov r1, r2\n"
    "pop {r4, pc}\n"
    ".size smt4_diagnostic_wait_words, .-smt4_diagnostic_wait_words\n"
    ".global smt4_diagnostic_deliver\n"
    ".type smt4_diagnostic_deliver, %function\n"
    "smt4_diagnostic_deliver:\n"
    "push {r4, lr}\n"
    "bl smt4_diagnostic_deliver_words\n"
    "mov r2, r1\n"
    "pop {r4, pc}\n"
    ".size smt4_diagnostic_deliver, .-smt4_diagnostic_deliver\n"
    ".popsection\n");

/* ARM 0x002AD7E8: one extended contract, with an entry bridge above.
 * Types 2/5 return the reloaded type and final release r2; other returning
 * types return both words from wait. The C pair prevents epilogue clobbers. */
uint64_t smt4_diagnostic_deliver_words(volatile smt4_diagnostic_record *record)
{
    for (;;) {
        smt4_worker_backend_acquire(smt4_diagnostic_lock);
        uint32_t status = 0;
        if (smt4_diagnostic_handle == 0)
            status = smt4_service_connect_port(&smt4_diagnostic_handle,
                (const char *)(uintptr_t)smt4_diagnostic_constants[2]);
        if (!(status >> 31)) {
            smt4_diagnostic_process(&record->process, smt4_diagnostic_constants[0]);
            uint32_t handle = smt4_diagnostic_handle;
            smt4_diagnostic_request(&handle, record);
            register uint32_t closing __asm__("r0") = smt4_diagnostic_handle;
            if (closing != 0) {
                __asm__ volatile ("svc 0x23" : "+r" (closing) : :
                                  "r1", "r2", "r3", "r12", "cc", "memory");
                smt4_diagnostic_handle = smt4_diagnostic_constants[1];
            }
        } else if (status == UINT32_C(0xD0401834) && record->type == 2) {
            smt4_file_delay(INT64_C(5000000));
            smt4_worker_backend_release(smt4_diagnostic_lock);
            continue;
        }
        uint64_t released = smt4_diagnostic_release_words(smt4_diagnostic_lock);
        uint32_t type = record->type;
        if (type == 2 || type == 5)
            return (released & UINT64_C(0xFFFFFFFF00000000)) | type;
        uint32_t state[2] = {0, 0};
        smt4_diagnostic_wait_initialize(state, 1);
        return smt4_diagnostic_wait_words(state);
    }
}

uint32_t smt4_worker_diagnostic(uint32_t result, uint32_t site)
{
    smt4_diagnostic_global.flags = 0;
    smt4_diagnostic_global.magic = UINT16_C(0xBCA3);
    smt4_diagnostic_global.type = 0;
    smt4_diagnostic_global.site = site;
    smt4_diagnostic_global.result = result;
    return smt4_diagnostic_deliver(&smt4_diagnostic_global);
}
