/* Project-authored EU base v0 recovery; see resource-pool-object-teardown.md.
 * Entry r2 reaches diagnostics; returned r2 reaches the next embedded pool.
 * Ordinary C calls cannot express this additional scratch-register return.
 * Keep this bounded chain in ARM assembly, with calls to recovered source. */
#include "resource_pool_owner.h"
#include "resource_worker_backend.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

/* 0x002A458C: capture active before replacing the vtable. Neither diagnostic
 * setup overwrites r2. Reload the list after callbacks; each detached node
 * replaces r2, so the final node address is the helper's scratch return.
 * With no list, return entry r2 or the most recent diagnostic's returned r2. */
__asm__(
    ".text\n.align 2\n.arm\n"
    ".global smt4_resource_pool_base_teardown\n"
    ".type smt4_resource_pool_base_teardown, %function\n"
    "smt4_resource_pool_base_teardown:\n"
    "push {r4, lr}\n"
    "ldr r1, [r0, #12]\n"
    "mov r4, r0\n"
    "ldr r0, =0x00420bc0\n"
    "cmp r1, #0\n"
    "str r0, [r4]\n"
    "blne smt4_worker_prefix_diagnostic\n"
    "ldr r0, [r4, #16]\n"
    "cmp r0, #0\n"
    "blne smt4_worker_prefix_diagnostic\n"
    "ldr r1, [r4, #16]!\n"
    "cmp r1, #0\n"
    "movne r0, #0\n"
    "beq 2f\n"
    "1: mov r2, r1\n"
    "ldr r1, [r1, #4]\n"
    "str r0, [r2, #4]\n"
    "str r0, [r2]\n"
    "cmp r1, #0\n"
    "bne 1b\n"
    "str r0, [r4]\n"
    "2: sub r0, r4, #16\n"
    "pop {r4, pc}\n"
    ".size smt4_resource_pool_base_teardown, .-smt4_resource_pool_base_teardown\n"
    ".ltorg\n"
);

/* 0x00356844: reload five ownership slots after each virtual call. Virtual
 * targets use r1, leaving r2 untouched until a callee changes it. Clear each
 * free head, then carry the first base helper's r2 into the second (+F4,+B8).
 * File callback bodies have their own return-register dependencies. */
__asm__(
    ".text\n.align 2\n.arm\n"
    ".global smt4_resource_pool_object_teardown\n"
    ".type smt4_resource_pool_object_teardown, %function\n"
    "smt4_resource_pool_object_teardown:\n"
    "push {r4, r5, r6, lr}\n"
    "mov r4, r0\n"
    "ldr r0, =0x00420948\n"
    "mov r6, #0\n"
    "str r6, [r4, #8]\n"
    "mov r5, r6\n"
    "str r0, [r4]\n"
    "1: add r0, r4, r5, lsl #2\n"
    "ldr r0, [r0, #12]\n"
    "cmp r0, #0\n"
    "beq 2f\n"
    "ldr r1, [r0]\n"
    "ldr r1, [r1, #44]\n"
    "blx r1\n"
    "2: add r5, r5, #1\n"
    "cmp r5, #5\n"
    "blt 1b\n"
    "add r0, r4, #244\n"
    "ldr r4, =0x00420b00\n"
    "str r4, [r0]\n"
    "ldr r1, [r0, #36]\n"
    "cmp r1, #0\n"
    "strne r6, [r0, #36]\n"
    "bl smt4_resource_pool_base_teardown\n"
    "str r4, [r0, #-60]!\n"
    "ldr r1, [r0, #36]\n"
    "cmp r1, #0\n"
    "strne r6, [r0, #36]\n"
    "bl smt4_resource_pool_base_teardown\n"
    "sub r0, r0, #184\n"
    "pop {r4, r5, r6, pc}\n"
    ".size smt4_resource_pool_object_teardown, .-smt4_resource_pool_object_teardown\n"
    ".ltorg\n"
);

/* 0x003567F0: forward incoming r2 through virtual teardown. Only afterwards
 * capture the current global pool and return this object to it. */
__asm__(
    ".text\n.align 2\n.arm\n"
    ".global smt4_resource_pool_object_dispose\n"
    ".type smt4_resource_pool_object_dispose, %function\n"
    "smt4_resource_pool_object_dispose:\n"
    "push {r4, r5, r6, lr}\n"
    "mov r5, r0\n"
    "ldr r0, [r0]\n"
    "ldr r1, [r0, #52]\n"
    "mov r0, r5\n"
    "blx r1\n"
    "ldr r0, =smt4_worker_backend_state\n"
    "ldr r6, [r0, #4]\n"
    "add r4, r6, #48\n"
    "mov r0, r4\n"
    "bl smt4_worker_backend_acquire\n"
    "ldr r0, [r6, #36]\n"
    "str r0, [r5]\n"
    "str r5, [r6, #36]\n"
    "ldr r0, [r6, #44]\n"
    "sub r0, r0, #1\n"
    "str r0, [r6, #44]\n"
    "mov r0, r4\n"
    "pop {r4, r5, r6, lr}\n"
    "b smt4_worker_backend_release\n"
    ".size smt4_resource_pool_object_dispose, .-smt4_resource_pool_object_dispose\n"
    ".ltorg\n"
);
