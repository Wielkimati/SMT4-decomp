# Consumed resource-order index and remainder

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Addresses are original virtual addresses in ARM mode. Names are project
annotations, not recovered original names. The C implementations were derived
from the local instructions; no external implementation was copied.

## Recovered contract

[`resource_order.c`](../../src/resource_order.c) reconstructs the consumed
behavior of `0x0029706C`. The original compares its endpoints as signed values,
swaps them if necessary, and computes an inclusive width. It reads the u32 at
`0x004651C0`, computes `state * 0x41C64E6D + 0x3039` modulo 2^32, and writes the
updated state **before** calling the division dependency. The dividend is the
updated state's full upper 16 bits, with no 15-bit mask. The index is the lower
endpoint plus the dependency's r1 result.

The supported comparison domain is precisely the bulk caller's domain:
lower endpoint 1..33, upper endpoint 66, arbitrary initial u32 state. Thus the
remainder inputs are dividend 0..65535 and divisor 34..66. State seeding, other
users of this state, reversed/negative endpoints, concurrent mutation and
overflowing or full-width intervals are outside this package. The source retains
the observed endpoint ordering; its reversed branch is not claimed validated.

[`resource_order_remainder.c`](../../src/resource_order_remainder.c) reconstructs
the consumed r1 remainder of `0x002C61B0` using unsigned shifted comparisons and
subtraction. Its C interface returns that remainder in **r0**, and the rebuilt
index caller uses that interface. This is deliberately not a binary-compatible
replacement for the original division entry. The original r0 quotient, signed
input paths and zero-divisor behavior remain outside this reconstruction.

The original entry starts with `ORRS`/`BMI` and handles negative inputs on a
separate path at `0x002C62F0`. It must not be labeled a general unsigned division
routine merely because the consumed inputs are positive. Its positive path
shares subtraction code with the previously recovered unsigned-quotient entry
at `0x002C6C64`. The new C remainder loop compares before shifting, so a successful
comparison guarantees the shifted divisor fits in u32. It contains no C division
operator or compiler-runtime dependency.

## Instruction evidence and comparisons

Ghidra's index listing agrees with independent GNU ARM disassembly in
`local/analysis/bulk-20261006/`. The new run exports the remainder disassembly,
Ghidra listing and exact visited instruction addresses. Original index
instructions occupy `[0x0029706C,0x002970BC)` with two following literals.
Executed remainder instructions stay inside `[0x002C61B0,0x002C62F0)`.
The signed branch and large-input normalization are intentionally not covered
by the consumed-domain corpus. Address coverage includes predicated instructions
and does not establish every conditional outcome or every input combination.
The run visits 17 index, 56 remainder and all 46 bulk-loader instruction
addresses. The three endpoint-swap instructions are outside the tested bounds;
the remainder's nonnegative dispatch reaches subtraction at bit 11 or below.

`tools/resource_order_cases.py` supplies independent Python integer expectations.
The Java harness checks those expectations again, then executes original and
rebuilt instructions in separate Ghidra PcodeEmulator states. Inverse-LCG seeds
force each remainder test dividend into the updated state's high half, using
both 0 and 65535 for the low half. This makes truncation, update order and state
write errors observable without relying solely on random seeds.

Direct comparisons check returned values, the exact state word and write count,
remainder arguments and call count, stack alignment/restoration, r4-r11,
initialized reads, allowed writes, execution ranges and instruction budgets.
The original r1 is compared to rebuilt r0 only for direct remainder calls.
The rebuilt paths execute no original instructions.

The integrated checker reuses the bulk-loader trace/registry oracle. It runs the
original and rebuilt index/remainder instructions, intercepting **only** the
synchronous file backend. Seventy seeds (six edge seeds and 64 deterministic
random seeds) each exercise six registry profiles, two size-output behaviors and
three null/nonnull return models. It checks every index/remainder call, all 33
state writes, ordered load calls, full registry contents and preserved registers.
Even all-loaded and all-zero-policy profiles must advance the state 33 times.
File I/O, allocation and backend side effects beyond the modeled size output
remain unrecovered.

## Reproduce

With the saved Ghidra GUI project closed, from `SMT4-decomp/`:

```powershell
python tools/check_resource_order.py --output local/validation/order-next
python tools/check_resource_bulk.py --output local/validation/bulk-regression-next
python -m unittest discover -s tests -v
```

The first command builds a separate 304-byte freestanding ARMv6 unit containing
bulk loader, index and remainder. It uses the existing pinned GCC/binutils,
Ghidra and JDK, read-only saved import, original-address data bindings for registry
and state, and one intercepted load backend. Generated material stays ignored
under `local/`. The earlier bulk checker retains arbitrary modeled index returns
and its 1,726-case schedule corpus; the two modes have different dependency
contracts and neither replaces the other's evidence.

Successful evidence: `local/validation/order-20261006/COMPLETE.json`.

| Check | Result |
| --- | --- |
| Direct remainder comparisons | 3,165 passed |
| Direct index/state comparisons | 6,330 passed |
| Integrated bulk comparisons | 2,520 passed |
| Modeled load calls per integrated path | 94,776 |
| Original instruction addresses visited across the chain | 119 |
| Maximum instructions per direct / bulk call | 214 / 8613 |
| ARM unit | 304 bytes |
| Public synthetic tests | 31 passed |

The earlier 1,726-case intercepted-index bulk corpus also passes unchanged:
`local/validation/order-20261006-bulk-regression/COMPLETE.json`. It uses the
hash-checked disposable `tbcr-20261006` import to avoid locking the primary
project while the integrated run executes.

Three local mutants are rejected: a 15-bit random mask, omitted state store,
and strict-greater subtraction that mishandles exact remainders. Records are
`local/validation/order-20261006-negative-{15-bit,state-store,exact-remainder}/NEGATIVE.json`;
driver: `local/validation/check-order-negatives.py`. Mutated source copies stay
local; no success marker is produced. Negative runs also use the disposable
hash-checked import. These checks are bounded evidence, not exhaustive inputs.

## Remaining work

Next bounded source task: isolate synchronous backend `0x002C5E90`, reached by
the load wrapper at `0x002C3344`, and identify its allocation/file dependencies.
The order-state initializer and other users are additional static leads; do not
assume this is the game's only random-number state. Compiler/ABI research and
the host address boundary remain open. Live verification stays deferred, with
G1/G2 unpassed. No emulator, save or profile is changed by these comparisons.
No full 3DS application, binary match, revision-pinned port import or PC runtime
is claimed.
