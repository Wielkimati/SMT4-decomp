# Arbitration argument marshalling

2026-10-13 update: [wait consumed-return extension](resource-wait-return.md)
establishes wait/arbitration r0/r2 and replaces wait/initializer models in
create/chain `--recover-result-diagnostic`. Earlier evidence below retains its
historical boundaries; lower locks and kernel outcomes remain modeled.

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This adds the twenty-seventh bounded recovered contract. Names are project
descriptions, not recovered original symbols.

## Contract and boundary

ARM entry `0x002A88FC`, exclusive end `0x002A8914`, preserves caller r4/r5,
loads the two stack argument words into those registers, issues SVC `0x22`,
restores r4/r5, and returns through LR. Independent GNU disassembly and Ghidra
agree on all six instructions. The reconstructed interface in
`src/resource_arbitration.c` retains the existing declaration in
`src/resource_signal.h`:

| SVC register | Input word |
| --- | --- |
| r0 | Handle |
| r1 | Original 32-bit address |
| r2 | Operation, unchanged |
| r3 | Count bit pattern, unchanged |
| r4 | Low 32 bits of timeout, from entry SP |
| r5 | High 32 bits of timeout, from entry SP + 4 |

The wrapper does not validate, narrow, dereference, retry, or interpret these
arguments. It returns the SVC r0 word unchanged. Source uses fixed-register
operands and explicit inline `svc 0x22`, with memory/flags/r12 clobbers. The
returning boundary model may change r0-r5, r12 and flags; it preserves r6-r11,
SP and LR. This is a declared model for testing the wrapper, not a recovered
kernel contract. In particular, error meanings, time units, blocking, address
validity and kernel side effects are outside this recovery.

Pinned GCC builds **20 bytes**: it combines the original two `LDR` instructions
into one `LDRD`. This is behavioral reconstruction, not binary matching. The
stack is eight-byte aligned in the tested ABI, and the source remains confined
to original 32-bit ARM addresses. No external implementation was incorporated.

## Checks and reproduction

Close the saved Ghidra project and run these jobs sequentially from the repository:

```powershell
python tools/check_resource_arbitration.py --output local/validation/arbitration-next
python tools/check_resource_signal_lock.py --recover-arbitration --output local/validation/arbitration-signal-lock-next
python -m unittest discover -s tests -v
```

Successful records:
`local/validation/arbitration-20261006/COMPLETE.json` and
`local/validation/arbitration-signal-lock-20261006/COMPLETE.json`.
Drivers verify pinned tool/reference hashes, build with warnings as errors,
retain independent disassembly, verify the Ghidra mapped-image hash, and write
success last. Generated binaries/listings/traces remain ignored under `local/`.

| Check | Result |
| --- | ---: |
| Direct original/rebuilt/oracle comparisons | 1,920 |
| Direct SVC boundary visits, both paths | 3,840 |
| Original wrapper instruction addresses visited | 6 |
| Integrated signal/lock/wrapper comparisons | 7,556 |
| Integrated bounded pending prefixes | 36 |
| Integrated original instruction addresses visited | 126 |
| Integrated unit size | 496 bytes |
| Integrated SVC boundary visits, both paths | 37,182 |
| Integrated exclusive attempts, both paths | 114,178 |
| Integrated clear-exclusive operations, both paths | 33,088 |
| Public synthetic tests | 31 passed |

Direct cases include 512 combinations of timeout boundary words and results,
384 single-bit/complement probes across all six arguments, and 1,024 seeded
random cases. Caller registers and stack bytes vary; the harness checks SVC
number, every argument word, return value, callee-saved registers, stack restoration,
argument/guard preservation, initialized reads and bounded execution. Input
addresses include null, unaligned and high-bit values; no dereference occurs.

The integrated checker now supports `--recover-arbitration`. Both paths execute
the wrapper prologue/epilogue, with original or rebuilt signal/acquire/release
instructions. Scheduled competing writes and handle changes happen at SVC;
the independent signal/lock transition oracle remains authoritative. Timeout
registers are checked before the model poisons r4/r5, exercising restoration
in nested calls. Pending prefixes and all existing events must still agree.
The rebuilt path executes no original instructions. Omitting the flag retains
the earlier interception at the wrapper entry.

SVC instructions are counted as visited but intercepted before execution; the
five original wrapper instructions surrounding SVC execute in Ghidra. Exclusive
outcomes are scheduled, as in the earlier signal/lock report. Neither instruction
coverage nor these controlled schedules establish physical ARM concurrency.

Four local source mutants are rejected: loading the high timeout word into r4,
narrowing count to 16 bits, invoking SVC `0x21`, and discarding the returned
result. Driver: `local/validation/check-arbitration-negatives.py`; evidence:
`local/validation/arbitration-20261006-negative-*/NEGATIVE.json`. Each failure
is checked for its expected comparison diagnostic and has no success marker.

Regressions also pass: the default 7,556-case signal/lock checker and the
3,924-case synchronous chain retain their prior results and interception
boundaries. Records are
`local/validation/arbitration-20261006-signal-lock-regression/COMPLETE.json` and
`local/validation/arbitration-20261006-chain-regression/COMPLETE.json`.

## Limits and next work

Kernel arbitration, hardware exclusives, arbitrary concurrency, file I/O,
allocation, worker behavior, and live agreement remain open. No emulator,
save, profile, or original dump changed. G1/G2 remain open and live checks stay
deferred. The subsequent [chain/SVC integration](resource-chain-svc.md) now
executes this wrapper: 3,924 comparisons, 1,368 bytes and 341 original instruction
addresses pass. Next connect bulk/lifecycle callers to the recovered synchronous
chain with explicit lower boundaries.
