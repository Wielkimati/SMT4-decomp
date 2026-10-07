# EU TBCR consumers: static recovery targets

2026-10-06, A07 started. Expanded-code SHA-256:
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All addresses here are original virtual addresses in ARM mode. Names are project
descriptions, not original symbols. The instruction analysis below now supports
seven recovered entry-point contracts and ARM unit comparisons; see
[the recovery report](recovery/nkm-sort-index.md) for results and limits.

## Concrete file-to-code chain

The callback entry at `0x0042A480` resolves, by the startup dispatcher's
modulo-32-bit relative-address rule, to initializer `0x003F05F0`. This function
was missing from the initial automatic function inventory. It contains executable
blocks separated by literal pools and resource strings; treating the whole range
as contiguous ARM instructions would decode data as code.

At `0x003F0618`, it loads registry base `0x0049382C` from literal `0x003F0914`.
At `0x003F062C`, `ADD r3,pc,#0x2FC` resolves to `0x003F0930`, the beginning of
`battle/NKMSortIndex.tbb`. At `0x003F0634`, it stores that pointer at registry
offset `0x10`. It initializes that entry's `+4` and `+8` words to zero and `+0xC`
byte to one. This establishes **resource slot 1** in a 16-byte-entry registry.
The byte's complete role and the loader's lifecycle remain unverified.

The accessor at `0x002C0F18` takes a resource ID in `r0` and section index in `r1`.
For unsigned ID `< 67`, it reads the loaded-container pointer at
`0x0049382C + id*16 + 4`. Otherwise it uses null. It tail-calls `0x002AC358`,
preserving the section-index register. Ghidra's initial prototype misses that
second argument, so use the instruction listing rather than its inferred signature.

## Isolated helpers

| Address | Static behavior | Boundary / dependency |
| --- | --- | --- |
| `0x002AC358` | Select a `TBL1` section from `TBCR`: check null, magic, unsigned index against count, then add container base field and selected relative offset; check resulting pointer and section magic | No file size, overflow, or extent checks; only caller-owned readable memory is supported |
| `0x002C0EF0` | Return `section+16` for nonnull `TBL1`, otherwise null | Ignores header word at `+0x0C`; no payload-size check |
| `0x002C0EA0` | Return zero for null, wrong magic, or zero field `+8`; otherwise tail-call `0x002C6C64` with `r0=word(+4)`, `r1=word(+8)` | Nonzero-divisor quotient confirmed in 818 instruction-level cases; full division ABI still unclaimed; initial decompiler drops its second argument |
| `0x002C0F18` | Resolve loaded registry pointer, then select section | Registry readiness and lifetime are preconditions, not evidence of automatic loading |

All four table helpers now have recovered source and pass 1,154 direct
instruction-level comparisons. The selector also has explicit modulo-32-bit
address/index-shift cases. See [helper recovery](recovery/tbcr-access.md).

Both Ghidra and xPack GNU objdump decode the checks and address arithmetic
consistently. `0x002C6C64` begins an unsigned shift/subtract division sequence;
the count interpretation also agrees with the corpus. The consumed r0 quotient
now passes 818 edge/random comparisons for nonzero divisors. Other ABI outputs
and division entry with zero divisor remain unverified.

## First selected consumer: `0x002883E8`

This 15-instruction routine is a small, directly identified NKMSortIndex consumer:

1. Preserve the original `r0` argument as an unsigned index.
2. Request resource 1, section 2 through `0x002C0F18`.
3. Obtain the payload and count through the helpers above.
4. If unsigned `index < count`, read the **first little-endian u16** at
   `payload + index*4`. Otherwise read the first u16 at the payload start.
5. Return the zero-extended halfword in `r0`.

Instruction evidence: `CMP r0,r4` at `0x00288410`, `ADDHI` at `0x00288414`,
`LDRHHI` at `0x00288418`, and `LDRHLS` at `0x0028841C`. The stride is four bytes,
but the load width is two. It **falls back to entry 0** for out-of-range indices;
there is no synthetic zero/error return for those inputs. Missing or empty
resources still lead to a read through the returned payload pointer, so they are
not established supported inputs for a safe reconstruction.

On the pinned file, section 2 has 1,201 entries. Its u32 values happen to be a
permutation of 1..1,201, but the consumer only reads their low halfwords. A
recovered implementation must preserve that width even when a synthetic entry's
high halfword is nonzero. Naming the return value as a demon ID remains a
hypothesis until callers and game behavior are investigated.

Completed A07 package: `src/nkm_sort_index.c` reconstructs this routine with
explicit original-helper dependencies. Its ARM build agrees in 1,770 cases,
including these indices, all 1,201 reference entries, and synthetic records.
The controlled registry/helper chain executes original instructions without
helper stubs; the loader is not recovered. G2 still awaits G1 and live consumer
agreement. See [the report](recovery/nkm-sort-index.md) and [build strategy](build-strategy.md).

## Second consumer: `0x001A0EA4`

This routine requests resource 1, section 3, walks four-byte entries, compares
their first u16 to the full input argument, and reads the second u16 for the
first match. It returns 50 when no match exists or the matched second halfword
is zero; otherwise it returns that second halfword. Thus section 3 is used as
**pairs of u16**, explaining why interpreting it as an inverse u32 permutation
was inappropriate. The pair's gameplay meaning and caller preconditions remain
unresolved. The routine repeatedly calls the count helper during iteration.

Recovered in `src/nkm_section3.c`: 236 original/rebuilt/expected comparisons
pass, including duplicate precedence, zero-valued first matches, full-width
inputs, fixed stride, zero counts and rejected sections. All 30 original
consumer instruction addresses were visited. The combined 472-byte unit uses
rebuilt helpers and quotient throughout. See [the report](recovery/nkm-section3.md).

## Reproducible inspection and limits

The subsequent [lifecycle recovery](recovery/resource-lifecycle.md) traces
loaded-pointer writes, explains the policy byte, and reconstructs individual
load/request/release plus completion. The bulk loader handles NKMSortIndex's
initial nonzero policy; its source and actual I/O/backend remain pending.

`tools/ghidra/InspectTbcr.java` checks the complete mapped executable hash and
initializer callback, temporarily disassembles/creates that missing initializer,
and exports selected listings, decompiler output, and incoming references.
Run with headless **`-readOnly -noanalysis -process code.bin`** against the saved
`local/ghidra/smt4-eu/SMT4-EU` project. The original database is not changed.
Use the pinned launcher assembled by `java_command` in `tools/ghidra_reference.py`.
The reviewed command list and logs are in
`local/analysis/tbcr-20261006/consumers-command.json` and `consumers-console.log`;
output is `code-consumers/`. A future output directory must be new. Close the
GUI project before running headless; even `-readOnly` needs its project lock.

The first attempt failed on that lock. The user then closed Ghidra and the
original project became available. A separate fresh import had already started
at `local/ghidra/tbcr-20261006/`; it completed with the same mapped hash, startup
checks, and 8,786 automatic function objects. It is a disposable analysis copy,
not the authoritative working project and not new source coverage.

Independent decoder command, from this repository (adjust start/end as needed):

```powershell
& 'local/tools/xpack-arm-none-eabi-gcc-15.2.1-1.1/bin/arm-none-eabi-objdump.exe' -D -b binary -m arm --adjust-vma=0x100000 --start-address=0x2883e8 --stop-address=0x288424 'local/reference-eu/base/0000/exefs/code.bin'
```

Raw branch-pattern scans can match literal words and can miss Thumb calls; they
were used only to locate candidates, never as a trustworthy call-graph count.
Reviewed text annotations live in `config/symbols-eu.json`. Generated pseudocode
and disassembly remain ignored. No original game bytes are embedded in tests.
