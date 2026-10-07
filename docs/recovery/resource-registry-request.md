# Registry asynchronous submission and completion integration

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All original entry addresses below are ARM. This combines eleven existing
contracts; the repository total remains thirty-one. No recovered C behavior changed.

## Executed boundary and observations

Registry request `0x0033C844` now executes the asynchronous wrapper `0x002B6820`,
backend `0x002AE72C`, callback constructor `0x00155BBC`, descriptor constructor
`0x002B0494` and descriptor setters on one emulated thread and retained memory.
The harness later reads the actual callback/context stored at descriptor
`+0x130/+0x134` and invokes completion `0x00155B30`, which executes the registry
callback `0x0019F990` and descriptor failure/cleanup helpers.

Both original and rebuilt paths execute these routines. The rebuilt path executes
no original instructions. Allocation, constructor synchronization/result handling,
strings, worker completion/dispatch and packet release remain explicit models.
The dispatcher itself is not reconstructed or executed.

The comparisons establish the following behavior for the documented fixtures:

- A pending request leaves a null registry pointer and preserves its stale size.
  The registry wrapper supplies flags zero, its entry as callback context, its
  pointer field as output, and the request wrapper supplies parameter four.
- Repeating a request before completion allocates a second packet and descriptor:
  the wrapper has no separate pending marker. Earlier list nodes, packets and
  descriptor contents remain intact while later requests append to the list.
- Completion first publishes its output pointer, then the registry callback
  writes the pointer again and publishes size. Successful completion subsequently
  detaches descriptor data, increments cleanup and releases the packet. State five
  publishes zero pointer/size and retains descriptor data for later cleanup.
- For multiple requests targeting one entry, the last completion executed by the
  model determines the entry's final pointer/size, including a failure or null
  successful result. All six completion orders for three outstanding requests
  are checked. This does not establish that gameplay actually issues duplicates.
- Once completion publishes a nonnull pointer, a subsequent registry request
  returns one without another allocation. High-bit policy bytes and unsigned
  out-of-range IDs retain the original eligibility behavior.

The independent oracle checks every modeled memory region and its guards, all
external instruction stores as byte multisets, and the exact order of registry
stores. Constructor checkpoints check the initialized packet, output clearing,
list insertion, strings and descriptor state before returning. Completion checks
publication before entering the real registry callback and ownership before
packet release. Lower calls poison caller-saved registers and condition flags;
outer calls check SP, integer callee-saved registers, saved d8 and caller stack.
The synchronization model changes the global handle to check its release-time reload.

## Corpus and reproduction

Run from `SMT4-decomp/`, with Ghidra jobs sequential and the saved project closed:

```powershell
python tools/check_resource_registry_request.py --output local/validation/registry-request-next
python -m unittest discover -s tests -v
```

Successful final record:
`local/validation/registry-request-20261006-final/COMPLETE.json`.
The **1,036-byte ARMv6 unit** uses function sections and linker garbage collection
to exclude synchronous load and registry release routines. Reference/tool hashes,
source/harness hashes, original/rebuilt disassembly and exact instruction coverage
are retained locally. The Ghidra project is opened read-only.

| Check | Result |
| --- | ---: |
| Eligibility scenarios: 67 IDs, four policy bytes, two initial pointers | 536 |
| Completion scenarios: 67 IDs, three modes, three outcomes | 603 |
| Retained-request scenarios: six completion orders, four initial list sizes | 24 |
| Total original/rebuilt/oracle scenarios | 1,163 |
| Executed submissions per path | 742 |
| Executed completions per path | 742 |
| Skipped registry calls per path | 790 |
| Original instruction addresses visited | All 266 |
| Maximum instructions in a submitted/completed outer call | 242 |
| Modeled lower calls across both paths | 15,086 |
| Public synthetic tests | 31 passed |

Paths include empty/ordinary paths, a prefix, colons at either side of the eight-byte
scan limit, and a 250-character path. Modes are 0/1/255; data and sizes include zero,
high-bit and maximum unsigned values. Initial lists contain zero through three
nodes. Each retained-request scenario submits IDs 0, 0 and 66 before dispatching
any completion; all outstanding memory is checked at every return. Five unsigned
out-of-range IDs are also exercised. Instruction visits include predicated
instructions and do not imply every condition outcome or arbitrary concurrency.

Four local mutants are rejected: wrong registry output field, wrong registry
callback context, wrong stored dispatch context, and detaching data before the
registry callback. The driver is
`local/validation/check-registry-request-negatives.py`; each
`registry-request-20261006-negative-*/NEGATIVE.json` records its expected diagnostic
and confirms absence of a success marker. Production sources were unchanged.

## Limits and next work

2026-10-07 continuation: optional `--recover-release` now executes release
routing inside this chain, passing 1,271 scenarios in 1,148 bytes and all 294
original instruction addresses. See [integrated release evidence](resource-registry-request-release.md).
Default mode retains the boundary and corpus described here.

The fixtures use valid disjoint allocations, bounded paths without format
directives, and completion after submission returns. Packet release records the
call without implementing a free list, reuse or descriptor destruction. There is
no callback reentrancy, actual worker execution, concurrent CPU scheduling,
allocation failure, file I/O, live gameplay evidence or binary-matching claim.
Submission snapshots establish pending state, not asynchronous progress or liveness.
G1/G2 and the original compiler/host-address questions remain open.

Subsequent work statically traced the dispatcher at `0x00113D58`; see
[worker trace](resource-worker.md). Release routing `0x002C43B4` is now separately
recovered and compared; see [release evidence](resource-release.md). This
integration's default mode still models both boundaries. Next reconstruct
and compare bounded worker callback/cleanup behavior; keep worker transitions
explicitly modeled until their instructions execute in the checker.
