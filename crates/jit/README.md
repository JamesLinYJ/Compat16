# JIT

Windows ARM64 and AMD64 hosts translate frequently executed integer
x86 instructions with Cranelift 0.136.2. The translator is connected to the
ordinary CPU step and bounded scheduler quanta. The CPU
crate keeps `forbid(unsafe_code)`; the generated-code call is owned by this
crate behind a pointer-free, constructor-checked integer IR.

Microsoft describes [Prism](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation)
as JIT translation of x86 blocks to ARM64 with reusable translated-code caches.
This implementation applies JIT translation and cache reuse to Compat16's
16/32-bit execution model. It does not depend on Prism or its private cache
format, and it does not claim Prism's optimization coverage.

## Execution contract

- Instruction fetch, current-byte decode validation, segmentation, paging and
  CPU feature checks run before translation. Cache keys contain normalized
  operations, register slices and immediates. A rewritten/remapped instruction
  therefore selects its current body, rather than a stale address-only entry.
- Straight-line register-only sequences contain up to sixteen operations in
  one SSA function. The recorder learns instructions already fetched by the
  CPU; it does not fetch ahead. Generated code computes owned checkpoints.
  Each later step validates its actual site, decoded operation and complete
  input register/flag state before applying one checkpoint. Rewritten code,
  changed state and control transfers discard predicted tails.
  The existing CPU boundary still owns EIP, RF, interrupt/debug shadows,
  breakpoint delivery, continuation stamps, event observation and instruction
  budgets. This single-step path retains every observable instruction boundary.
- A separate `IntegerLoop` / `LoopCache` compiles up to sixteen register
  operations and a conditional or unconditional backedge into a compiled SSA
  loop. Values stay in host registers, intermediate dead flags are omitted,
  and only the exit state is written. There are no intermediate checkpoint
  stores. This interface has no CPU, filesystem or Windows dependency.
  The CPU adapter supports 16/32-bit real-address and protected segment caches,
  and explicitly certified Win16 selector projections. It rechecks segment
  permissions, CPL/RPL, limits and CPU model features without speculative guest
  faults. Paging, debugging, pending CPU events, interrupt shadows and incomplete
  REP retain ordinary stepping. It checks
  the complete current code span on every dispatch, including the branch,
  and counts every body instruction and backedge without exceeding the budget.
  A provider must explicitly certify stable, unobserved RAM snapshots; device
  memory and custom observers retain ordered fetches. Host process-memory
  snapshots use checked OS copies; no guest address becomes a host pointer.
  The DOS scheduler dispatches at most 256 instructions per quantum, then
  resamples its time-driven device clock and arbitrates interrupts. Quanta
  also stop at the absolute budget and the existing 4,096-instruction host pump.
  The Win16 scheduler also dispatches eligible loops, capped by its next
  readiness checkpoint (at most 64 instructions) and the absolute budget.
  Service gates, instruction history, write watches and active guest callback
  continuations keep single stepping. Host-time sampling follows these bounded
  quanta; guest timer input frequency and instruction counts retain their
  contracts. This is not a cycle-accurate timing claim.
- `MemoryLoop` / `MemoryLoopCache` adds checked 8/16/32-bit loads, stores and
  arithmetic with 16/32-bit effective addresses. Generated code receives an
  exclusive owned byte slice, never a mapping of guest memory. Every access
  checks its complete width against that window. Budget/window exits publish
  the completed prefix and identify the next instruction; the ordinary CPU
  handles any subsequent fault. The CPU adapter snapshots 256 bytes only when
  the provider certifies unobserved RAM and permits coalesced writeback. It
  checks full-window read/write permissions and canonical code/data identities,
  rejecting self-modifying aliases including A20 aliases. MMIO, shared storage,
  alignment-checking CPL3 execution and uncertified providers retain the checked
  path. A partial backing-store write is terminal and is never replayed.
  Each memory instruction preserves full flags for precise prefix exits.
- `Region` / `RegionCache` links up to sixteen integer basic blocks and 64
  guest instructions into one compiled control-flow graph. Conditional,
  unconditional and sequential edges use direct compiled branches with SSA
  state; there is no CPU callback, guest fetch or interpreter dispatch between
  them. A full-block budget guard permits dead intermediate flag elimination.
  Cold prefix paths materialize complete flags at every instruction boundary.
  Every cycle spends budget, including branch-only blocks. Entry can resume
  any instruction after a budget exit, so partial quanta need no interpreter
  step. The CPU revalidates the complete original code span, model and segment
  permissions before each entry, including resumes and remapped successors.
  Discovery is restricted to a certified, nonwrapping span of at most 255
  bytes. Overlapping instruction streams and unguarded near targets remain
  interpreter work; an invalid target never retires its branch early.
  Observed guest successors guide conditional edge order. Linking currently
  covers register integer blocks; memory and x87 operations exit the region
  precisely and retain their existing checked execution paths.
- `FloatCache` compiles x87 add/subtract/multiply/divide on normal finite
  operands and signed zeros. Addition aligns a jammed 128-bit significand and
  normalizes deep cancellation. Multiplication retains the full 128-bit
  product. Division uses two corrected radix-2^32 quotient digits and an exact
  remainder, with a direct path for power-of-two divisors. Explicit rounding
  preserves 24/53/64-bit precision, the extended exponent range, all four RC
  modes, PE and C1. Host `f64` and the host FP environment are never used.
  Subnormal, NaN, infinity, unsupported encoding and range cases retain the
  existing APFloat implementation. Checked scalar memory conversion and
  exception precedence stay in the CPU x87 executor, including integer-memory,
  reversed and popping arithmetic forms.
- `FloatBlock` / `FloatBlockCache` compiles 2–32 consecutive x87 operations into
  one SSA function: register arithmetic, FLD/FST/FSTP registers, FXCH, FLD1,
  FLDZ, FCHS/FABS and raw 80-bit loads/stores. Each arithmetic instruction rounds
  separately; this does not fuse operations or erase intermediate precision
  exceptions. Budget, special-value, empty-stack and stack-full exits publish
  the exact completed prefix. Unmasked PE commits its rounded result, records
  ES/B and exits before the next waiting instruction. Tags, TOP, C1, sticky
  status and saved instruction/data pointers retain their architectural roles.
  The CPU rechecks CR0 availability, pending exceptions, model, code bytes,
  segment permissions and event boundaries before every entry. RAM access uses
  fixed validated offsets into an exclusive 256-byte snapshot. The CPU currently
  accepts absolute addresses within one certified data window, rejects code
  aliases, and publishes RAM before CPU state. Paging, observers, MMIO and CPL3
  alignment checking retain ordinary stepping. Floating blocks do not link
  across integer control-flow edges or compile transcendental operations.
- Generated code addresses only exclusive nine-word integer states, bounded
  owned checkpoint buffers, six-word scalar and nineteen-word block floating buffers, and checked owned RAM windows. Guest register
  values cannot become host pointers. AL/AH and 16-bit writes retain
  unaffected register bits. Arithmetic computes CF/PF/AF/ZF/SF/OF; INC/DEC
  retain CF, and logical operations retain the interpreter's undefined AF.
- MOV/MOVZX/MOVSX, ADD/ADC, SUB/SBB, AND/OR/XOR, CMP/TEST, INC/DEC, NEG/NOT,
  register XCHG/BSWAP and all sixteen SETcc/CMOVcc conditions are supported.
  CMOV still requires support from the selected guest CPU model. Single-step integer memory
  operands pass through the CPU's existing checked access plans; generated code
  receives only their values. Cold/failing compilation returns before reading
  operands, preserving single device reads on interpreter fallback. Read/modify/
  write operations reuse the same prepared access, and flags commit only after
  a successful write. LOCK operations, memory XCHG, system instructions, control
  transfers other than eligible linked branches/backedges, strings, I/O and
  remaining x87 arithmetic continue
  through the checked interpreter.
- Single instructions become eligible on their 32nd execution; learned blocks
  become eligible on their second dispatch. At most 1,024 code entries and
  1,024 trace plans live
  in one CPU's process-local cache. Eviction drops every private code pointer
  before freeing its module. No pointer escapes the cache owner.
  Compiled loops become eligible after eight cache dispatches and have their
  own bounded 1,024-entry cache. Loop and checkpoint signatures have distinct
  compiler keys and share the same authenticated persistence contract.
  Linked regions use a separate 256-entry cache and become eligible after
  eight dispatches. Scalar floating arithmetic has twelve precision/rounding
  variants per operation, each eligible after 32 calls. Floating blocks use a
  separate 256-entry cache with twelve variants and an eight-dispatch threshold.
  They use the same compiler
  relocation, private code ownership and authenticated persistence contracts.
- Cranelift publishes writable code as executable and synchronizes the native
  instruction cache. Compilation/publication failure leaves interpretation
  available. No executable pointer
  is shared across code owners or processes.

## Host branch behavior

The host processor predicts the branches in generated ARM64 or AMD64 code.
The JIT keeps hot loop dispatch on a reusable direct path before hash-table
lookup, marks loop exit blocks cold for Cranelift layout, and finishes full
256-instruction RAM quanta at a backedge when possible. Smaller budgets still
support precise prefix exits. The CPU continues validating code, permissions,
events and canonical aliases on every dispatch.

RAM addresses use Cranelift's `select_spectre_guard` before the bounds branch.
Loads and stores depend on the checked selection; its fallback is the owned
integer state, which is large enough even when the caller supplies a one-byte
window. This retains the architectural exit and prevents branch speculation
from supplying an unchecked memory-window address.

`--jit-stats` reports taken/fallthrough guest branches, budget and RAM-window
exits, direct loop-dispatch hits, linked-region instructions/direct links and x87
arithmetic executions/range fallbacks and floating-block instruction counts. Loop outcomes are reconstructed once per
quantum. Regions accumulate bounded software edge counts in SSA values and
publish them once at exit. These are software
execution counts, not hardware misprediction or performance-counter readings.
Actual workload measurements decide whether a layout/dispatch change is useful.

## Persistent compilation artifacts

The independent module exposes an opaque `Artifact` and an optional
`ArtifactStore`; it has no Windows, filesystem or runtime dependency. Cranelift's
incremental compiler cache serializes relocatable compiled artifacts, with its
own key covering IR, compiler version, target ISA, flags and CPU features.
Restored artifacts pass through Cranelift relocation and executable publication.

The Windows host stores artifacts under the account's LocalAppData directory,
in `Compat16/Jit/v1`. Per-user DPAPI protection binds bytes to their compiler
key; a versioned envelope and SHA-256 digest also check decrypted output.
Guest plaintext cannot enter the unsafe authenticated-artifact restore API.
The native host account is trusted: DPAPI is not a sandbox against native
programs running as that same account. See Microsoft's
[DPAPI contract](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

Reads are bounded, writes use a nonblocking process lock and atomic replacement,
and storage is capped at 4,096 artifacts / 64 MiB with a 1 MiB payload limit.
Missing, corrupt, incompatible or unavailable cache data falls back to ordinary
compilation. Filesystem failures never become guest execution failures.

## Controls and evidence

`--cpu-engine jit` is the Windows default. `--cpu-engine interpreter` disables
JIT execution, including for DOS EXEC children and restored CPU owners.
`--no-jit-cache` disables disk persistence. The optional store is shared with
DOS EXEC children and restored CPU owners; executable allocations remain private.
`--jit-stats` prints compilation, execution, failure, block, checkpoint, loop, iteration, RAM-window instruction and
persistence counters
for the active CPU. Restoring a CPU owner creates a new nonarchitectural cache;
these counters are not a lifetime aggregate across all subprocesses.

Cargo checks establish Rust compilation. Native release builds, executed JIT
counters, interpreter comparisons, original application acceptance and measured
speedup are separate evidence. Generated-code call counts include block heads;
checkpoint hits count later instructions applied without another generated-code call.
The ordinary step retains per-instruction validation. The opt-in loop path
validates code once per bounded quantum. Paging, multiple data segments in
one RAM loop, indirect/far control transfers, exceptional/transcendental x87 and I/O
compilation remain unsupported. Throughput measurements must identify their
host architecture; AMD64 execution under ARM64 Windows emulation is not native
AMD64 performance evidence.

Additional registry license material is in
[`LICENSES/JIT-DEPENDENCIES.txt`](../../LICENSES/JIT-DEPENDENCIES.txt), and the
normal release script includes it with the existing legal files.
