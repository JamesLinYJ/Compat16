# Native integer JIT

Windows ARM64 and AMD64 hosts translate frequently executed integer
x86 instructions with Cranelift 0.136.2. The translator is connected to the
ordinary CPU step. The CPU
crate keeps `forbid(unsafe_code)`; the generated-code call is owned by this
crate behind a pointer-free, constructor-checked integer IR.

Microsoft describes [Prism](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation)
as JIT translation of x86 blocks to ARM64 with reusable translated-code caches.
This implementation applies native translation and cache reuse to Compat16's
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
  operations and a conditional or unconditional backedge into a native SSA
  loop. Values stay in native registers, intermediate dead flags are omitted,
  and only the exit state is written. There are no intermediate checkpoint
  stores. This interface has no CPU, filesystem or Windows dependency.
  The CPU adapter accepts only ordinary real-address CS caches with no paging,
  debugging, pending CPU event, interrupt shadow or incomplete REP. It checks
  the complete current code span on every dispatch, including the branch,
  and counts every body instruction and backedge without exceeding the budget.
  A provider must explicitly certify stable, unobserved RAM snapshots; device
  memory and custom observers retain ordered fetches. Native process-memory
  snapshots use checked OS copies; no guest address becomes a host pointer.
  The DOS scheduler dispatches at most 256 instructions per quantum, then
  resamples its time-driven device clock and arbitrates interrupts. Quanta
  also stop at the absolute budget and the existing 4,096-instruction host pump.
  Firmware/DOS service segments, instruction history and write watches keep
  single stepping. Protected-mode and Win16 observer execution retain the
  original per-instruction path. This changes host-time sampling granularity,
  not the instruction counts or guest timer input frequency; it is not a
  cycle-accurate timing claim.
- Generated code addresses only exclusive nine-word integer states and a
  bounded owned checkpoint buffer. Guest
  register values cannot become native pointers. AL/AH and 16-bit writes retain
  unaffected register bits. Arithmetic computes CF/PF/AF/ZF/SF/OF; INC/DEC
  retain CF, and logical operations retain the interpreter's undefined AF.
- MOV/MOVZX/MOVSX, ADD/ADC, SUB/SBB, AND/OR/XOR, CMP/TEST, INC/DEC, NEG/NOT,
  register XCHG/BSWAP and all sixteen SETcc/CMOVcc conditions are supported.
  CMOV still requires support from the selected guest CPU model. Integer memory
  operands pass through the CPU's existing checked access plans; generated code
  receives only their values. Cold/failing compilation returns before reading
  operands, preserving single device reads on interpreter fallback. Read/modify/
  write operations reuse the same prepared access, and flags commit only after
  a successful write. LOCK operations, memory XCHG, system instructions, control
  transfers other than eligible loop backedges, strings, I/O and x87 continue
  through the checked interpreter.
- Single instructions become eligible on their 32nd execution; learned blocks
  become eligible on their second dispatch. At most 1,024 code entries and
  1,024 trace plans live
  in one CPU's process-local cache. Eviction drops every private code pointer
  before freeing its module. No pointer escapes the cache owner.
  Native loops become eligible after eight cache dispatches and have their
  own bounded 1,024-entry cache. Loop and checkpoint signatures have distinct
  compiler keys and share the same authenticated persistence contract.
- Cranelift publishes writable code as executable and synchronizes the native
  instruction cache. Compilation/publication failure disables native execution
  for this cache while leaving interpretation available. No executable pointer
  is shared across code owners or processes.

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
native execution, including for DOS EXEC children and restored CPU owners.
`--no-jit-cache` disables disk persistence. The optional store is shared with
DOS EXEC children and restored CPU owners; executable allocations remain private.
`--jit-stats` prints compilation, execution, failure, block, checkpoint, loop, iteration and
persistence counters
for the active CPU. Restoring a CPU owner creates a new nonarchitectural cache;
these counters are not a lifetime aggregate across all subprocesses.

Cargo checks establish Rust compilation. Native release builds, executed JIT
counters, interpreter comparisons, original application acceptance and measured
speedup are separate evidence. Native-call counts include block heads;
checkpoint hits count later instructions applied without another native call.
The ordinary step retains per-instruction validation. The opt-in real-address
loop path validates code once per bounded quantum; direct generated guest
memory access, protected-mode loop fusion, x87 and I/O compilation remain
unsupported. Throughput measurements must identify their
host architecture; AMD64 execution under ARM64 Windows emulation is not native
AMD64 performance evidence.

Additional registry license material is in
[`LICENSES/JIT-DEPENDENCIES.txt`](../../LICENSES/JIT-DEPENDENCIES.txt), and the
normal release script includes it with the existing legal files.
