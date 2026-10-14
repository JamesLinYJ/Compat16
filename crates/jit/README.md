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
- Each translation unit currently retires one integer instruction.
  The existing CPU boundary still owns EIP, RF, interrupt/debug shadows,
  breakpoint delivery, continuation stamps, event observation and instruction
  budgets. No block skips an observable instruction boundary.
- Generated code addresses only an exclusive nine-word integer state. Guest
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
  transfers, strings, I/O and x87 continue through the checked interpreter.
- An IR body becomes eligible on its 32nd execution. At most 1,024 entries live
  in one CPU's process-local cache. Eviction drops every private code pointer
  before freeing its module. No pointer escapes the cache owner.
- Cranelift publishes writable code as executable and synchronizes the native
  instruction cache. Compilation/publication failure disables native execution
  for this cache while leaving interpretation available. No disk cache or
  generated code is shared across processes.

## Controls and evidence

`--cpu-engine jit` is the Windows default. `--cpu-engine interpreter` disables
native execution, including for DOS EXEC children and restored CPU owners.
`--jit-stats` prints compilation, execution, failure and cache-reset counters
for the active CPU. Restoring a CPU owner creates a new nonarchitectural cache;
these counters are not a lifetime aggregate across all subprocesses.

Cargo checks establish Rust compilation. Native release builds, executed JIT
counters, interpreter comparisons, original application acceptance and measured
speedup are separate evidence. Multi-instruction block fusion, direct generated
guest memory access and persistent module caches are not implemented in this
version.

Additional registry license material is in
[`LICENSES/JIT-DEPENDENCIES.txt`](../../LICENSES/JIT-DEPENDENCIES.txt), and the
normal release script includes it with the existing legal files.
