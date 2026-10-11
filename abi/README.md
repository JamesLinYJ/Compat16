# Typed Win16 ABI catalog

This directory contains the production ABI source in **compact TOML authoring schema v2**. [`abi-schema`](../crates/abi-schema/src/manifest/) expands it into a validated, normalized Rust model; [`abi-codegen`](../crates/abi-codegen/) consumes that model. The compact format and normalized representation have different responsibilities: authoring avoids repeated facts, while validation and generation operate on explicit typed records.

## Layout and identity

- `catalog.toml` indexes logical modules, groups, shared types, defaults and explicit name-collision resolutions. Every production TOML file must be indexed.
- `groups/<module>/<domain>.toml` groups exports by responsibility, such as KERNEL memory/files/process, USER windows/messages/controls, and GDI drawing/fonts/raster. Each file supplies its module and local defaults once.
- `types/runtime.toml` defines reusable guest value types and their explicit historical declaration-encoding defaults.

A logical DLL/module is an import identity, not a physical file boundary. Moving an export between groups must preserve its module, ordinal, names, binding, and expanded defaults. Module source spellings, aliases, case-insensitive lookup, and conventional `.EXE`, `.DLL`, `.DRV`, and `.MOD` suffixes remain part of the lookup contract. `name_resolutions` preserves historical name collisions without deleting declarations.

The loader indexes regular `.toml` files, permits this README as documentation, and rejects symlinks, unsafe paths, unindexed manifest files, and unknown fields. Compiled baselines and machine-readable reports remain JSON validation artifacts outside the production catalog.

## Authoring contracts

An export starts with `[[exports]]`. Its `call` table contains the canonical runtime signature. Parameters appear in guest argument order, one compact typed record per line:

```toml
[exports.call]
returns = "word"
params = [
  { name = "buckets", type = "I16", encoding = "word" },
]
```

Here the shared type defines the semantic value and default slot size. The explicit `encoding` preserves a historical declaration encoding that differs from the named type's default; it does not alter the runtime value type. `slot_bytes` is an explicit override where needed. A guest byte may occupy a two-byte slot; guest segmented pointers are never native host addresses.

The authoring defaults are deterministic: calls use fixed-stack Pascal unless overridden; exports use function kind unless overridden. Root architecture and ordinal-source defaults and group attribute defaults are explicit in their files. Empty `attributes` or `args` arrays deliberately clear inherited values. TOML has no null: omit an optional field to represent absence, never a placeholder string or guessed value.

`call.returns` is the runtime return shape. Fixed stack size and cleanup are derived from the canonical signature. Variable-stack and register-context calls use explicit kinds. Do not add a second editable runtime parameter list, stack-byte total, or return classification.

`decl` retains historical declaration differences. For bound calls, each parameter's explicit encoding or named-type encoding default supplies its declaration hint; unbound declarations retain known historical encodings in `decl.args`. Return modifiers derive from historical attributes, independently of the runtime return shape. These rules normalize declaration evidence without using it to invent callability.

A `binding` names an existing Rust dispatch variant with `rust_id`, stable numeric `id_value`, and descriptor `constant`. File order must not renumber identities. Bindings contain no arbitrary Rust expressions and establish decoder connection, not complete application compatibility. A declaration without `call` remains an unknown runtime ABI; a binding requires a known call. Variables and equates retain their declared values. Dynamic selector/profile data-export policy remains in runtime `data_exports.rs`.

Production TOML contains build/runtime metadata only. Runtime-relevant `source_module`, declaration attributes, and encoding metadata remain in the catalog.

## Editing and validation

1. Edit the appropriate domain group. Reuse a named type only when its semantic contract and declared encoding are appropriate; record explicit overrides where they differ. Keep unsupported details unknown.
2. Index new group/type files. Check the expanded effect of defaults before changing them: a default can affect many declarations.
3. Build on a supported Windows host with the pinned toolchain using `scripts/build.ps1`. The Win16 build script loads and normalizes the catalog, validates the Rust model, and generates `win16_exports.rs` and `win16_bindings.rs` into Cargo's `OUT_DIR`. Do not edit or commit generated Rust.
4. Review normalized output and compiled descriptor parity through the shared build-tools pipeline:

   ```powershell
   cargo run -p build-tools -- inspect --catalog abi --module KERNEL
   cargo run -p build-tools -- audit-win16 --catalog abi --module KERNEL
   cargo run -p build-tools -- generate --catalog abi --output target/abi-review
   ```

   `inspect` validates the complete catalog before filtering its display. `audit-win16` distinguishes declaration-only exports and compares canonical bindings/signatures with compiled descriptors. `generate` uses the same generator as the build script.
5. Use focused normalization, schema, generator, resolver, and ABI regression checks for the change. Format migrations must preserve expanded records field by field. A successful build alone does not establish application compatibility.

## Provenance and licensing

The repository [LICENSE](../LICENSE), [source/data notices](../LICENSES/NOTICE.txt), and applicable original notices continue to apply. See also the retained [ABI source notes](../crates/win16/ABI_EVIDENCE.md). Replacing a format or parser does not change attribution or licensing obligations.
