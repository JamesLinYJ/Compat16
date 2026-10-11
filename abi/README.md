# Typed Win16 ABI catalog

This directory is the production declaration and callable-signature input for the Rust ABI generator. TOML is the serialization format; the authoritative model and validation rules are Rust types in [`abi-schema`](../crates/abi-schema/src/manifest/model.rs).

## Layout and identity

- `catalog.toml` indexes logical modules, explicit name-collision resolutions, export groups, and shared-type files. Every TOML file beneath this directory must be indexed.
- `groups/<module>/<domain>.toml` contains export declarations organized by responsibility: for example KERNEL memory/files/process, USER windows/messages/controls, and GDI drawing/fonts/raster.
- `types/runtime.toml` defines reusable scalar and segmented-pointer value types. Parameters reference these by name.

A logical DLL/module is an import identity, not a physical file boundary. Its exports may span several groups; moving an export between groups must not change its module, ordinal, names, or binding identity. The module index retains source-module spellings and aliases. Import lookup is ASCII-case-insensitive and recognizes the conventional `.EXE`, `.DLL`, `.DRV`, and `.MOD` suffixes. Explicit `name_resolutions` preserve historical collisions without deleting either declaration.

The loader examines regular TOML files for index completeness. This README is documentation, not an indexed manifest. Symlinks and unsafe paths are rejected.

## Serialization rules

TOML keeps records readable as tables and arrays of tables, with comments alongside the declarations. The format does not change the Rust model or its validation rules. `[[exports]]` starts an export; nested tables describe its declaration, entry, signature, and optional binding. `[[exports.entry.abi.signature.parameters]]` preserves parameter order.

TOML has no null value. Omit an optional field to represent Rust `Option::None`; do not substitute an empty string, zero, or an invented type. Required empty arrays remain explicit. The loader rejects unknown fields rather than accepting misspelled contracts. Machine-readable compiled baselines and reports remain JSON; they are validation artifacts, not production manifests.

## Canonical contracts and evidence

For a bound function or stub, `entry.abi.signature` is the canonical callable contract:

- `calling_convention` selects the supported guest convention.
- Each parameter has a name, physical `slot_bytes`, and typed value. A guest byte can occupy a two-byte slot; segmented pointers are guest values, never native host addresses.
- `returns` records the runtime return shape independently of historical return modifiers.

Fixed stack size and caller/callee cleanup are derived from this signature. Variable-stack and register-context entries are explicit variants. Do not add a second editable parameter list, stack-byte total, or return classification elsewhere.

`declaration` retains historical declaration kind, attributes, architecture constraints, and ABI hints for inspection and lossless provenance. These hints do not select a callable decoder and must not override a verified runtime signature. `evidence` records sources and source lines; it is not executable Rust.

A `binding` identifies the existing Rust dispatch variant through `rust_id`, its stable numeric `id_value`, and its exported descriptor `constant`. Reordering groups must not renumber these values. Bindings do not contain arbitrary Rust expressions. A binding demonstrates connection to a request decoder, not complete application compatibility or implementation coverage.

Unbound callable declarations use `entry.abi.kind = "unknown"` and no binding. Known historical encodings remain in declaration evidence; they do not justify inventing semantic parameter or return types. Variables and equates retain their declared values. Dynamic selector/profile data-export policy remains in the runtime's `data_exports.rs`.

## Editing and validation

1. Edit the relevant domain group. Add or reuse a shared type only when its contract is supported by evidence. Preserve unknown details as unknown.
2. Index new group/type files in `catalog.toml`. Preserve existing ordinals, aliases, collision choices, discriminants, and source evidence unless intentionally changing the public contract.
3. Build on a supported Windows host with the pinned toolchain using `scripts/build.ps1`. The Win16 build script calls `abi_schema::manifest::load_catalog`, then `abi_codegen::compile_catalog`, and writes generated Rust into Cargo's `OUT_DIR`. Generated files are not source files to edit or commit.
4. Inspect and audit with the build-tools CLI when reviewing changes:

   ```powershell
   cargo run -p build-tools -- inspect --catalog abi --module KERNEL
   cargo run -p build-tools -- audit-win16 --catalog abi --module KERNEL
   ```

   `inspect` validates the complete catalog before filtering the display. `audit-win16` compares the selected module's canonical bindings and signatures with compiled descriptors and distinguishes declaration-only entries.
5. For generator review, `cargo run -p build-tools -- generate --catalog abi --output target/abi-review` emits the same two Rust files through the shared generator. Use focused schema, generator, resolver, and ABI regression checks for the change. A successful build alone does not establish application compatibility.

## Provenance and licensing

Historical spec and catalog paths in evidence refer to the source revision from which the records were migrated; they need not remain active build inputs. Preserve these references when reorganizing files. Changing serialization or replacing a parser does not establish clean-room authorship or remove obligations attached to source material. The repository [LICENSE](../LICENSE) and [source/data notices](../LICENSES/NOTICE.txt) continue to apply, together with any applicable original notices.
