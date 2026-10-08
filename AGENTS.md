# Development guide

## Architecture

- Use Rust 2024 and the pinned toolchain. Keep `Cargo.lock` tracked.
- Keep guest CPU execution, DOS/Win16 ABI translation, and native host APIs separate.
- Native hosts are Windows AMD64 and ARM64. Guest x86 execution does not require an x86 host build.
- Guest addresses and handles are never host pointers. Use checked, process-owned memory; no physical memory, raw disks, hardware port access, or inline assembly.
- Use Unicode Windows APIs at the host boundary. Preserve guest ANSI/DBCS byte counts, layouts, and calling conventions.
- Prefer established libraries and Windows services. Use fixed-layout codecs where appropriate; explain unavoidable custom codecs beside the implementation.
- Fix general contracts and ownership errors. Avoid application-name exceptions, invented success results, and blanket warning suppression.

## Changes

- Keep patches focused and preserve unrelated changes. Do not discard work or rewrite Git history without authorization.
- Keep entrypoints thin and split large modules by responsibility. Generated Rust belongs in `OUT_DIR`.
- Read the files relevant to the task. Do not add progress diaries, investigation archives, or duplicate source snapshots.
- Keep private paths, user names, machine names, credentials, and local infrastructure details out of tracked files and release packages.
- Use neutral technical language. These instructions apply to all contributors and development tools.
- Preserve required third-party notices. A rewrite or rename does not by itself change their terms.

## Validation

- Build with `scripts/build.ps1`. Keep the four native runtime files together.
- Do not run system installation, remove shared tools, or publish changes without authorization for that action.
- Choose focused validation for the requested change. Do not add or run tests unless requested.
- A successful build establishes compilation, not application compatibility. Report observed runtime behavior and remaining limits separately.
- Interactive application input remains with the person performing acceptance unless they delegate it.
