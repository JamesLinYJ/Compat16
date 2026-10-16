#![forbid(unsafe_code)]

mod audit;
mod probe;
mod vga_probe;

pub use abi_codegen::{GeneratedCatalog, compile_catalog};
pub use abi_schema::manifest;
pub use audit::{Win16AuditReport, audit_win16_module};
pub use probe::{
    ProbeBuildError, ProbeFormat, dos_probe_bytes, probe_file_contents, probe_file_name,
};
pub use vga_probe::{VGA_PROBE_FILE_CONTENTS, VGA_PROBE_FILE_NAME, vga_probe_bytes};
