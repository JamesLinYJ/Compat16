//! PE32 (I386) parsing and guest load planning.
//!
//! The `object` PE reader owns the general DOS/COFF/optional-header and table
//! layouts. This adapter adds checked guest RVA, image-size, and relocation
//! rules without exposing `object` types across the formats crate boundary.

#[path = "pe32/exports.rs"]
mod pe32_exports;
#[path = "pe32/imports.rs"]
mod pe32_imports;
#[path = "pe32/load_plan.rs"]
mod pe32_load_plan;
#[path = "pe32/parse.rs"]
mod pe32_parse;
#[path = "pe32/relocations.rs"]
mod pe32_relocations;
#[path = "pe32/rva.rs"]
mod pe32_rva;
#[path = "pe32/sections.rs"]
mod pe32_sections;
#[path = "pe32/tls.rs"]
mod pe32_tls;
#[path = "pe32/types.rs"]
mod pe32_types;

pub use pe32_load_plan::{Pe32LoadOptions, Pe32LoadPlan, plan_pe32_load};
pub use pe32_parse::parse_pe32;
pub use pe32_types::{
    Pe32DataDirectory, Pe32DataDirectoryKind, Pe32DelayImportMetadata, Pe32DirectoryAddressKind,
    Pe32Error, Pe32Export, Pe32ExportTarget, Pe32ForwardTarget, Pe32Image, Pe32ImportKind,
    Pe32ImportModule, Pe32ImportSymbol, Pe32ImportTarget, Pe32LoadSection, Pe32Relocation,
    Pe32Section, Pe32TlsMetadata,
};
