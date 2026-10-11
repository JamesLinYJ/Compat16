//! Versioned, project-owned guest ABI catalog.
//!
//! Logical module identity is independent of file grouping. Declaration
//! encodings live only in historical declaration evidence; semantic types describe
//! verified runtime values. An unknown signature is never made callable by a
//! binding or by a guessed width. Loading validates the complete rooted catalog.

mod model;
mod validate;
#[cfg(test)]
mod tests;

pub use model::*;
pub use validate::{ManifestError, ValidatedCatalog, load_catalog, validate_catalog};
