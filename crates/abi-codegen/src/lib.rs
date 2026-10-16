#![forbid(unsafe_code)]

mod manifest;
pub use manifest::{GeneratedCatalog, compile_catalog};

#[cfg(test)]
mod manifest_tests;
