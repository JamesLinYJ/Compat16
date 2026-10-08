#![forbid(unsafe_code)]

mod error;
mod model;
mod parser;
mod record;
mod render;
#[cfg(test)]
mod return_modifier_tests;

pub use error::SpecError;

/// Compile one project-owned ABI specification into an `entry!` slice.
///
/// The module header in `source` must agree with `module` and
/// `source_module`. `spec_path` is emitted as project provenance.
pub fn compile_spec(
    module: &str,
    source_module: &str,
    spec_path: &str,
    source: &str,
) -> Result<String, SpecError> {
    let parsed = parser::parse_spec(module, source_module, spec_path, source)?;
    Ok(render::render_spec(&parsed))
}
