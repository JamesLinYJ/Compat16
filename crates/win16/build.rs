//! Compile the validated, project-owned ABI catalog into immutable Rust data.

use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let crate_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let catalog_root = crate_root.join("../../abi");
    // Watch the directory as well as indexed files so adding an unindexed TOML
    // file reruns validation instead of silently retaining a stale catalog.
    println!("cargo:rerun-if-changed={}", catalog_root.display());
    let catalog = abi_schema::manifest::load_catalog(&catalog_root)?;
    println!("cargo:rerun-if-changed={}", catalog_root.join("catalog.toml").display());
    for path in catalog.catalog().groups.iter().chain(&catalog.catalog().types) {
        println!("cargo:rerun-if-changed={}", catalog_root.join(path).display());
    }
    let generated = abi_codegen::compile_catalog(&catalog);
    let output = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(output.join("win16_exports.rs"), generated.metadata)?;
    fs::write(output.join("win16_bindings.rs"), generated.bindings)?;
    Ok(())
}
