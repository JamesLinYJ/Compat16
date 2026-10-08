//! Compile this crate's module specifications into immutable Rust ABI data.

use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let specs = root.join("specs");
    println!("cargo:rerun-if-changed={}", specs.display());
    let mut paths = fs::read_dir(&specs)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().is_some_and(|extension| extension == "spec"));
    paths.sort();
    if paths.is_empty() {
        return Err("Win16 module specifications are missing".into());
    }

    let mut output = String::from("// Generated from this crate's module specifications.\n");
    let mut modules = Vec::new();
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
        let source = fs::read_to_string(&path)?;
        let (module, source_module) = module_header(&source)?;
        if modules.iter().any(|(name, _)| name == &module) {
            return Err(format!("duplicate Win16 module specification: {module}").into());
        }
        let file_name = path.file_name().ok_or("specification has no file name")?
            .to_str().ok_or("specification file name is not Unicode")?;
        let spec_path = format!("specs/{file_name}");
        let records = abi_codegen::compile_spec(&module, &source_module, &spec_path, &source)?;
        let identifier = format!("MODULE_{}", module.replace('.', "_"));
        output.push_str(&format!("static {identifier}: &[ExportMetadata] = {records};\n"));
        modules.push((module, identifier));
    }
    output.push_str("pub static WIN16_EXPORTS: &[&[ExportMetadata]] = &[\n");
    for (_, identifier) in modules {
        output.push_str(&format!("    {identifier},\n"));
    }
    output.push_str("];\n");
    let destination = PathBuf::from(env::var("OUT_DIR")?).join("win16_exports.rs");
    fs::write(destination, output)?;
    Ok(())
}

fn module_header(source: &str) -> Result<(String, String), Box<dyn Error>> {
    let mut module = None;
    let mut source_module = None;
    for line in source.lines().filter_map(|line| line.trim().strip_prefix('#')) {
        for token in line.split_ascii_whitespace() {
            if let Some(value) = token.strip_prefix("module=") {
                if module.replace(value.to_owned()).is_some() {
                    return Err("module specification repeats its module name".into());
                }
            }
            if let Some(value) = token.strip_prefix("source_module=") {
                if source_module.replace(value.to_owned()).is_some() {
                    return Err("module specification repeats its module file name".into());
                }
            }
        }
    }
    let module = module.ok_or("module specification is missing module= header")?;
    if module.is_empty() || !module.bytes().all(|byte| byte.is_ascii_uppercase()
        || byte.is_ascii_digit() || byte == b'_') {
        return Err(format!("invalid Win16 module name: {module}").into());
    }
    let source_module = source_module.ok_or("module specification is missing source_module= header")?;
    if source_module.is_empty() {
        return Err("module specification has an empty module file name".into());
    }
    Ok((module, source_module))
}
