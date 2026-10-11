use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use build_tools::{
    ProbeFormat, VGA_PROBE_FILE_NAME, audit_win16_module, compile_catalog, dos_probe_bytes,
    manifest::{Module, ValidatedCatalog, load_catalog}, vga_probe_bytes,
};
use win16_abi::exports::export_descriptors;

pub(super) fn run() -> ExitCode {
    match run_command() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("build tools: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run_command() -> Result<ExitCode, String> {
    let mut args = env::args_os().skip(1);
    let Some(command) = args.next() else {
        return Err(usage().to_owned());
    };
    let command = command
        .into_string()
        .map_err(|_| format!("command is not valid Unicode\n{}", usage()))?;
    if command == "--help" || command == "-h" || command == "help" {
        println!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }
    match command.as_str() {
        "inspect" => {
            run_catalog_command(false, args)?;
            Ok(ExitCode::SUCCESS)
        }
        "generate" => {
            run_catalog_command(true, args)?;
            Ok(ExitCode::SUCCESS)
        }
        "audit-win16" => run_audit_win16_command(args),
        "probe" => {
            run_probe_command(args)?;
            Ok(ExitCode::SUCCESS)
        }
        "vga-probe" => {
            run_vga_probe_command(args)?;
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command `{other}`\n{}", usage())),
    }
}

fn run_audit_win16_command(args: impl Iterator<Item = OsString>) -> Result<ExitCode, String> {
    let mut module = None;
    let mut catalog_root = None;
    parse_options(args, |key, value| match key {
        "--module" => set_once(&mut module, unicode_module(value)?, key),
        "--catalog" => set_once(&mut catalog_root, PathBuf::from(value), key),
        _ => Err(format!("unknown option `{key}`")),
    })?;

    let module = module.ok_or_else(|| format!("audit-win16 requires --module\n{}", usage()))?;
    let root = catalog_root.ok_or_else(|| format!("audit-win16 requires --catalog\n{}", usage()))?;
    let catalog = load_catalog(&root).map_err(|error| error.to_string())?;
    let report = audit_win16_module(&catalog, &module, export_descriptors())
        .map_err(|error| error.to_string())?;
    println!("# input_catalog={}", tsv_field(&root.display().to_string()));
    print!("{}", report.to_tsv());
    Ok(if report.has_differences() { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

fn unicode_module(value: OsString) -> Result<String, String> {
    value.into_string().map_err(|_| "--module value must be valid Unicode".to_owned())
}

fn tsv_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn run_catalog_command(
    is_generate: bool,
    args: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    let mut catalog_root = None;
    let mut output = None;
    let mut module_name = None;

    parse_options(args, |key, value| match key {
        "--catalog" => set_once(&mut catalog_root, PathBuf::from(value), key),
        "--output" => set_once(&mut output, PathBuf::from(value), key),
        "--module" => set_once(&mut module_name, unicode_module(value)?, key),
        _ => Err(format!("unknown option `{key}`")),
    })?;

    let root = catalog_root.ok_or_else(|| format!("missing --catalog\n{}", usage()))?;
    if is_generate && output.is_none() {
        return Err(format!("generate requires --output\n{}", usage()));
    }
    if is_generate && module_name.is_some() {
        return Err("generate emits the whole validated catalog and does not accept --module".to_owned());
    }
    if !is_generate && output.is_some() {
        return Err("inspect does not accept --output".to_owned());
    }
    let catalog = load_catalog(&root).map_err(|error| error.to_string())?;

    if is_generate {
        let output = output.ok_or_else(|| "generate requires --output".to_owned())?;
        let generated = compile_catalog(&catalog);
        fs::create_dir_all(&output)
            .map_err(|error| format!("could not create {}: {error}", output.display()))?;
        for (name, source) in [
            ("win16_exports.rs", generated.metadata),
            ("win16_bindings.rs", generated.bindings),
        ] {
            let path = output.join(name);
            fs::write(&path, source)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        }
        println!(
            "generated {} declarations and {} bindings in {}",
            catalog.exports().count(),
            catalog.exports().filter(|(_, export)| export.binding.is_some()).count(),
            output.display()
        );
    } else if let Some(name) = module_name {
        let module = catalog.module(&name).ok_or_else(|| format!("unknown catalog module `{name}`"))?;
        inspect_module(&catalog, module);
    } else {
        for module in &catalog.catalog().modules {
            inspect_module(&catalog, module);
        }
    }
    Ok(())
}

fn run_probe_command(args: impl Iterator<Item = OsString>) -> Result<(), String> {
    let mut output = None;
    let mut format = ProbeFormat::Com;
    let mut format_seen = false;
    parse_options(args, |key, value| match key {
        "--output" => set_once(&mut output, PathBuf::from(value), key),
        "--format" => {
            if format_seen {
                return Err("duplicate --format option".to_owned());
            }
            format_seen = true;
            let value = value
                .into_string()
                .map_err(|_| "--format value must be valid Unicode".to_owned())?;
            format = match value.as_str() {
                "com" => ProbeFormat::Com,
                "mz" => ProbeFormat::Mz,
                _ => return Err("--format must be `com` or `mz`".to_owned()),
            };
            Ok(())
        }
        _ => Err(format!("unknown option `{key}`")),
    })?;

    let output = output.ok_or_else(|| format!("probe requires --output\n{}", usage()))?;
    let image = dos_probe_bytes(format).map_err(|error| error.to_string())?;
    fs::write(&output, &image)
        .map_err(|error| format!("could not write {}: {error}", output.display()))?;
    let kind = match format {
        ProbeFormat::Com => "COM",
        ProbeFormat::Mz => "MZ",
    };
    println!(
        "generated {kind} DOS probe ({} bytes); it writes RSPROOF.TXT and exits 0 only after the write and close succeed",
        image.len()
    );
    Ok(())
}

fn run_vga_probe_command(args: impl Iterator<Item = OsString>) -> Result<(), String> {
    let mut output = None;
    parse_options(args, |key, value| match key {
        "--output" => set_once(&mut output, PathBuf::from(value), key),
        _ => Err(format!("unknown option `{key}`")),
    })?;

    let output = output.ok_or_else(|| format!("vga-probe requires --output\n{}", usage()))?;
    let image = vga_probe_bytes().map_err(|error| error.to_string())?;
    fs::write(&output, &image)
        .map_err(|error| format!("could not write {}: {error}", output.display()))?;
    println!(
        "generated VGA COM fixture ({} bytes); it writes {} only after its guest VGA checks pass",
        image.len(),
        VGA_PROBE_FILE_NAME
    );
    Ok(())
}

fn parse_options(
    mut args: impl Iterator<Item = OsString>,
    mut handle: impl FnMut(&str, OsString) -> Result<(), String>,
) -> Result<(), String> {
    while let Some(option) = args.next() {
        let key = option
            .to_str()
            .ok_or_else(|| "option name is not valid Unicode".to_owned())?;
        if !key.starts_with("--") {
            return Err(format!("expected an option, found `{key}`"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after `{key}`"))?;
        handle(key, value)?;
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate {option} option"));
    }
    *slot = Some(value);
    Ok(())
}

fn inspect_module(catalog: &ValidatedCatalog, module: &Module) {
    let exports = catalog.exports().filter(|(_, export)| export.module == module.id);
    println!(
        "module {:?} source_module={:?} aliases={:?}",
        module.id, module.source_module, module.aliases
    );
    for (path, export) in exports {
        println!(
            "source={path:?} ordinal={} ordinal_source={:?} declared_name={:?} name={:?} aliases={:?} architecture={:?}",
            export.ordinal, export.ordinal_source, export.declared_name, export.name,
            export.aliases, export.architecture
        );
        println!("  entry={:?} binding={:?}", export.entry, export.binding);
        println!("  declaration_evidence={:?}", export.declaration);
        println!("  provenance={:?}", export.evidence);
    }
}

fn usage() -> String {
    let command = std::env::current_exe().ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "build-tools".to_owned());
    format!("usage:\n  {command} inspect --catalog DIR [--module NAME]\n  {command} generate --catalog DIR --output OUT_DIR\n  {command} audit-win16 --catalog DIR --module NAME\n  {command} probe --output FILE [--format com|mz]\n  {command} vga-probe --output FILE\n\nDIR must contain catalog.toml (compact TOML v2); indexed groups and shared types are TOML files.")
}
