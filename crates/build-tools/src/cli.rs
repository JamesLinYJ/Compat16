use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use build_tools::{
    audit_win16_module, dos_probe_bytes, generate_rust, parse_spec, vga_probe_bytes,
    win16_dialog_probe_bytes, win16_font_families_probe_bytes, win16_modeless_probe_bytes,
    win16_user_queries_probe_bytes, win16_outline_metrics_probe_bytes,
    win16_local_handle_delta_probe_bytes,
    ProbeFormat, SpecEntry, SpecModule, VGA_PROBE_FILE_NAME,
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
            run_spec_command(false, args)?;
            Ok(ExitCode::SUCCESS)
        }
        "generate" => {
            run_spec_command(true, args)?;
            Ok(ExitCode::SUCCESS)
        }
        "audit-win16" => run_audit_win16_command(args),
        "probe" => {
            run_probe_command(args)?;
            Ok(ExitCode::SUCCESS)
        }
        "win16-dialog-probe" => {
            run_win16_probe_command("win16-dialog-probe", args)?;
            Ok(ExitCode::SUCCESS)
        }
        "win16-modeless-probe" => {
            run_win16_probe_command("win16-modeless-probe", args)?;
            Ok(ExitCode::SUCCESS)
        }
        "win16-font-families-probe" => {
            run_win16_probe_command("win16-font-families-probe", args)?;
            Ok(ExitCode::SUCCESS)
        }
        "win16-user-queries-probe" => {
            run_win16_probe_command("win16-user-queries-probe", args)?;
            Ok(ExitCode::SUCCESS)
        }
        "win16-outline-metrics-probe" => {
            run_win16_probe_command("win16-outline-metrics-probe", args)?;
            Ok(ExitCode::SUCCESS)
        }
        "win16-local-handle-delta-probe" => {
            run_win16_probe_command("win16-local-handle-delta-probe", args)?;
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
    let mut spec_path = None;
    parse_options(args, |key, value| match key {
        "--module" => {
            let value = value
                .into_string()
                .map_err(|_| "--module value must be valid Unicode".to_owned())?;
            set_once(&mut module, value, key)
        }
        "--spec" => set_once(&mut spec_path, PathBuf::from(value), key),
        _ => Err(format!("unknown option `{key}`")),
    })?;

    let module = module.ok_or_else(|| format!("audit-win16 requires --module\n{}", usage()))?;
    let spec_path = spec_path.ok_or_else(|| format!("audit-win16 requires --spec\n{}", usage()))?;
    let descriptors = export_descriptors();
    let canonical_module = descriptors
        .iter()
        .find(|descriptor| module_matches(&module, descriptor.module()))
        .map(|descriptor| descriptor.module())
        .ok_or_else(|| {
            format!(
                "unknown Win16 module `{module}`; use a catalog module such as KERNEL, USER, GDI, KEYBOARD, TOOLHELP, or WIN87EM"
            )
        })?;

    let source = fs::read_to_string(&spec_path)
        .map_err(|error| format!("could not read {}: {error}", spec_path.display()))?;
    let spec = parse_spec(&source, canonical_module)
        .map_err(|error| format!("{}: {error}", spec_path.display()))?;
    let report = audit_win16_module(canonical_module, &spec, descriptors);

    println!("# input_spec={}", tsv_field(&spec_path.display().to_string()));
    print!("{}", report.to_tsv());
    if report.has_differences() {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn module_matches(input: &str, expected: &str) -> bool {
    let input = input.trim();
    let module_stem = strip_ascii_suffix(input, ".EXE")
        .or_else(|| strip_ascii_suffix(input, ".DLL"))
        .unwrap_or(input);
    module_stem.eq_ignore_ascii_case(expected)
}

fn strip_ascii_suffix<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let start = value.len().checked_sub(suffix.len())?;
    if !value.is_char_boundary(start) {
        return None;
    }
    value[start..]
        .eq_ignore_ascii_case(suffix)
        .then_some(&value[..start])
}

fn tsv_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn run_spec_command(
    is_generate: bool,
    args: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    let mut input = None;
    let mut output = None;
    let mut module_name = None;

    parse_options(args, |key, value| match key {
        "--input" => set_once(&mut input, PathBuf::from(value), key),
        "--output" => set_once(&mut output, PathBuf::from(value), key),
        "--module" => {
            let module = value
                .into_string()
                .map_err(|_| "--module value must be valid Unicode".to_owned())?;
            set_once(&mut module_name, module, key)
        }
        _ => Err(format!("unknown option `{key}`")),
    })?;

    let input = input.ok_or_else(|| format!("missing --input\n{}", usage()))?;
    let module_name = module_name.ok_or_else(|| format!("missing --module\n{}", usage()))?;
    if is_generate && output.is_none() {
        return Err(format!("generate requires --output\n{}", usage()));
    }
    if is_generate && output.as_ref().is_some_and(|path| path == &input) {
        return Err("--output must not be the same path as --input".to_owned());
    }
    if !is_generate && output.is_some() {
        return Err("inspect does not accept --output".to_owned());
    }

    let source = fs::read_to_string(&input)
        .map_err(|error| format!("could not read {}: {error}", input.display()))?;
    let module = parse_spec(&source, module_name)
        .map_err(|error| format!("{}: {error}", input.display()))?;

    if is_generate {
        let output_path = output.ok_or_else(|| "generate requires --output".to_owned())?;
        let generated = generate_rust(&module);
        fs::write(&output_path, generated)
            .map_err(|error| format!("could not write {}: {error}", output_path.display()))?;
        println!(
            "generated {} metadata entries for {} in {}",
            module.exports.len(),
            module.original_module_name,
            output_path.display()
        );
    } else {
        inspect_module(&module);
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

fn run_win16_probe_command(
    command: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    let mut output = None;
    parse_options(args, |key, value| match key {
        "--output" => set_once(&mut output, PathBuf::from(value), key),
        _ => Err(format!("unknown option `{key}`")),
    })?;
    let output = output.ok_or_else(|| format!("{command} requires --output\n{}", usage()))?;
    let image = match command {
        "win16-local-handle-delta-probe" => win16_local_handle_delta_probe_bytes(),
        "win16-user-queries-probe" => win16_user_queries_probe_bytes(),
        "win16-outline-metrics-probe" => win16_outline_metrics_probe_bytes(),
        "win16-modeless-probe" => win16_modeless_probe_bytes(),
        "win16-font-families-probe" => win16_font_families_probe_bytes(),
        _ => win16_dialog_probe_bytes(),
    }.map_err(|error| error.to_string())?;
    fs::write(&output, &image)
        .map_err(|error| format!("could not write {}: {error}", output.display()))?;
    println!("generated {command} hidden NE fixture ({} bytes)", image.len());
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

fn inspect_module(module: &SpecModule) {
    println!(
        "module {:?}: {} declarations",
        module.original_module_name,
        module.exports.len()
    );
    for entry in &module.exports {
        inspect_entry(entry);
    }
}

fn inspect_entry(entry: &SpecEntry) {
    let ordinal = match entry.ordinal {
        build_tools::Ordinal::Explicit(value) => value.to_string(),
        build_tools::Ordinal::Automatic => "@".to_owned(),
    };
    let kind = format!("{:?}", entry.kind).to_lowercase();
    let convention = entry
        .convention
        .map(|value| value.as_spec_name().to_owned())
        .unwrap_or_else(|| "-".to_owned());
    let arguments = entry
        .arguments
        .iter()
        .map(|value| value.as_spec_name())
        .collect::<Vec<_>>()
        .join(",");
    let alias = entry
        .implementation_name
        .as_deref()
        .map(|name| format!(" implementation={name:?}"))
        .unwrap_or_default();
    let values = if entry.values.is_empty() {
        String::new()
    } else {
        format!(" values={:?}", entry.values)
    };
    println!(
        "line={} ordinal={} kind={} convention={} name={:?} args=[{}] flags={:?}{}{}",
        entry.source_line,
        ordinal,
        kind,
        convention,
        entry.export_name,
        arguments,
        entry.flags,
        alias,
        values
    );
}

fn usage() -> String {
    let command = std::env::current_exe().ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "build-tools".to_owned());
    format!("usage:\n  {command} inspect --input FILE --module ORIGINAL_NAME\n  {command} generate --input FILE --module ORIGINAL_NAME --output FILE\n  {command} audit-win16 --module USER --spec FILE\n  {command} probe --output FILE [--format com|mz]\n  {command} vga-probe --output FILE\n  {command} win16-dialog-probe --output FILE\n  {command} win16-modeless-probe --output FILE\n  {command} win16-font-families-probe --output FILE\n  {command} win16-outline-metrics-probe --output FILE\n  {command} win16-user-queries-probe --output FILE\n  {command} win16-local-handle-delta-probe --output FILE")
}
