#![forbid(unsafe_code)]

//! Process execution entry owned by the native core module.

use runtime::{DiagnosticKind as Kind, RuntimeError};

#[cfg(windows)]
#[path = "diagnostics.rs"]
mod diagnostics;

#[cfg(windows)]
#[path = "dos_version.rs"]
mod dos_version;

pub fn entry() -> i32 {
    match run() {
        Ok(code) => i32::from(code),
        Err(error) => { eprintln!("runtime: {error}"); 125 }
    }
}

#[cfg(not(windows))]
fn run() -> Result<u8, RuntimeError> {
    Err(RuntimeError::new(Kind::CompatibilityGap, "this launcher currently requires Windows"))
}

#[cfg(windows)]
fn run() -> Result<u8, RuntimeError> {
    let child = host_services::windows::GuestChildLaunch::from_process_arguments()?;
    let result = run_program(child.as_ref());
    if let (Some(child), Err(error)) = (&child, &result) { child.report_failure(error); }
    if let (Some(child), Ok(_)) = (&child, &result) { child.reporter().ready()?; }
    result
}

#[cfg(windows)]
fn run_program(child: Option<&host_services::windows::GuestChildLaunch>) -> Result<u8, RuntimeError> {
    use std::path::PathBuf;
    use formats::parse_ne;
    use host_services::windows::{encode, ConsolePolicy, WindowsHost};
    use runtime::{Diagnostic, Runtime, RuntimeHost};

    let command_name = std::env::current_exe().ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "launcher".to_owned());
    let system_launch = if child.is_some() { None } else { crate::system_launch::parse(
        &host_services::windows::current_command_line()?,
    )? };
    let mut arguments = std::env::args_os().skip(1);
    // Interactive applications may wait indefinitely for input. An execution
    // budget is a diagnostic option, not the default process lifetime.
    let mut limit = u64::MAX;
    let mut code_page = child.map_or(437, |child| child.dos_code_page);
    let mut dos_reported_version = None;
    let mut ansi_code_page = child.map(|child| child.ansi_code_page);
    let mut explicit_command_tail = None;
    let mut working_directory = None;
    let mut program = child.map(|child| child.program.clone())
        .or_else(|| system_launch.as_ref().map(|launch| launch.program.clone()));
    let mut trace_on_failure = false;
    let mut trace_file = None;
    let mut memory_watch = None;
    let mut win16_memory_watch = None;
    let mut guest_memory_dump = None;
    let mut dos_service_trace = None;
    let mut win16_io_trace = None;
    let mut complete_win16_io_trace = false;
    let mut execution_engine = if child.is_some_and(|child| child.interpreter) {
        runtime::ExecutionEngine::Interpreter
    } else { runtime::ExecutionEngine::Jit };
    let mut jit_stats = false;
    let mut jit_cache = child.is_none_or(|child| child.jit_cache);
    while child.is_none() && system_launch.is_none() {
        let Some(argument) = arguments.next() else { break; };
        match argument.to_str() {
            Some("--command-tail") => {
                explicit_command_tail = Some(arguments.next().and_then(|value| value.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing command tail"))?);
            }
            Some("--working-directory") => {
                working_directory = Some(PathBuf::from(arguments.next()
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing working directory"))?));
            }
            Some("--cpu-engine") => {
                execution_engine = match arguments.next().as_deref().and_then(|text| text.to_str()) {
                    Some("jit") => runtime::ExecutionEngine::Jit,
                    Some("interpreter") => runtime::ExecutionEngine::Interpreter,
                    _ => return Err(RuntimeError::new(Kind::InvalidInput,
                        "--cpu-engine requires jit or interpreter")),
                };
            }
            Some("--jit-stats") => jit_stats = true,
            Some("--no-jit-cache") => jit_cache = false,
            Some("--trace-on-failure") => trace_on_failure = true,
            Some("--trace-file") => {
                trace_file = Some(PathBuf::from(arguments.next()
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing trace file path"))?));
                trace_on_failure = true;
            }
            Some("--watch-memory") => {
                let value = arguments.next().and_then(|v| v.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                        "missing guest memory watch range (expected ADDRESS:LENGTH)"))?;
                memory_watch = Some(parse_memory_watch_range(&value)?);
            }
            Some("--watch-win16-memory") => {
                let value = arguments.next().and_then(|v| v.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                        "missing selector memory watch (SELECTOR:OFFSET:LENGTH)"))?;
                let (selector, range) = value.split_once(':').ok_or_else(|| RuntimeError::new(
                    Kind::InvalidInput, "selector memory watch requires SELECTOR:OFFSET:LENGTH"))?;
                let selector = parse_watch_integer(selector).map_err(|error| RuntimeError::with_source(
                    Kind::InvalidInput, "invalid watch selector", error))?;
                let (offset, length) = parse_memory_watch_range(range)?;
                let narrow = |value| u16::try_from(value).map_err(|error| RuntimeError::with_source(
                    Kind::InvalidInput, "watch selector and offset must fit 16 bits", error));
                win16_memory_watch = Some((narrow(selector)?, narrow(offset)?, length));
            }
            Some("--dump-guest-memory") => {
                guest_memory_dump = Some(PathBuf::from(arguments.next()
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                        "missing guest memory dump path"))?));
            }
            Some("--trace-dos-services") => {
                dos_service_trace = Some(PathBuf::from(arguments.next()
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                        "missing DOS service trace path"))?));
            }
            Some("--trace-win16-io") | Some("--trace-win16-io-complete") => {
                complete_win16_io_trace = argument.to_str() == Some("--trace-win16-io-complete");
                win16_io_trace = Some(PathBuf::from(arguments.next()
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                        "missing Win16 I/O trace path"))?));
            }
            Some("--max-instructions") => {
                limit = arguments.next().and_then(|v| v.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing instruction limit"))?
                    .parse().map_err(|e| RuntimeError::with_source(Kind::InvalidInput, "invalid instruction limit", e))?;
                if limit == 0 { return Err(RuntimeError::new(Kind::InvalidInput, "instruction limit must be positive")); }
            }
            Some("--dos-version") => {
                let text = arguments.next().and_then(|value| value.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing DOS version"))?;
                dos_reported_version = Some(dos_version::parse(&text)?);
            }
            Some("--code-page") => {
                code_page = arguments.next().and_then(|v| v.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing code page"))?
                    .parse().map_err(|e| RuntimeError::with_source(Kind::InvalidInput, "invalid code page", e))?;
                if !matches!(code_page, 437 | 936) { return Err(RuntimeError::new(Kind::InvalidInput, "supported guest code pages: 437, 936")); }
            }
            Some("--win16-code-page") => {
                let value = arguments.next().and_then(|v| v.into_string().ok())
                    .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "missing Win16 ANSI code page"))?;
                ansi_code_page = if value == "auto" { None } else { Some(value.parse::<u32>()
                    .map_err(|error| RuntimeError::with_source(Kind::InvalidInput, "invalid Win16 ANSI code page", error))?) };
            }
            Some("--help") | Some("-h") => {
                println!("{command_name} [--max-instructions N] [--cpu-engine jit|interpreter] [--jit-stats] [--no-jit-cache] [--code-page 437|936] [--dos-version MAJOR.MINOR] [--win16-code-page auto|N] [--trace-on-failure] [--trace-file PATH] [--watch-memory ADDRESS:LENGTH | --watch-win16-memory SELECTOR:OFFSET:LENGTH] [--dump-guest-memory PATH] [--trace-dos-services PATH] [--trace-win16-io PATH | --trace-win16-io-complete PATH] PROGRAM [DOS arguments]\nExample: --watch-memory 0x10000:16\nDOS/Win16 development runtime: COM/MZ and early NE execution; compatibility coverage is incomplete.");
                println!("Launch options: --command-tail TEXT preserves program argument quotes and spacing; --working-directory PATH selects the initial directory.");
                return Ok(0);
            }
            Some(value) if value.starts_with('-') => return Err(RuntimeError::new(Kind::InvalidInput, format!("unknown option {value}"))),
            _ => { program = Some(PathBuf::from(argument)); break; }
        }
    }
    let program = program.ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
        format!("usage: {command_name} PROGRAM [DOS arguments]")))?
        .canonicalize().map_err(|e| RuntimeError::with_source(Kind::HostFailure, "resolve program path", e))?;
    let bytes = if let Some(child) = child { std::borrow::Cow::Borrowed(child.image.as_slice()) } else {
        std::borrow::Cow::Owned(std::fs::read(&program)
            .map_err(|e| RuntimeError::with_source(Kind::HostFailure, "read program image", e))?)
    };
    let is_win16 = parse_ne(&bytes).is_ok();
    if child.is_some() && parse_ne(&bytes).is_ok_and(|module|
        module.header.flags & 0x8000 != 0 || module.header.target_os != 2) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "WinExec requires a Windows executable, not a library or another NE target"));
    }
    let text_profile = crate::program_encoding::resolve(&bytes, ansi_code_page);
    let ansi_code_page = text_profile.as_ref().map(|profile| profile.selection.code_page)
        .unwrap_or(if code_page == 936 { 936 } else { 1252 });
    // Win16 lpCmdLine uses Windows ANSI; a DOS PSP tail uses OEM. Internal
    // WinExec requests already carry the caller's encoded command tail.
    let tail = if let Some(child) = child {
        child.command_tail.clone()
    } else {
        let command = if let Some(launch) = system_launch {
            String::from_utf16(&launch.command).map_err(|error|
                RuntimeError::with_source(Kind::InvalidInput, "system command contains invalid UTF-16", error))?
        } else {
            crate::launch_options::command_text(explicit_command_tail, arguments)?
        };
        if is_win16 {
            host_services::windows::encode_ansi(&command, ansi_code_page)?
        } else {
            encode(&command, code_page).map_err(|error|
                RuntimeError::with_source(Kind::InvalidInput, "command encoding", error))?
        }
    };
    let working_directory = working_directory.map(|path| {
        let path = path.canonicalize().map_err(|error| RuntimeError::with_source(
            Kind::HostFailure, "resolve working directory", error))?;
        if !path.is_dir() {
            return Err(RuntimeError::new(Kind::InvalidInput, "working directory is not a directory"));
        }
        Ok(path)
    }).transpose()?;
    // Preserve the caller's output paths before host initialization establishes
    // the guest program's working directory for native relative file APIs.
    for path in [&mut trace_file, &mut guest_memory_dump, &mut dos_service_trace, &mut win16_io_trace] {
        if let Some(value) = path {
            *value = std::path::absolute(&*value).map_err(|error| RuntimeError::with_source(
                Kind::HostFailure, "resolve diagnostic output path", error))?;
        }
    }
    let directory = if let Some(child) = child { child.directory.as_path() } else {
        working_directory.as_deref().unwrap_or(program.parent().ok_or_else(||
            RuntimeError::new(Kind::InvalidInput, "program has no parent directory"))?)
    };
    // Declared first so every runtime/host owner retires before the executor.
    let work = std::sync::Arc::new(parallel_work::BoundedExecutor::new());
    let console_policy = if is_win16 { ConsolePolicy::Inherit } else { ConsolePolicy::AllocateIfMissing };
    let mut host = WindowsHost::new_with_console_policy(
        directory, code_page, ansi_code_page, console_policy,
    ).map_err(|e| RuntimeError::with_source(Kind::HostFailure, "host initialization", e))?;
    host.set_child_execution_options(execution_engine == runtime::ExecutionEngine::Interpreter, jit_cache);
    if let Some(child) = child { host.set_program_load_reporter(child.reporter()); }
    host.set_work_executor(std::sync::Arc::clone(&work));
    if let Some(profile) = &text_profile {
        crate::program_encoding::report(&mut host, profile);
    }
    if let Some(path) = &dos_service_trace { host.enable_dos_service_trace(path)?; }
    if let Some(path) = &win16_io_trace {
        host.enable_win16_io_trace(path, complete_win16_io_trace)?;
    }
    let virtual_path = host.dos_program_path(&program).map_err(|error|
        RuntimeError::with_source(Kind::HostFailure, "map executable to its DOS path", error))?;
    let environment = if let Some(child) = child { child.environment.clone() } else {
    let (environment, environment_report) = host.inherited_environment()
        .map_err(|error| RuntimeError::with_source(Kind::HostFailure, "inherit DOS process environment", error))?;
    let replacement_count = environment_report.replacement_entries;
    if replacement_count != 0 {
        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
            "{replacement_count} inherited environment entries contain characters unavailable in code page {code_page}; Windows substituted default characters",
        )));
    }
    environment
    };
    let mut runtime = if is_win16 {
        let win16_path = host.win16_main_module_path(&program)?;
        // Guest instructions and native API calls have separate execution
        // boundaries. Host bitness alone does not establish a usable generic
        // thunk backend or authorize publishing native guest-memory addresses.
        Runtime::load_with_storage(
            &bytes, &tail, &virtual_path, &win16_path, &environment, None,
        )?
    } else {
        Runtime::load_with_environment(&bytes, &tail, &virtual_path, &environment)?
    };
    if is_win16 {
        if let Some(child) = child { runtime.set_win16_startup_show_command(child.show)?; }
    }
    runtime.set_work_executor(std::sync::Arc::clone(&work))?;
    runtime.set_execution_engine(execution_engine);
    if let Some(version) = dos_reported_version { runtime.set_dos_reported_version(version)?; }
    if jit_cache && execution_engine == runtime::ExecutionEngine::Jit {
        runtime.set_jit_artifact_store(host.jit_artifact_store());
    }
    if trace_on_failure { runtime.enable_instruction_trace()?; }
    if let Some((address, length)) = memory_watch {
        runtime.watch_guest_memory(address, length)?;
    }
    if let Some((selector, offset, length)) = win16_memory_watch {
        if memory_watch.is_some() {
            return Err(RuntimeError::new(Kind::InvalidInput, "choose one memory watch range"));
        }
        runtime.watch_win16_memory(selector, offset, length)?;
    }
    if !is_win16 {
        if let Some(child) = child { child.reporter().report(Ok(()))?; }
    }
    let result = runtime.run(&mut host, limit).map_err(|e| {
        let progress = runtime.progress();
        let error = e.with_context(format!("after {} instructions, CS:IP={:04X}:{:04X}",
            progress.instructions, progress.code_segment, progress.instruction_pointer));
        if let Some(path) = &guest_memory_dump {
            match runtime.snapshot_guest_memory() {
                Ok(snapshot) => match diagnostics::save_guest_memory(path, &snapshot) {
                    Ok(()) => host.report_diagnostic(&Diagnostic::info(error.kind(), format!(
                        "guest memory snapshot saved to {} ({} bytes)", path.display(), snapshot.len(),
                    ))),
                    Err(cause) => host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                        "could not save guest memory snapshot").with_cause(cause)),
                },
                Err(cause) => host.report_diagnostic(&Diagnostic::warning(cause.kind(),
                    "could not capture guest memory snapshot").with_cause(cause)),
            }
        }
        let mut evidence = String::new();
        if let Some(trace) = runtime.format_instruction_trace() {
            if !trace.is_empty() {
                evidence.push_str("instruction history (oldest first):\n");
                evidence.push_str(&trace);
            }
        }
        let memory_watch_report = runtime.format_memory_write_watch();
        if let Some(watch) = &memory_watch_report {
            evidence.push_str("guest memory write watch (first plus recent changes):\n");
            evidence.push_str(watch);
        }
        if trace_on_failure || memory_watch_report.is_some() {
            let report = Diagnostic::info(error.kind(), format!("execution evidence:\n{evidence}"));
            if let Some(path) = &trace_file {
                match diagnostics::save(path, &report, &error) {
                    Ok(()) => host.report_diagnostic(&Diagnostic::info(error.kind(),
                        format!("detailed diagnostics saved to {}", path.display()))),
                    Err(cause) => {
                        host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                            "could not save instruction trace; retaining console diagnostics").with_cause(cause));
                        host.report_diagnostic(&report);
                    }
                }
            } else {
                // Console traces are explicitly requested by
                // --trace-on-failure or --watch-memory without a destination file.
                host.report_diagnostic(&report);
            }
        }
        error
    })?;
    if result != 0 && (trace_on_failure || memory_watch.is_some() || win16_memory_watch.is_some()) {
        if let Some(mut trace) = runtime.format_instruction_trace() {
            if let Some(watch) = runtime.format_memory_write_watch() {
                trace.push_str("\nguest memory write watch:\n");
                trace.push_str(&watch);
            }
            if let Some(path) = &trace_file {
                if let Err(error) = diagnostics::save_guest_exit(path, result, &trace) {
                    host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                        "could not save requested guest exit history").with_cause(error));
                    eprintln!("guest exit status: {result}\ninstruction history:\n{trace}");
                }
            } else {
                eprintln!("guest exit status: {result}\ninstruction history:\n{trace}");
            }
        }
    }
    host.finish_native_windows()?;
    if jit_stats {
        let stats = runtime.jit_statistics();
        eprintln!("active CPU JIT: compiled={} executed={} failures={} cache_resets={}",
            stats.compiled, stats.executed, stats.failures, stats.cache_resets);
        eprintln!("JIT blocks: compiled={} executed={} checkpoints={} invalidations={} persistent_hits={} persistent_writes={}",
            stats.blocks_compiled, stats.blocks_executed, stats.checkpoint_hits, stats.block_invalidations,
            stats.persistent_hits, stats.persistent_writes);
        eprintln!("JIT loops: compiled={} executed={} iterations={}",
            stats.loops_compiled, stats.loops_executed, stats.loop_iterations);
        eprintln!("JIT guest branches: taken={} fallthrough={} budget_exits={} window_exits={} loop_dispatch_hits={}",
            stats.branches_taken, stats.branches_fallthrough, stats.budget_exits,
            stats.memory_window_exits, stats.loop_dispatch_hits);
        eprintln!("JIT memory loops: compiled={} executed={} instructions={}",
            stats.memory_loops_compiled, stats.memory_loops_executed, stats.memory_instructions);
        eprintln!("JIT linked regions: compiled={} executed={} instructions={} direct_links={}",
            stats.regions_compiled, stats.regions_executed, stats.region_instructions, stats.direct_links);
        eprintln!("JIT x87 blocks: compiled={} executed={} instructions={}",
            stats.float_blocks_compiled, stats.float_blocks_executed, stats.float_block_instructions);
        eprintln!("JIT x87: compiled={} executed={} fallbacks={}",
            stats.float_compiled, stats.float_executed, stats.float_fallbacks);
    }
    host.finish_output().map_err(|e| RuntimeError::with_source(Kind::HostFailure, "incomplete console output", e))?;
    Ok(result)
}

#[cfg(windows)]
fn parse_memory_watch_range(value: &str) -> Result<(u32, u32), RuntimeError> {
    let Some((address, length)) = value.split_once(':') else {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "guest memory watch range must be ADDRESS:LENGTH (for example 0x10000:16)"));
    };
    if address.contains(':') || length.contains(':') {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "guest memory watch range must contain exactly one colon"));
    }
    let address = parse_watch_integer(address).map_err(|error| {
        RuntimeError::with_source(Kind::InvalidInput, "invalid guest memory watch address", error)
    })?;
    let length = parse_watch_integer(length).map_err(|error| {
        RuntimeError::with_source(Kind::InvalidInput, "invalid guest memory watch length", error)
    })?;
    Ok((address, length))
}

#[cfg(windows)]
fn parse_watch_integer(value: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
}
