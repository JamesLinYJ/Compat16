//! Runtime diagnostic forwarding for native host traces.

use super::*;

pub(super) fn read_win16_module(
    host: &mut WindowsHost,
    name: &[u8],
    application_path: &[u8],
) -> Result<Result<runtime::Win16ModuleImage, u16>, RuntimeError> {
    let result =
        win16_module_files::read_module(host.win16_dcs.text_codec(), name, application_path);
    // Observe the existing owned image only when the optional trace is active.
    // No repeated search, extra file read or native LastError query is needed.
    if host.win16_io_trace.is_some() {
        observe_win16_io(
            host,
            &runtime::Win16IoEvent::ModuleSearch {
                name,
                result: &result,
            },
        );
    }
    result
}

pub(super) fn read_win16_task_module(
    host: &mut WindowsHost,
    name: &[u8],
    application_path: &[u8],
    path: &runtime::Win16GuestPath,
) -> Result<Result<runtime::Win16ModuleImage, u16>, RuntimeError> {
    let result = win16_module_files::read_task_module(
        host.win16_dcs.text_codec(), &mut host.filesystem, name, application_path, path);
    if host.win16_io_trace.is_some() {
        observe_win16_io(host, &runtime::Win16IoEvent::ModuleSearch { name, result: &result });
    }
    result
}

pub(super) fn observe_win16_io(host: &mut WindowsHost, event: &runtime::Win16IoEvent<'_>) {
    let result = match host.win16_io_trace.as_mut() {
        Some(trace) => trace.record(event),
        None => return,
    };
    if let Err(error) = result {
        host.win16_io_trace = None;
        host.report_diagnostic(
            &Diagnostic::warning(
                Kind::HostFailure,
                "Win16 I/O trace write failed; tracing has been disabled",
            )
            .with_cause(error),
        );
    }
}

pub(super) fn observe_dos_service(
    host: &mut WindowsHost,
    instruction_count: u64,
    before: &runtime::GuestRegisters,
    after: &runtime::GuestRegisters,
) {
    let write_result = match host.dos_service_trace.as_mut() {
        Some(trace) => trace.record(instruction_count, before, after),
        None => return,
    };
    let reached_limit = host
        .dos_service_trace
        .as_ref()
        .is_some_and(service_trace::DosServiceTrace::is_full);
    if reached_limit {
        host.dos_service_trace = None;
    }
    if let Err(error) = write_result {
        host.dos_service_trace = None;
        host.report_diagnostic(
            &Diagnostic::warning(
                Kind::HostFailure,
                "DOS service trace write failed; tracing has been disabled",
            )
            .with_cause(error),
        );
    }
}
