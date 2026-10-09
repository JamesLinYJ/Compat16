//! Optional Win16 file, module lookup, resource, and service-boundary observations.

use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Win16ServiceBoundaryStage {
    DispatchEnter,
    DispatchReturn,
    DispatchError,
}

impl fmt::Display for Win16ServiceBoundaryStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DispatchEnter => "dispatch-enter",
            Self::DispatchReturn => "dispatch-return",
            Self::DispatchError => "dispatch-error",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowCreationApi {
    CreateWindow,
    CreateDialog,
}

impl fmt::Display for Win16WindowCreationApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CreateWindow => "CreateWindow",
            Self::CreateDialog => "CreateDialog",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Win16WindowCreationPhase {
    GuestApiCompleted,
}

impl fmt::Display for Win16WindowCreationPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GuestApiCompleted => "guest-api-completed",
        })
    }
}

impl fmt::Display for crate::Win16NativeWindowApiReturn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInvoked => "not-invoked",
            Self::ReturnedNull => "returned-null",
            Self::ReturnedWindow => "returned-window",
        })
    }
}

impl fmt::Display for crate::Win16WindowCreationRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NullProcedureRejectedByRuntime => "null-procedure-rejected-by-runtime",
            Self::GuestOwnerUnavailable => "guest-owner-unavailable",
            Self::GuestParentUnavailable => "guest-parent-unavailable",
            Self::GuestMenuUnavailable => "guest-menu-unavailable",
            Self::InvalidGuestCreationData => "invalid-guest-creation-data",
            Self::GuestTemplateUnavailable => "guest-template-unavailable",
            Self::UnsupportedControlCreationData => "unsupported-control-creation-data",
            Self::UnsupportedMenuResource => "unsupported-menu-resource",
            Self::UnsupportedControlTitleResource => "unsupported-control-title-resource",
            Self::GuestClassUnavailable => "guest-class-unavailable",
            Self::UnsupportedGuestClassRoute => "unsupported-guest-class-route",
            Self::UnsupportedClassMenuResource => "unsupported-class-menu-resource",
            Self::NativeOwnerUnavailable => "native-owner-unavailable",
            Self::NativeTemplateUnavailable => "native-template-unavailable",
            Self::NativeWindowClassUnavailable => "native-window-class-unavailable",
            Self::NativeParentUnavailable => "native-parent-unavailable",
            Self::NativeMenuUnavailable => "native-menu-unavailable",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Win16WindowCallbackProcedure {
    WindowProcedure,
    DialogProcedure,
}

impl fmt::Display for Win16WindowCallbackProcedure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WindowProcedure => "wndproc",
            Self::DialogProcedure => "dlgproc",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Win16WindowCallbackPhase {
    GuestEntry,
    GuestReturn,
}

impl fmt::Display for Win16WindowCallbackPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GuestEntry => "guest-entry",
            Self::GuestReturn => "guest-return",
        })
    }
}

/// Width-tagged Win16 callback result after guest return-stack validation.
/// WndProc returns LRESULT in AX:DX; DLGPROC returns BOOL in AX.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Win16WindowCallbackReturn {
    WindowProcedure(u32),
    DialogProcedure(u16),
}

/// Observation only: these values cannot change guest results or own resources.
pub enum Win16IoEvent<'a> {
    ModuleFileName { path: &'a [u8], copied: usize },
    DosOpenFailure { path: &'a [u8], error: u16 },
    ShellExecuteRequest {
        file: &'a [u8],
        parameters: Option<&'a [u8]>,
        directory: Option<&'a [u8]>,
    },
    ShellExecuteResult { value: u32 },
    WinExecRequest { command_line: &'a [u8], directory: &'a str, show: u16 },
    WinExecResult { value: u16, native_error: Option<u32> },
    Dialog {
        api: &'static str,
        caption: &'a [u8],
        text: &'a [u8],
    },
    TaskExit { status: u16 },
    /// Already decoded geometry, without additional guest reads or USER calls.
    WindowPositionRequest {
        window: u16,
        insert_after: u16,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        flags: u16,
    },
    /// Actual successful GetWindowRect/GetClientRect result already returned
    /// by the host; observation adds no USER call or guest-memory read.
    WindowRectResult {
        api: &'static str,
        window: u16,
        rect: crate::Win16HostRect,
    },
    /// Actual completed GDI metrics, borrowed before guest-wire projection.
    TextMetrics { dc: u16, dimensions: &'a [i32; 8] },
    /// Already decoded request; observing it performs no additional guest read.
    Pe32ThunkRequest {
        request: &'a win16_abi::generic_thunk::Win16GenericThunkRequest,
    },
    /// The actual search result, borrowed before ownership returns to runtime.
    ModuleSearch {
        name: &'a [u8],
        result: &'a Result<Result<crate::Win16ModuleImage, u16>, crate::RuntimeError>,
    },
    GenericThunk {
        operation: &'a crate::Win16ThunkOperation,
    },
    GenericThunkReturn {
        value: u32,
    },
    Api {
        module: &'static str,
        ordinal: u16,
        caller_selector: u16,
        caller_offset: u16,
    },
    /// A Win16 service-gate boundary; deliberately excludes guest arguments
    /// so an opt-in trace stays compact and does not inspect additional state.
    ServiceBoundary {
        module: &'a [u8],
        name: Option<&'a [u8]>,
        ordinal: Option<u16>,
        instruction: u64,
        selector: u16,
        offset: u16,
        stage: Win16ServiceBoundaryStage,
    },
    /// Creation completion couples the direct native API return state to the
    /// final Win16 handle. It deliberately carries no inferred failure cause.
    WindowCreation {
        api: Win16WindowCreationApi,
        phase: Win16WindowCreationPhase,
        native_return: crate::Win16NativeWindowApiReturn,
        preflight_rejection: Option<crate::Win16WindowCreationRejection>,
        class_instance: Option<u16>,
        window_class: Option<&'a win16_abi::Win16ClassName>,
        live_window: Option<crate::Win16HostWindow>,
        guest_window: u16,
        dialog_ncdestroy_observed: Option<bool>,
        dialog_template: Option<&'a win16_abi::Win16DialogTemplateRef>,
    },
    /// Guest callback observations bracket only checked WndProc/DLGPROC calls.
    /// DLGPROC's AX BOOL and DWLP_MSGRESULT stay separate values.
    WindowCallback {
        callback: u64,
        window: u16,
        procedure: Win16WindowCallbackProcedure,
        phase: Win16WindowCallbackPhase,
        message: u16,
        return_value: Option<Win16WindowCallbackReturn>,
        dialog_message_result: Option<u32>,
    },
    ProcedureLookup {
        module: &'a win16_abi::Win16ModuleReference,
        procedure: &'a win16_abi::Win16ProcReference,
        result: Option<u32>,
    },
    Open {
        path: &'a [u8],
        mode: u16,
        created: bool,
        result: Option<u16>,
    },
    LzOpen {
        path: &'a [u8],
        style: u16,
        result: u32,
        file: Option<u16>,
    },
    LzClose {
        file: u16,
        closed: bool,
        consumed_sources: &'a [u16],
    },
    Alias {
        operation: &'static str,
        source: u16,
        result: u32,
    },
    /// Already decoded selector words and the actual API result. The observer
    /// neither reads guest memory nor changes descriptor ownership or rights.
    SelectorChange {
        operation: &'static str,
        source: u16,
        destination: Option<u16>,
        result: &'a Result<u16, crate::RuntimeError>,
    },
    Copy {
        source: u16,
        destination: u16,
        result: u32,
    },
    Transfer {
        operation: &'static str,
        file: u16,
        buffer: u32,
        requested: i32,
        result: Option<u32>,
    },
    Seek {
        operation: &'static str,
        file: u16,
        offset: i32,
        origin: u16,
        result: Option<u32>,
    },
    Close {
        file: u16,
        result: Option<u32>,
    },
    Resource {
        operation: &'static str,
        module: u16,
        resource: u16,
        offset: usize,
        length: usize,
        data: u16,
    },
    ResourceResult {
        operation: &'static str,
        module: u16,
        resource: u16,
        value: u32,
    },
}

impl fmt::Display for Win16IoEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleFileName { path, copied } => {
                f.write_str("module-file-name path=")?;
                write_quoted(f, path)?;
                write!(f, " copied={copied}")
            }
            Self::DosOpenFailure { path, error } => {
                f.write_str("dos-open path=")?;
                write_quoted(f, path)?;
                write!(f, " error={error:04X}")
            }
            Self::ShellExecuteRequest { file, parameters, directory } => {
                f.write_str("shell-execute file=")?;
                write_quoted(f, file)?;
                f.write_str(" parameters=")?;
                match parameters { Some(value) => write_quoted(f, value)?, None => f.write_str("null")? };
                f.write_str(" directory=")?;
                match directory { Some(value) => write_quoted(f, value), None => f.write_str("null") }
            }
            Self::ShellExecuteResult { value } => write!(f, "shell-execute result={value}"),
            Self::WinExecRequest { command_line, directory, show } => {
                f.write_str("win-exec command=")?;
                write_quoted(f, command_line)?;
                write!(f, " directory={directory:?} show={show}")
            }
            Self::WinExecResult { value, native_error } =>
                write!(f, "win-exec result={value} native-error={native_error:?}"),
            Self::Dialog { api, caption, text } => {
                write!(f, "dialog api={api} caption=")?;
                write_quoted(f, caption)?;
                f.write_str(" text=")?;
                write_quoted(f, text)
            }
            Self::TaskExit { status } => write!(f, "guest-task-exit status={status}"),
            Self::WindowPositionRequest {
                window, insert_after, x, y, width, height, flags,
            } => write!(f,
                "window-position-request window={window:04X} insert-after={insert_after:04X} x={x} y={y} width={width} height={height} flags={flags:04X}"),
            Self::WindowRectResult { api, window, rect } => write!(f,
                "window-rect-result api={api} hwnd={window:04X} left={} top={} right={} bottom={}",
                rect.left, rect.top, rect.right, rect.bottom),
            Self::TextMetrics { dc, dimensions } => write!(f,
                "text-metrics dc={dc:04X} height={} ascent={} descent={} internal-leading={} external-leading={} average-width={} maximum-width={} weight={}",
                dimensions[0], dimensions[1], dimensions[2], dimensions[3],
                dimensions[4], dimensions[5], dimensions[6], dimensions[7]),
            Self::Pe32ThunkRequest { request } => write_pe32_thunk_request(f, request),
            Self::ModuleSearch { name, result } => {
                f.write_str("module-search name=")?;
                write_quoted(f, name)?;
                match result {
                    Ok(Ok(image)) => {
                        f.write_str(" resolved=")?;
                        write_quoted(f, &image.path)?;
                        write!(f, " bytes={}", image.image.len())?;
                        match formats::inspect_pe_header(&image.image) {
                            Some(header) => {
                                let kind = match header.kind {
                                    formats::PeHeaderKind::Pe32 => "PE32",
                                    formats::PeHeaderKind::Pe32Plus => "PE32+",
                                };
                                write!(f, " pe={kind} machine=0x{:04X} dll={}",
                                    header.machine, header.is_dll)
                            }
                            None => f.write_str(" pe-header=unavailable"),
                        }
                    }
                    Ok(Err(code)) => write!(f, " guest-error={code}"),
                    Err(error) => write!(f, " bridge-error={error}"),
                }
            }
            Self::GenericThunk { operation } => {
                use crate::Win16ThunkOperation as Operation;
                match operation {
                    Operation::LoadLibrary {
                        name,
                        reserved_hfile,
                        flags,
                    } => {
                        write!(
                            f,
                            "thunk-load flags=0x{flags:08X} hfile=0x{reserved_hfile:08X} name="
                        )?;
                        write_quoted(f, name)
                    }
                    Operation::FreeLibrary { module } => {
                        write!(f, "thunk-free module=0x{module:08X}")
                    }
                    Operation::GetProcAddress { module, name } => {
                        write!(f, "thunk-lookup module=0x{module:08X} name=")?;
                        write_quoted(f, name)
                    }
                    Operation::GetLinearAddress { guest_offset } => {
                        write!(f, "thunk-linear guest-offset=0x{guest_offset:08X}")
                    }
                    Operation::Call {
                        procedure,
                        convention,
                        arguments,
                    } => {
                        let convention = match convention {
                            crate::Win16ThunkConvention::Stdcall => "stdcall",
                            crate::Win16ThunkConvention::Cdecl => "cdecl",
                        };
                        write!(
                            f,
                            "thunk-call procedure=0x{procedure:08X} convention={convention} count={}",
                            arguments.len()
                        )
                    }
                }
            }
            Self::SelectorChange { operation, source, destination, result } => {
                write!(f, "selector-change operation={operation} source={source:04X} destination=")?;
                match destination {
                    Some(value) => write!(f, "{value:04X}")?,
                    None => f.write_str("none")?,
                }
                match result {
                    Ok(value) => write!(f, " result={value:04X}"),
                    Err(error) => write!(f, " bridge-error={error}"),
                }
            }
            Self::GenericThunkReturn { value } => write!(f, "thunk-return value=0x{value:08X}"),
            Self::Api {
                module,
                ordinal,
                caller_selector,
                caller_offset,
            } => {
                write!(
                    f,
                    "call {module}.{ordinal} caller={caller_selector:04X}:{caller_offset:04X}"
                )
            }
            Self::ServiceBoundary {
                module,
                name,
                ordinal,
                instruction,
                selector,
                offset,
                stage,
            } => {
                write!(f, "service-boundary stage={stage} module=")?;
                write_path(f, module)?;
                f.write_str(" name=")?;
                match name {
                    Some(name) => write_path(f, name)?,
                    None => f.write_str("-")?,
                }
                f.write_str(" ordinal=")?;
                match ordinal {
                    Some(ordinal) => write!(f, "{ordinal}")?,
                    None => f.write_str("-")?,
                }
                write!(
                    f,
                    " instruction={instruction} guest={selector:04X}:{offset:04X}"
                )
            }
            Self::WindowCreation {
                api,
                phase,
                native_return,
                preflight_rejection,
                class_instance,
                window_class,
                live_window,
                guest_window,
                dialog_ncdestroy_observed,
                dialog_template,
            } => {
                write!(f, "window-create api={api} phase={phase} native-return={native_return} preflight=")?;
                match preflight_rejection {
                    Some(rejection) => write!(f, "{rejection}")?,
                    None => f.write_str("none")?,
                }
                f.write_str(" window-class=")?;
                match (class_instance, window_class) {
                    (Some(instance), Some(class)) => write_window_class_reference(f, *instance, class)?,
                    _ => f.write_str("not-applicable")?,
                }
                f.write_str(" live-host-window=")?;
                match live_window {
                    Some(window) => write!(f, "{:016X}", window.0)?,
                    None => f.write_str("none")?,
                }
                write!(f, " guest-hwnd={guest_window:04X}")?;
                f.write_str(" dialog-ncdestroy-observed=")?;
                match dialog_ncdestroy_observed {
                    Some(destroyed) => write!(f, "{destroyed}"),
                    None => f.write_str("not-applicable"),
                }?;
                f.write_str(" template=")?;
                match dialog_template {
                    Some(reference) => write_dialog_template_reference(f, reference),
                    None => f.write_str("not-applicable"),
                }
            }
            Self::WindowCallback {
                callback,
                window,
                procedure,
                phase,
                message,
                return_value,
                dialog_message_result,
            } => {
                write!(f, "window-callback phase={phase} procedure={procedure} callback={callback} window={window:04X} message={message:04X} return=")?;
                match return_value {
                    Some(Win16WindowCallbackReturn::WindowProcedure(value)) => {
                        write!(f, "WNDPROC32:{value:08X}")
                    }
                    Some(Win16WindowCallbackReturn::DialogProcedure(value)) => {
                        write!(f, "DLGPROC16:{value:04X}")
                    }
                    None => f.write_str("pending"),
                }?;
                f.write_str(" dialog-msgresult=")?;
                match dialog_message_result {
                    Some(value) => write!(f, "{value:08X}"),
                    None => f.write_str("not-applicable"),
                }
            }
            Self::ProcedureLookup {
                module,
                procedure,
                result,
            } => {
                f.write_str("procedure-lookup module=")?;
                match module {
                    win16_abi::Win16ModuleReference::Current => f.write_str("current")?,
                    win16_abi::Win16ModuleReference::Handle(handle) => write!(f, "{handle:04X}")?,
                    win16_abi::Win16ModuleReference::Name(name) => write_quoted(f, name)?,
                }
                f.write_str(" procedure=")?;
                match procedure {
                    win16_abi::Win16ProcReference::Ordinal(ordinal) => write!(f, "#{ordinal}")?,
                    win16_abi::Win16ProcReference::Name(name) => write_quoted(f, name)?,
                }
                f.write_str(" result=")?;
                write_result(f, *result)
            }
            Self::Alias {
                operation,
                source,
                result,
            } => {
                write!(
                    f,
                    "{operation} source={source:04X} result={result} (0x{result:08X})"
                )
            }
            Self::Copy {
                source,
                destination,
                result,
            } => {
                write!(
                    f,
                    "lz-copy source={source:04X} destination={destination:04X} result={result} (0x{result:08X})"
                )
            }
            Self::Open {
                path,
                mode,
                created,
                result,
            } => {
                write!(
                    f,
                    "{} mode={mode:04X} path=\"",
                    if *created { "create" } else { "open" }
                )?;
                write_path(f, path)?;
                write!(f, "\" handle=")?;
                match result {
                    Some(handle) => write!(f, "{handle:04X}"),
                    None => f.write_str("bridge-error"),
                }
            }
            Self::LzOpen {
                path,
                style,
                result,
                file,
            } => {
                write!(f, "lz-open style={style:04X} path=\"")?;
                write_path(f, path)?;
                write!(f, "\" result={result} (0x{result:08X}) handle=")?;
                match file {
                    Some(number) => write!(f, "{number:04X}"),
                    None => f.write_str("none"),
                }
            }
            Self::LzClose {
                file,
                closed,
                consumed_sources,
            } => {
                write!(
                    f,
                    "lz-close handle={file:04X} closed={closed} consumed-sources="
                )?;
                for (index, source) in consumed_sources.iter().enumerate() {
                    if index != 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{source:04X}")?;
                }
                Ok(())
            }
            Self::Transfer {
                operation,
                file,
                buffer,
                requested,
                result,
            } => {
                write!(
                    f,
                    "{operation} handle={file:04X} buffer={:04X}:{:04X} requested={requested} result=",
                    buffer >> 16,
                    buffer & 0xffff
                )?;
                write_result(f, *result)
            }
            Self::Seek {
                operation,
                file,
                offset,
                origin,
                result,
            } => {
                write!(
                    f,
                    "{operation} handle={file:04X} offset={offset} origin={origin} result="
                )?;
                write_result(f, *result)
            }
            Self::Close { file, result } => {
                write!(f, "close handle={file:04X} result=")?;
                write_result(f, *result)
            }
            Self::Resource {
                operation,
                module,
                resource,
                offset,
                length,
                data,
            } => {
                write!(
                    f,
                    "{operation} module={module:04X} resource={resource:04X} image-offset={offset} length={length} data={data:04X}"
                )
            }
            Self::ResourceResult {
                operation,
                module,
                resource,
                value,
            } => {
                write!(
                    f,
                    "{operation} module={module:04X} resource={resource:04X} result={value} (0x{value:08X})"
                )
            }
        }
    }
}

fn write_quoted(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("\"")?;
    write_path(f, bytes)?;
    f.write_str("\"")
}

fn write_window_class_reference(
    f: &mut fmt::Formatter<'_>,
    instance: u16,
    class: &win16_abi::Win16ClassName,
) -> fmt::Result {
    write!(f, "{instance:04X}:")?;
    match class {
        win16_abi::Win16ClassName::Atom(atom) => write!(f, "atom:{atom:04X}"),
        win16_abi::Win16ClassName::Name(bytes) => {
            f.write_str("name=")?;
            write_quoted(f, bytes)
        }
    }
}

fn write_dialog_template_reference(
    f: &mut fmt::Formatter<'_>,
    reference: &win16_abi::Win16DialogTemplateRef,
) -> fmt::Result {
    match reference {
        win16_abi::Win16DialogTemplateRef::Resource { instance, name } => {
            write!(f, "resource:{instance:04X}:")?;
            match name {
                win16_abi::Win16ResourceName::Id(id) => write!(f, "#{id:04X}"),
                win16_abi::Win16ResourceName::Name(bytes) => write_quoted(f, bytes),
            }
        }
        win16_abi::Win16DialogTemplateRef::GlobalHandle { instance, template } => {
            write!(f, "global:{instance:04X}:{template:04X}")
        }
        win16_abi::Win16DialogTemplateRef::FarAddress { instance, template } => {
            write!(f, "far:{instance:04X}:{:04X}:{:04X}", template >> 16, template & 0xffff)
        }
    }
}

fn write_path(f: &mut fmt::Formatter<'_>, path: &[u8]) -> fmt::Result {
    // Escape ANSI and control bytes without changing the actual native path.
    for byte in path {
        match byte {
            b'"' | b'\\' => write!(f, "\\{}", char::from(*byte))?,
            0x20..=0x7e => write!(f, "{}", char::from(*byte))?,
            _ => write!(f, "\\x{byte:02X}")?,
        }
    }
    Ok(())
}

fn write_pe32_thunk_request(
    f: &mut fmt::Formatter<'_>,
    request: &win16_abi::generic_thunk::Win16GenericThunkRequest,
) -> fmt::Result {
    use win16_abi::generic_thunk::Win16GenericThunkRequest as Request;
    match request {
        Request::LoadLibraryEx32W { library_name, reserved_hfile, flags, .. } => {
            write!(f, "thunk-load flags=0x{flags:08X} hfile=0x{reserved_hfile:08X} name=")?;
            write_quoted(f, library_name)
        }
        Request::FreeLibrary32W { module_handle, .. } => {
            write!(f, "thunk-free module=0x{module_handle:08X}")
        }
        Request::GetProcAddress32W { module_handle, procedure_name, .. } => {
            write!(f, "thunk-lookup module=0x{module_handle:08X} name=")?;
            write_quoted(f, procedure_name)
        }
        Request::GetVDMPointer32W { address_far, mode, .. } => {
            write!(f, "thunk-pointer far=0x{address_far:08X} mode=0x{mode:04X}")
        }
        Request::CallProc32W(frame) | Request::CallProcEx32W(frame) => {
            let api = match frame.api {
                win16_abi::generic_thunk::Win16GenericThunkApi::CallProc32W => "CallProc32W",
                win16_abi::generic_thunk::Win16GenericThunkApi::CallProcEx32W => "CallProcEx32W",
            };
            write!(f, "thunk-call api={api} procedure=0x{:08X} count={} mask=0x{:08X}",
                frame.target_procedure, frame.parameter_count, frame.pointer_mask)
        }
    }
}

pub(crate) fn observes_io(request: &win16_abi::Win16ApiRequest) -> bool {
    use win16_abi::Win16ApiRequest as Request;
    matches!(
        request,
        Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::CreateFile { .. }
        )) | Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::OpenFile { .. }
        )) | Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::OpenStructuredFile { .. }
        )) | Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::ReadFile { .. }
        )) | Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::WriteFile { .. }
        )) | Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::SeekFile { .. }
        )) | Request::Kernel(win16_abi::Win16KernelRequest::Files(
            win16_abi::Win16KernelFilesRequest::CloseFile { .. }
        )) | Request::LzExpand(_)
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::FindResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::LoadResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::LockResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::FreeResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::AccessResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::SizeofResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::AllocResource { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::SetResourceHandler { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::DefResourceHandler { .. }
            ))
            | Request::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::GetProcAddress { .. }
            ))
    )
}

fn write_result(f: &mut fmt::Formatter<'_>, result: Option<u32>) -> fmt::Result {
    match result {
        Some(value) => write!(f, "{value} (0x{value:08X})"),
        None => f.write_str("bridge-error"),
    }
}
