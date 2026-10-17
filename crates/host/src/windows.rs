mod bindings;
mod com_bindings;
mod win16_com_objects;
mod win16_com_callback_copy;
mod win16_com_callback_proxy;
mod win16_com_interface_calls;
mod win16_com_request_executor;
mod win16_ole_native;
mod win16_storage_ole;
mod environment;
mod jit_cache;

impl WindowsHost {
    pub fn jit_artifact_store(&self) -> Option<std::sync::Arc<dyn runtime::JitArtifactStore>> {
        jit_cache::open_default()
    }
}
mod process_command_line;
pub use process_command_line::current_command_line;
mod win16_program_launch;
pub use win16_program_launch::{GuestChildLaunch, ProgramLoadReporter};
#[path = "windows/error_mapping.rs"]
mod error_mapping;
pub(crate) use error_mapping::{invalid, os_error};
use error_mapping::{console_input_runtime_error, last_error, vga_runtime_error};
mod mouse;
mod native_output_buffer;
mod printer_protocol;
mod printer_worker;
#[path = "windows/service_trace.rs"]
mod service_trace;
#[path = "vga_window.rs"]
mod vga_window;
mod win16;
mod win16_open_file;
mod win16_file_paths;
mod win16_file_devices;
mod win16_comm;
mod win16_lz_file_paths;
mod win16_common;
mod win16_injected_input;
mod win16_drawing;
mod win16_gdi;
mod win16_get_dc_ex;
mod win16_metafile;
mod win16_gdi_bitmap_transfer;
mod win16_gdi_device;
mod win16_gdi_services;
mod win16_network_redirector;
mod win16_spool_jobs;
mod win16_network_print_queues;
mod win16_gdi_object_factories;
mod win16_gdi_objects;
mod win16_io_trace;
mod win16_mci_owner;
mod win16_media_services;
mod win16_midi;
mod win16_multimedia_buffers;
mod win16_wave_format_storage;
mod win16_netbios;
mod win16_network;
mod win16_wnet_caps;
mod win16_network_wake;
mod win16_ole2disp;
mod win16_ole2nls;
mod win16_path_info;
mod win16_kernel_file_system;
mod win16_wing_dib_backend;
mod win16_wing_dib_format;
mod win16_wing_dib_header;
mod win16_wing_dib_storage;
mod win16_wing_dib_use;
mod multimedia_wake;
mod win16_printer;
mod win16_profile_sections;
mod win16_private_profile;
mod win16_registered_names;
mod win16_wing_brush;

pub(crate) fn run_native_worker() -> Result<(), RuntimeError> {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
    };
    // The dedicated helper reports failure through its private pipe and exit
    // status. A native crash must not leave it waiting on an invisible dialog.
    // SAFETY: This changes only the calling helper process's error UI policy.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)
    };
    printer_worker::run_native_worker()
}
mod guest_memory;
mod runtime_host;
mod dos_time;
mod guest_text;
pub mod text_encoding_metadata;
#[path = "windows/runtime_host_dde.rs"]
mod runtime_host_dde;
#[path = "windows/runtime_host_multimedia.rs"]
mod runtime_host_multimedia;
#[path = "windows/runtime_host_gdi.rs"]
mod runtime_host_gdi;
#[path = "windows/runtime_host_input.rs"]
mod runtime_host_input;
#[path = "windows/runtime_host_diagnostics.rs"]
mod runtime_host_diagnostics;
#[path = "windows/runtime_host_wave.rs"]
mod runtime_host_wave;
#[path = "windows/runtime_host_windows.rs"]
mod runtime_host_windows;
#[path = "windows/runtime_host_lz.rs"]
mod runtime_host_lz;
#[path = "windows/runtime_host_ver.rs"]
mod runtime_host_ver;
#[path = "windows/runtime_host_mouse.rs"]
mod runtime_host_mouse;
mod win16_atoms;
#[path = "windows/win16_acm_direct.rs"]
mod win16_acm_direct;
mod win16_compat_calls_lzexpand;
mod win16_compat_calls_ver;
mod win16_dde;
#[path = "windows/win16_classic_dde_wire.rs"]
mod win16_classic_dde_wire;
mod win16_images;
mod win16_dialog_icon_retention;
#[cfg(test)]
#[path = "windows/win16_dialog_static_creation_probe_tests.rs"]
mod dialog_static_creation_probe_tests;
#[cfg(test)]
#[path = "windows/win16_static_icon_ownership_probe_tests.rs"]
mod static_icon_ownership_probe_tests;
mod win16_keyboard;
#[path = "windows/win16_modal.rs"]
mod win16_modal;
mod win16_kernel_diagnostics;
mod win16_module_files;
mod win16_registry;
mod win16_storage;
mod win16_text;
mod win16_user_services_system;
mod win16_windows;
mod win32_import_system;

pub use environment::EnvironmentReport;
use crate::filesystem::Filesystem;
use devices::keyboard::KeyStroke;
use devices::mouse::MouseInput;
use devices::video::ConsoleSnapshot;
use dos_kernel::{
    DosDirectoryEntry, DosDiskSpace, DosErrorCode, DosFileAccess, DosFileOpenRequest,
    DosFileOpenResult, DosFileSharing, DosHost, DosHostError, DosHostFile, DosHostSearch,
    DosSeekOrigin,
};
use mouse::{MouseMapper, map_button_state};
use runtime::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAtomName,
    Win16HostClass, Win16HostClassSpec, Win16HostCursor, Win16HostDc, Win16HostFile,
    Win16HostFontRecord, Win16HostGdiObject, Win16HostIcon, Win16HostWindow, Win16RegisteredClass,
    Win16SelectObjectResult, Win16WindowOperation, Win16WindowReply, Win16WindowStep,
};
use std::collections::VecDeque;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};
use text_codec::{CellRole, CodePage, StreamDecoder, decode_text_row};
use vga_window::VgaWindow;
use windows_sys::Win32::Foundation::HANDLE as Handle;
use windows_sys::Win32::System::Console::{
    AllocConsole, CHAR_INFO, CHAR_INFO_0, COMMON_LVB_LEADING_BYTE, COMMON_LVB_TRAILING_BYTE, COORD,
    ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_QUICK_EDIT_MODE, GetConsoleMode, GetNumberOfConsoleInputEvents,
    GetStdHandle, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
    MOUSE_EVENT, MOUSE_EVENT_RECORD, ReadConsoleInputW, SMALL_RECT, SetConsoleCursorPosition,
    SetConsoleMode, WriteConsoleOutputW, WriteConsoleW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_MOUSEPRESENT, WaitMessage};

pub fn decode(bytes: &[u8], code_page: u32) -> Result<String, DosHostError> {
    CodePage::try_from(code_page)
        .and_then(|page| page.decode(bytes))
        .map_err(|error| DosHostError::with_source(DosErrorCode::InvalidData, error))
}

pub fn encode(text: &str, code_page: u32) -> Result<Vec<u8>, DosHostError> {
    CodePage::try_from(code_page)
        .and_then(|page| page.encode(text))
        .map_err(|error| DosHostError::with_source(DosErrorCode::InvalidData, error))
}

/// Whether host initialization may create a console for guest DOS input.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConsolePolicy {
    Inherit,
    AllocateIfMissing,
}

pub struct WindowsHost {
    program_load_reporter: Option<ProgramLoadReporter>,
    child_execution: win16_program_launch::ExecutionOptions,
    win16_format_work: parallel_work::SharedExecutor,
    win16_work_generation: Arc<AtomicU64>,
    win16_callback_sender: runtime::Win16GuestCallbackSender,
    win16_callback_receiver: runtime::Win16GuestCallbackReceiver,
    filesystem: Filesystem,
    code_page: u32,
    input: Handle,
    original_input_mode: Option<u32>,
    keys: VecDeque<KeyStroke>,
    mouse_inputs: VecDeque<MouseInput>,
    mouse_mapper: MouseMapper,
    last_mouse_input: Option<MouseInput>,
    last_mouse_buttons: u16,
    last_drag_sample: Option<runtime::Win16DragSample>,
    mouse_input_enabled: bool,
    dos_extended_byte: Option<u8>,
    stdout_decoder: StreamDecoder,
    stderr_decoder: StreamDecoder,
    vga_window: VgaWindow,
    dos_service_trace: Option<service_trace::DosServiceTrace>,
    win16_io_trace: Option<win16_io_trace::Win16IoTrace>,
    win16_files: win16::Win16Files,
    win16_comm: win16_comm::Win16CommPorts,
    win16_file_system: win16_kernel_file_system::Win16HostFileSystemState,
    // Retire MCI before dropping the USER window that supplies its wake lease.
    win16_mci: win16_mci_owner::Win16MciHost,
    // Native MIDI callbacks share the USER worker wake and must retire before it.
    win16_midi: win16_midi::Win16MidiHost,
    // Drop/join the USER worker before the owner-thread DC table. The worker
    // owns a shared clone for callback HDC tokens and must release that clone
    // before the screen-DC table is finally dropped on this thread.
    win16_windows: win16_windows::Win16Windows,
    win16_dcs: win16_gdi::Win16Dcs,
    // Drop registered classes before their referenced GDI images/brushes.
    win16_objects: win16_gdi_objects::Win16Objects,
    win16_images: win16_images::Win16Images,
    win16_atoms: win16_atoms::Win16Atoms,
    win16_registry: win16_registry::RegistryHandles,
    win16_network: win16_network::Win16NetworkHost,
    win16_spool_jobs: win16_spool_jobs::Win16SpoolJobs,
    win16_network_print_queues: win16_network_print_queues::Win16NetworkPrintQueues,
    win16_netbios: win16_netbios::HostState,
    win16_media_services: win16_media_services::Win16MediaServicesHost,
    win16_session_mixer: runtime::Win16SessionMixer,
    win32_imports: win32_import_system::Win32ImportSystem,
    win16_acm_direct: win16_acm_direct::Win16AcmHost,
    win16_wave: win16_multimedia_buffers::Win16WaveHost,
    guest_memory: Option<guest_memory::WindowsGuestMemory>,
}

impl WindowsHost {
    /// Format jobs operate on owned buffers; native calls stay on this owner.
    pub fn set_work_executor(&mut self, work: parallel_work::SharedExecutor) {
        self.win16_format_work = work;
    }

    /// Prepare the one stable guest backing used by this host/runtime pair.
    pub fn prepare_guest_memory(
        &mut self,
        size: u32,
    ) -> Result<Box<dyn guest_core::memory::MemoryStorage>, RuntimeError> {
        if self.guest_memory.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host already owns a guest memory reservation",
            ));
        }
        let owner = guest_memory::WindowsGuestMemory::new(size)?;
        let storage = owner.storage();
        self.guest_memory = Some(owner);
        Ok(storage)
    }

    /// Return the executable's path in the DOS drive namespace used by the
    /// PSP/environment. Reuse the directory enumerator's existing 8.3 mapping
    /// so non-OEM filenames remain reopenable without lossy character changes.
    /// Win16 module APIs separately use the real host ANSI path.
    pub fn dos_program_path(&mut self, program: &Path) -> Result<Vec<u8>, DosHostError> {
        self.filesystem
            .guest_path_for_host_path(program)?
            .ok_or_else(|| invalid(DosErrorCode::PathNotFound))
    }

    pub fn new(root: &Path, code_page: u32) -> Result<Self, DosHostError> {
        Self::new_with_ansi_code_page(root, code_page, if code_page == 936 { 936 } else { 1252 })
    }
    pub fn new_with_ansi_code_page(root: &Path, code_page: u32, ansi_code_page: u32) -> Result<Self, DosHostError> {
        Self::new_with_console_policy(root, code_page, ansi_code_page, ConsolePolicy::AllocateIfMissing)
    }
    pub fn new_with_console_policy(
        root: &Path,
        code_page: u32,
        ansi_code_page: u32,
        console_policy: ConsolePolicy,
    ) -> Result<Self, DosHostError> {
        let codec = guest_text::GuestTextCodec::new(ansi_code_page)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InvalidData, error))?;
        let page = CodePage::try_from(code_page)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InvalidData, error))?;
        let filesystem = Filesystem::new_native_directory(root, code_page)?;
        // Native relative file APIs and the DOS drive-relative namespace begin
        // at the same program directory. Rust uses the Unicode Windows API here.
        std::env::set_current_dir(root).map_err(os_error)?;
        // Limit outstanding native notifications independently of their
        // per-event byte budget. Producers use nonblocking delivery.
        const CALLBACK_MAILBOX_CAPACITY: usize = 64;
        let (win16_callback_sender, win16_callback_receiver) =
            runtime::win16_guest_callback_channel(CALLBACK_MAILBOX_CAPACITY)
                .map_err(|error| DosHostError::with_source(DosErrorCode::InvalidData, error))?;
        // SAFETY: GetStdHandle has no memory preconditions and returns an OS-owned handle.
        let mut input = unsafe { GetStdHandle((-10i32) as u32) };
        // Windowed guests preserve redirected/inherited streams without
        // creating a visible console merely to initialize unused DOS input.
        if (input.is_null() || input as isize == -1)
            && console_policy == ConsolePolicy::AllocateIfMissing
        {
            // SAFETY: AllocConsole attaches a console to this process only.
            if unsafe { AllocConsole() } == 0 {
                return Err(last_error());
            }
            // SAFETY: Reacquire the standard handle after successful console allocation.
            input = unsafe { GetStdHandle((-10i32) as u32) };
        }
        let mut mode = 0;
        // SAFETY: Mode points to a valid u32. A redirected handle may return failure.
        let original_input_mode = if unsafe { GetConsoleMode(input, &mut mode) } != 0 {
            // Guest input owns line editing, echo and control characters.
            // Console mouse records share this input buffer, so the common
            // event pump preserves keyboard and mouse records independently.
            // SAFETY: This handle's console mode was just read successfully.
            let input_mode = (mode
                & !(ENABLE_LINE_INPUT
                    | ENABLE_ECHO_INPUT
                    | ENABLE_PROCESSED_INPUT
                    | ENABLE_QUICK_EDIT_MODE))
                | ENABLE_MOUSE_INPUT
                | ENABLE_EXTENDED_FLAGS;
            if unsafe { SetConsoleMode(input, input_mode) } == 0 {
                return Err(last_error());
            }
            Some(mode)
        } else {
            None
        };
        let win16_dcs = win16_gdi::Win16Dcs::with_text_codec(codec);
        let win16_images = win16_images::Win16Images::new(codec);
        let identity_source = Arc::new(AtomicU64::new(1));
        let win16_windows = win16_windows::Win16Windows::new(
            win16_dcs.clone(),
            win16_images.clone(),
            Arc::clone(&identity_source),
            guest_text::GuestTextCodec::new(code_page)
                .map_err(|error| DosHostError::with_source(DosErrorCode::GeneralFailure, error))?,
        );
        let multimedia_wake = win16_windows
            .multimedia_wake_sender()
            .map_err(|error| DosHostError::with_source(DosErrorCode::GeneralFailure, error))?;
        let win16_midi = win16_midi::Win16MidiHost::new(
            Arc::clone(&identity_source),
            multimedia_wake.clone(),
        );
        let win16_mci = win16_mci_owner::Win16MciHost::new(
            multimedia_wake.clone(), Arc::clone(&identity_source), codec)
            .map_err(|error| DosHostError::with_source(DosErrorCode::GeneralFailure, error))?;
        let win16_wave = win16_windows.new_wave_host(Arc::clone(&identity_source), codec);
        let win16_network = win16_network::Win16NetworkHost::new(
            identity_source, multimedia_wake.clone())
            .map_err(|error| DosHostError::with_source(DosErrorCode::GeneralFailure, error))?;
        let win16_work_generation = multimedia_wake.generation_observer();
        Ok(Self {
            program_load_reporter: None,
            child_execution: win16_program_launch::ExecutionOptions::default(),
            win16_format_work: Arc::new(parallel_work::BoundedExecutor::new()),
            win16_work_generation,
            filesystem,
            code_page,
            input,
            original_input_mode,
            win16_callback_sender,
            win16_callback_receiver,
            mouse_input_enabled: original_input_mode.is_some(),
            keys: VecDeque::new(),
            mouse_inputs: VecDeque::new(),
            mouse_mapper: MouseMapper::new(),
            last_mouse_input: None,
            last_mouse_buttons: 0,
            last_drag_sample: None,
            dos_extended_byte: None,
            stdout_decoder: StreamDecoder::new(page),
            stderr_decoder: StreamDecoder::new(page),
            vga_window: VgaWindow::new(code_page),
            dos_service_trace: None,
            win16_io_trace: None,
            win16_files: win16::Win16Files::new(),
            win16_comm: win16_comm::Win16CommPorts::new(),
            win16_file_system: win16_kernel_file_system::Win16HostFileSystemState::default(),
            win16_mci,
            win16_midi,
            win16_windows,
            win16_dcs,
            win16_objects: win16_gdi_objects::Win16Objects::new(),
            win16_images,
            win16_atoms: win16_atoms::Win16Atoms::new(),
            win16_registry: win16_registry::RegistryHandles::new(),
            win16_network,
            win16_spool_jobs: win16_spool_jobs::Win16SpoolJobs::default(),
            win16_network_print_queues:
                win16_network_print_queues::Win16NetworkPrintQueues::default(),
            win16_netbios: win16_netbios::HostState::new(multimedia_wake),
            win16_media_services: win16_media_services::Win16MediaServicesHost::new(codec),
            win16_session_mixer: runtime::Win16SessionMixer::default(),
            win32_imports: win32_import_system::Win32ImportSystem::new(codec),
            win16_acm_direct: win16_acm_direct::Win16AcmHost::default(),
            win16_wave,
            guest_memory: None,
        })
    }

    /// Start a bounded per-service DOS INT 21h trace in a new file.
    pub fn enable_dos_service_trace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        self.dos_service_trace = Some(service_trace::DosServiceTrace::create(path).map_err(
            |error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    format!("create DOS service trace {}", path.display()),
                    error,
                )
            },
        )?);
        Ok(())
    }

    /// Start an explicitly requested Win16 trace without logging file contents.
    /// Complete mode streams all events to disk instead of retaining a bounded transcript.
    pub fn enable_win16_io_trace(&mut self, path: &Path, complete: bool) -> Result<(), RuntimeError> {
        self.win16_io_trace =
            Some(win16_io_trace::Win16IoTrace::create(path, complete).map_err(|error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    format!("create Win16 I/O trace {}", path.display()),
                    error,
                )
            })?);
        Ok(())
    }

    /// Return DOS-usable inherited environment entries and path-conversion
    /// diagnostics. Environment values are data only; they are never logged.
    pub fn inherited_environment(
        &mut self,
    ) -> Result<(Vec<Vec<u8>>, EnvironmentReport), DosHostError> {
        environment::inherited_environment(&mut self.filesystem, self.code_page)
    }

    fn key(&mut self, blocking: bool) -> Result<Option<KeyStroke>, DosHostError> {
        if let Some(key) = self.keys.pop_front() {
            return Ok(Some(key));
        }
        if self.vga_window.is_active() {
            if blocking {
                loop {
                    self.pump_vga_events().map_err(|error| {
                        DosHostError::with_source(DosErrorCode::GeneralFailure, error)
                    })?;
                    if let Some(key) = self.keys.pop_front() {
                        return Ok(Some(key));
                    }
                    if unsafe { WaitMessage() } == 0 {
                        return Err(last_error());
                    }
                }
            }
            self.pump_vga_events()
                .map_err(|error| DosHostError::with_source(DosErrorCode::GeneralFailure, error))?;
            return Ok(self.keys.pop_front());
        }
        if self.original_input_mode.is_none() {
            if !blocking {
                if self.vga_window.is_active() {
                    return Ok(None);
                }
                return Err(invalid(DosErrorCode::InvalidFunction));
            }
            let mut byte = [0];
            if io::stdin().read(&mut byte).map_err(os_error)? == 0 {
                return Err(invalid(DosErrorCode::GeneralFailure));
            }
            return Ok(Some(KeyStroke {
                ascii: byte[0],
                scan: 0,
            }));
        }
        loop {
            self.pump_console_input(blocking)?;
            if let Some(key) = self.keys.pop_front() {
                return Ok(Some(key));
            }
            if !blocking {
                return Ok(None);
            }
        }
    }

    /// Drains the shared native input buffer and routes keyboard and mouse
    /// records to separate queues. In blocking mode only the first read waits.
    fn pump_console_input(&mut self, blocking: bool) -> Result<(), DosHostError> {
        if self.original_input_mode.is_none() {
            return Ok(());
        }
        let mut first_read = true;
        loop {
            if !blocking || !first_read {
                let mut available = 0;
                // SAFETY: Input is a console handle and available is writable.
                if unsafe { GetNumberOfConsoleInputEvents(self.input, &mut available) } == 0 {
                    return Err(last_error());
                }
                if available == 0 {
                    return Ok(());
                }
            }

            let mut record = INPUT_RECORD {
                EventType: 0,
                Event: INPUT_RECORD_0 {
                    KeyEvent: KEY_EVENT_RECORD {
                        bKeyDown: 0,
                        wRepeatCount: 0,
                        wVirtualKeyCode: 0,
                        wVirtualScanCode: 0,
                        uChar: KEY_EVENT_RECORD_0 { UnicodeChar: 0 },
                        dwControlKeyState: 0,
                    },
                },
            };
            let mut read = 0;
            // SAFETY: The official Windows binding supplies INPUT_RECORD layout; one record fits.
            if unsafe { ReadConsoleInputW(self.input, &mut record, 1, &mut read) } == 0 {
                return Err(last_error());
            }
            first_read = false;
            if read == 0 {
                if blocking {
                    continue;
                }
                return Ok(());
            }

            match record.EventType {
                event if event == KEY_EVENT as u16 => self.route_key_record(&record)?,
                event if event == MOUSE_EVENT as u16 => self.route_mouse_record(&record)?,
                _ => {}
            }
        }
    }

    fn route_key_record(&mut self, record: &INPUT_RECORD) -> Result<(), DosHostError> {
        // SAFETY: EventType identifies the active KeyEvent variant.
        let key_event = unsafe { record.Event.KeyEvent };
        if key_event.bKeyDown == 0 {
            return Ok(());
        }
        let repeat = usize::from(key_event.wRepeatCount);
        let scan = key_event.wVirtualScanCode as u8;
        // SAFETY: ReadConsoleInputW writes the UnicodeChar variant.
        let character = unsafe { key_event.uChar.UnicodeChar };
        let bytes = if character == 0 {
            vec![0]
        } else {
            encode(
                &String::from_utf16(&[character])
                    .map_err(|_| invalid(DosErrorCode::InvalidData))?,
                self.code_page,
            )?
        };
        let count = repeat
            .checked_mul(bytes.len())
            .ok_or_else(|| DosHostError::new(DosErrorCode::InsufficientMemory))?;
        self.keys
            .try_reserve(count)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InsufficientMemory, error))?;
        for _ in 0..repeat {
            for &byte in &bytes {
                self.keys.push_back(KeyStroke { ascii: byte, scan });
            }
        }
        Ok(())
    }

    fn route_mouse_record(&mut self, record: &INPUT_RECORD) -> Result<(), DosHostError> {
        if !self.mouse_input_enabled {
            return Ok(());
        }
        // SAFETY: EventType identifies the active MouseEvent variant.
        let mouse_event: MOUSE_EVENT_RECORD = unsafe { record.Event.MouseEvent };
        let buttons = map_button_state(mouse_event.dwButtonState);
        let position = mouse_event.dwMousePosition;
        let input = self.mouse_mapper.map_cell(position.X, position.Y, buttons);
        self.last_mouse_buttons = buttons;
        if self.last_mouse_input == Some(input) {
            return Ok(());
        }
        self.mouse_inputs
            .try_reserve(1)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InsufficientMemory, error))?;
        self.mouse_inputs.push_back(input);
        self.last_mouse_input = Some(input);
        Ok(())
    }

    fn output(&mut self, input: &[u8], stderr: bool) -> Result<usize, DosHostError> {
        let terminal = if stderr {
            io::stderr().is_terminal()
        } else {
            io::stdout().is_terminal()
        };
        if !terminal {
            if stderr {
                io::stderr().write_all(input).map_err(os_error)?;
            } else {
                io::stdout().write_all(input).map_err(os_error)?;
            }
            return Ok(input.len());
        }
        let decoder = if stderr {
            &mut self.stderr_decoder
        } else {
            &mut self.stdout_decoder
        };
        let text = decoder
            .push(input, false)
            .map_err(|_| invalid(DosErrorCode::InvalidData))?;
        Self::console_output(&text, stderr)?;
        Ok(input.len())
    }

    fn queue_vga_keys(&mut self, keys: Vec<KeyStroke>) -> Result<(), RuntimeError> {
        self.keys.try_reserve(keys.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "VGA keyboard queue", error)
        })?;
        self.keys.extend(keys);
        Ok(())
    }

    fn pump_vga_events(&mut self) -> Result<(), RuntimeError> {
        let keys = self.vga_window.pump_events().map_err(vga_runtime_error)?;
        self.queue_vga_keys(keys)
    }

    /// Finish native window ownership and preserve any shutdown failure.
    pub fn finish_native_windows(&mut self) -> Result<(), RuntimeError> {
        self.win16_windows.shutdown()
    }

    /// Complete the decoders explicitly so a trailing partial character is reported.
    pub fn finish_output(&mut self) -> Result<(), DosHostError> {
        if let Some(mut trace) = self.win16_io_trace.take() {
            if let Err(error) = trace.flush_recent() {
                self.report_diagnostic(&runtime::Diagnostic::warning(
                    runtime::DiagnosticKind::HostFailure,
                    "could not save recent Win16 observations",
                ).with_cause(error));
            }
        }
        let stdout = self
            .stdout_decoder
            .push(&[], true)
            .map_err(|_| invalid(DosErrorCode::InvalidData))?;
        let stderr = self
            .stderr_decoder
            .push(&[], true)
            .map_err(|_| invalid(DosErrorCode::InvalidData))?;
        if !stdout.is_empty() {
            Self::console_output(&stdout, false)?;
        }
        if !stderr.is_empty() {
            Self::console_output(&stderr, true)?;
        }
        Ok(())
    }

    fn console_output(text: &str, stderr: bool) -> Result<(), DosHostError> {
        let wide: Vec<u16> = text.encode_utf16().collect();
        // SAFETY: Fetch the OS-owned standard output/error handle.
        let handle = unsafe {
            GetStdHandle(if stderr {
                (-12i32) as u32
            } else {
                (-11i32) as u32
            })
        };
        let mut offset = 0;
        while offset < wide.len() {
            let count = u32::try_from(wide.len() - offset)
                .map_err(|_| invalid(DosErrorCode::InvalidData))?;
            let mut written = 0;
            // SAFETY: The suffix contains count valid UTF-16 units and written is writable.
            if unsafe {
                WriteConsoleW(
                    handle,
                    wide[offset..].as_ptr().cast(),
                    count,
                    &mut written,
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(last_error());
            }
            if written == 0 || written > count {
                return Err(invalid(DosErrorCode::GeneralFailure));
            }
            offset += written as usize;
        }
        Ok(())
    }
}

impl Drop for WindowsHost {
    fn drop(&mut self) {
        self.win16_network.shutdown_and_quarantine();
        if let Some(mode) = self.original_input_mode {
            // SAFETY: The standard console handle is OS-owned and kept for this object's lifetime.
            unsafe {
                SetConsoleMode(self.input, mode);
            }
        }
    }
}

impl DosHost for WindowsHost {
    fn local_date_time(&mut self) -> Result<dos_kernel::DosLocalDateTime, DosHostError> {
        Ok(dos_time::local_date_time())
    }
    fn standard_ioctl_info(
        &self,
        stream: dos_kernel::DosIoctlStream,
    ) -> Result<dos_kernel::DosIoctlObjectInfo, DosHostError> {
        crate::ioctl::standard_info(self.input, stream)
    }
    fn file_ioctl_info(
        &self,
        file: DosHostFile,
    ) -> Result<dos_kernel::DosIoctlObjectInfo, DosHostError> {
        self.filesystem.file_ioctl_info(file)
    }
    fn file_status(
        &mut self,
        file: DosHostFile,
    ) -> Result<dos_kernel::DosFileStatus, DosHostError> {
        self.filesystem.file_status(file)
    }
    fn file_set_write_time(
        &mut self,
        file: DosHostFile,
        time: u16,
        date: u16,
    ) -> Result<(), DosHostError> {
        self.filesystem.file_set_write_time(file, time, date)
    }
    fn guest_code_page(&self) -> CodePage {
        self.filesystem.guest_code_page()
    }
    fn read_stdin(&mut self, output: &mut [u8]) -> Result<usize, DosHostError> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(byte) = self.dos_extended_byte.take() {
            output[0] = byte;
            return Ok(1);
        }
        if self.original_input_mode.is_none()
            && self.keys.is_empty()
            && !self.vga_window.is_active()
        {
            crate::ioctl::validate_redirected_input(self.input)?;
            // DOS Function 3FH returns zero bytes at file EOF. Redirected
            // bytes, including NUL, must not become extended keyboard events.
            // Microsoft MS-DOS 4.0 Programmer's Reference, Function 3FH:
            // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
            return io::stdin().read(output).map_err(os_error);
        }
        let key = self
            .key(true)?
            .ok_or_else(|| invalid(DosErrorCode::GeneralFailure))?;
        output[0] = key.ascii;
        if key.ascii == 0 {
            self.dos_extended_byte = Some(key.scan);
        }
        Ok(1)
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        if let Some(byte) = self.dos_extended_byte.take() {
            return Ok(Some(byte));
        }
        Ok(self.key(false)?.map(|key| {
            if key.ascii == 0 {
                self.dos_extended_byte = Some(key.scan);
            }
            key.ascii
        }))
    }
    fn write_stdout(&mut self, input: &[u8]) -> Result<usize, DosHostError> {
        self.output(input, false)
    }
    fn write_stderr(&mut self, input: &[u8]) -> Result<usize, DosHostError> {
        self.output(input, true)
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        if self.original_input_mode.is_none() {
            return Err(invalid(DosErrorCode::InvalidFunction));
        }
        // Drain through the shared router so flushing DOS keyboard input does
        // not silently discard mouse records from the native console queue.
        self.pump_console_input(false)?;
        self.keys.clear();
        self.dos_extended_byte = None;
        Ok(())
    }
    fn file_create(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError> {
        self.filesystem.file_create(path, attributes)
    }
    fn file_create_new(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError> {
        self.filesystem.file_create_new(path, attributes)
    }
    fn file_extended_open(
        &mut self,
        path: &[u8],
        request: DosFileOpenRequest,
    ) -> Result<DosFileOpenResult, DosHostError> {
        self.filesystem.file_extended_open(path, request)
    }
    fn file_open(
        &mut self,
        path: &[u8],
        access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        self.file_open_with_sharing(path, access, DosFileSharing::DenyNone)
    }
    fn file_open_with_sharing(
        &mut self,
        path: &[u8],
        access: DosFileAccess,
        sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        let result = self.filesystem.file_open(path, access, sharing);
        if let Err(error) = &result {
            runtime_host_diagnostics::observe_win16_io(self,
                &runtime::Win16IoEvent::DosOpenFailure { path, error: error.code as u16 });
        }
        result
    }
    fn file_duplicate(&mut self, file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        self.filesystem.file_duplicate(file)
    }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        self.filesystem.file_close(file)
    }
    fn file_commit(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        self.filesystem.file_commit(file)
    }
    fn file_read(&mut self, file: DosHostFile, output: &mut [u8]) -> Result<usize, DosHostError> {
        self.filesystem.file_read(file, output)
    }
    fn file_input_status(&mut self, file: DosHostFile) -> Result<bool, DosHostError> {
        self.filesystem.file_input_status(file)
    }
    fn file_write(&mut self, file: DosHostFile, input: &[u8]) -> Result<usize, DosHostError> {
        self.filesystem.file_write(file, input)
    }
    fn file_seek(
        &mut self,
        file: DosHostFile,
        offset: i32,
        origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        self.filesystem.file_seek(file, offset, origin)
    }
    fn file_set_len(&mut self, file: DosHostFile, length: u32) -> Result<(), DosHostError> {
        self.filesystem.file_set_len(file, length)
    }
    fn file_delete(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        self.filesystem.file_delete(path)
    }
    fn directory_create(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        self.filesystem.directory_create(path)
    }
    fn directory_remove(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        self.filesystem.directory_remove(path)
    }
    fn directory_set_current(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        self.filesystem.directory_set_current(path, true)
    }
    fn directory_get_current(
        &mut self,
        drive: u8,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        self.filesystem.directory_get_current(drive, output)
    }
    fn file_rename(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<(), DosHostError> {
        self.filesystem.file_rename(old_path, new_path)
    }
    fn file_get_attributes(&mut self, path: &[u8]) -> Result<u8, DosHostError> {
        self.filesystem.file_get_attributes(path)
    }
    fn file_set_attributes(&mut self, path: &[u8], attributes: u8) -> Result<(), DosHostError> {
        self.filesystem.file_set_attributes(path, attributes)
    }
    fn directory_search_open(&mut self, directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        self.filesystem.directory_search_open(directory)
    }
    fn directory_search_next(
        &mut self,
        search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        self.filesystem.directory_search_next(search)
    }
    fn directory_search_close(&mut self, search: DosHostSearch) -> Result<(), DosHostError> {
        self.filesystem.directory_search_close(search)
    }
    fn current_drive(&self) -> u8 {
        self.filesystem.drive()
    }
    fn select_drive(&mut self, drive: u8) -> Result<(), DosHostError> {
        if drive == self.filesystem.drive() {
            Ok(())
        } else {
            Err(invalid(DosErrorCode::UnknownUnit))
        }
    }
    fn logical_drive_count(&self) -> u8 {
        self.filesystem.drive() + 1
    }
    fn disk_space(&self, drive: u8) -> Result<DosDiskSpace, DosHostError> {
        self.filesystem.disk_space(drive)
    }
}
