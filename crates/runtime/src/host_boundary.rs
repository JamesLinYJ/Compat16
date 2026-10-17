//! Owned host identities and services consumed by the runtime.

#[path = "host_boundary_audio.rs"]
mod audio;
use audio::audio_runtime_host_ports;

#[path = "host_boundary_graphics.rs"]
mod graphics;
use graphics::graphics_runtime_host_ports;

use crate::{
    Diagnostic, DiagnosticKind, GuestRegisters, RuntimeDdeHost, RuntimeError, RuntimeMciHost,
    RuntimeMidiHost, RuntimeNetbiosHost, Win16WindowOperation, Win16WindowReply, Win16WindowStep,
};
use devices::{keyboard::KeyStroke, mouse::MouseInput, video::ConsoleSnapshot};
use dos_kernel::DosHost;
use guest_core::OwnerId;

/// Result of probing only the first Win16 ANSI character. The input contains
/// actual guest bytes, not an implicitly terminated or padded host string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16AnsiNextProbe {
    /// Read exactly one more checked guest byte, up to four bytes in total.
    NeedMore,
    /// Byte offset of the next character or the explicit terminal NUL.
    Complete(usize),
}

/// Private profile location, resolved without changing the native process cwd.
#[derive(Clone, Debug)]
pub enum Win16ProfilePath {
    System,
    WindowsDirectory(String),
    File(crate::Win16GuestPath),
    Invalid,
}

/// Opaque host file identity. It is never a guest HFILE or native HANDLE.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostFile(pub u64);

/// Opaque host communications port. Guest `OpenComm` ids are separate words.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostCommPort(pub u64);

/// A parsed `COMn` or `LPTn` identity. The guest string is not a host path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostCommDevice {
    Com(u8),
    Lpt(u8),
}

/// `COM` devices accept serial timeouts and line control. `LPT` handles do not.
pub fn win16_comm_device_is_serial(device: Win16HostCommDevice) -> bool {
    matches!(device, Win16HostCommDevice::Com(_))
}

/// Win32 line state that a Win16 `DCB` flag can express.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostCommLine {
    Disable,
    Enable,
    Handshake,
}

/// Serial parameters applied with the host's device-control call.
///
/// Baud is the numeric rate. Win16 `CBR_*` constants are translated before
/// they reach the host. Fields the host API cannot store are rejected by the
/// runtime and never appear here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostCommConfig {
    pub baud_rate: u32,
    pub byte_size: u8,
    pub parity: u8,
    pub stop_bits: u8,
    pub binary: bool,
    pub parity_check: bool,
    pub cts_output_flow: bool,
    pub dsr_output_flow: bool,
    pub dtr: Win16HostCommLine,
    pub rts: Win16HostCommLine,
    pub xon_output: bool,
    pub xon_input: bool,
    pub error_char_enabled: bool,
    pub strip_null: bool,
    pub xon_char: u8,
    pub xoff_char: u8,
    pub error_char: u8,
    pub eof_char: u8,
    pub event_char: u8,
    pub xon_limit: u16,
    pub xoff_limit: u16,
}

/// Line control addressed to one open serial device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostCommControl {
    SetXoff,
    SetXon,
    SetRts,
    ClearRts,
    SetDtr,
    ClearDtr,
    Reset,
    SetBreak,
    ClearBreak,
}

/// Queue cleared by `FlushComm`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostCommQueue {
    Transmit,
    Receive,
}

/// An initialized stream identity in the host's common file table.
/// The host owns native LZ token classification, including token zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostLzInit {
    File(Win16HostFile),
    Error(i16),
}

/// Closing a stream can also consume the source used to initialize it.
/// Both identities are opaque tokens; no native handle value crosses here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostFileClose {
    pub closed: bool,
    pub consumed_source: Option<Win16HostFile>,
}

/// A completed LZ read preserves the native API's negative guest error code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostLzRead {
    Bytes(Vec<u8>),
    Error(i16),
}

/// An expanded filename or the native LZ API's signed failure code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostLzName {
    Name(Vec<u8>),
    Error(i16),
}

#[derive(Clone, Debug)]
pub struct Win16HostLzOpen {
    pub result: i16,
    pub file: Option<Win16HostFile>,
    pub ofstruct: Vec<u8>,
}

/// KERNEL.OpenFile result, including the caller-owned 16-bit OFSTRUCT image.
#[derive(Clone, Debug)]
pub struct Win16HostOpenFile {
    pub result: i16,
    pub file: Option<Win16HostFile>,
    pub ofstruct: Vec<u8>,
}

/// Native drive classification returned by the host without DOS drive
/// confinement or guest-visible host handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostDriveKind {
    Unknown,
    MissingRoot,
    Removable,
    Fixed,
    Remote,
    CdRom,
    RamDisk,
}

/// A copied guest module file. Relocation and execution stay in guest code.
#[derive(Debug)]
pub struct Win16ModuleImage {
    pub path: Vec<u8>,
    pub image: Vec<u8>,
}

/// Opaque host device-context identity; guest HDC words are allocated separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDc(pub u64);

/// One copied native font enumeration result. These scalar fields cross the
/// host boundary without exposing native GDI pointers or Windows ABI structs.
#[derive(Clone, Debug)]
pub struct Win16HostFontRecord {
    pub logfont_dimensions: [i32; 5],
    pub logfont_styles: [u8; 8],
    pub face_name: [u8; 32],
    /// ENUMLOGFONT16 names; zero-filled for the legacy EnumFonts route.
    pub full_name: [u8; 64],
    pub style: [u8; 32],
    pub textmetric_dimensions: [i32; 8],
    pub textmetric_styles: [u8; 9],
    pub textmetric_extra: [i32; 3],
    /// TrueType records can carry the Windows 3.1 NEWTEXTMETRIC tail.
    pub newtextmetric_extra: Option<[u32; 4]>,
    pub font_type: u16,
}

/// Opaque host GDI object identity, distinct from a guest 16-bit HGDIOBJ.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostGdiObject(pub u64);

/// Task cleanup distinguishes native ownership from the guest DeleteObject
/// result. Borrowed objects and USER-owned DC leases are not deleted by GDI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostGdiCleanup {
    Released,
    Borrowed,
    Absent,
    Failed,
}

/// Opaque native icon identity; never a guest HICON or native pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostIcon(pub u64);

/// Opaque native cursor identity, distinct from a guest HCURSOR word.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostCursor(pub u64);

/// Opaque registered native class identity; its atom is the result of USER
/// class registration, not a guest pointer or a GlobalAddAtom token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostClass(pub u64);

/// Opaque native HWND-incarnation identity. The host allocates these tokens
/// from a checked monotonic sequence and never reuses one for another HWND;
/// WOW allocates a separate 16-bit guest handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostWindow(pub u64);

/// Liveness of the exact host window incarnation named by a
/// `Win16HostWindow` token. Unknown or mismatched identities are errors at
/// the host boundary, not `Retired`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWindowLiveness {
    Live,
    Retired,
}

/// Retained native window-procedure identity. Its code address and encoding
/// remain in the host; WOW exposes a separately allocated guest FAR entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostProcedure(pub u64);

/// Opaque native HMENU identity, distinct from the guest's 16-bit HMENU.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMenu(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16RegisteredClass {
    pub class: Win16HostClass,
    pub atom: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ClassBackground {
    SystemColor(u16),
    Brush(Win16HostGdiObject),
}

/// One class resource a guest replacement installs on the native class that
/// its windows are created from. The variant selects the field and the payload
/// is the new resource; `None` clears it, matching a zero guest handle.
/// Ordinary `DefWindowProc` defaults read these native class fields, so the
/// runtime never publishes a guest replacement the host did not accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostClassResource {
    Icon(Option<Win16HostIcon>),
    Cursor(Option<Win16HostCursor>),
    Background(Option<Win16ClassBackground>),
}

/// A Windows predefined control class exposed through a runtime-owned alias.
/// Its native class name and procedure stay on the host side.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16HostSystemClass {
    Button,
    Edit,
    Static,
    ListBox,
    ComboBox,
    ScrollBar,
    MdiClient,
}

/// Copied Win16 class attributes after guest handles have been translated.
/// The host registers its own safe window procedure; no guest FAR pointer
/// crosses this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostClassSpec {
    pub style: u16,
    pub class_extra: i16,
    pub window_extra: i16,
    pub icon: Option<Win16HostIcon>,
    pub cursor: Option<Win16HostCursor>,
    pub background: Option<Win16ClassBackground>,
    pub system_class: Option<Win16HostSystemClass>,
}

/// Guest reservation sizes and opaque resources for a predefined class.
/// Native internal storage and WNDPROC pointers stay in the USER worker.
#[derive(Clone, Copy, Debug)]
pub struct Win16HostSystemClassInfo {
    pub spec: Win16HostClassSpec,
    pub procedure: Win16HostProcedure,
}

/// An atom lookup argument after WOW has copied or decoded the guest value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostAtomName<'a> {
    Integer(u16),
    String(&'a [u8]),
}

/// SelectObject returns a previous object, region complexity, or recording success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SelectObjectResult {
    Recorded,
    Object(Win16HostGdiObject),
    /// A private bitmap valid only while the exact native callback DC is live.
    CallbackBitmap { object: Win16HostGdiObject, dc: Win16HostDc },
    RegionComplexity(u16),
}

/// Advisory readiness, never a source-payload acknowledgement. Generation
/// changes prompt polling; callback_pending retains queued mailbox demand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SchedulerReadiness {
    pub generation: u64,
    pub callback_pending: bool,
}

/// One screen-coordinate observation for USER.465 DragDetect.
///
/// `x` and `y` are host screen pixels narrowed into signed Win16 range.
/// `left_down` and `escape_down` follow the high bit of the asynchronous
/// logical key state. The sample is not a guest pointer or a host HWND.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16DragSample {
    pub x: i16,
    pub y: i16,
    pub left_down: bool,
    pub escape_down: bool,
}

pub trait RuntimeHost:
    DosHost + RuntimeDdeHost + RuntimeMciHost + RuntimeMidiHost + RuntimeNetbiosHost
{
    /// Return the current owner incarnation for native COM/OLE work. A real
    /// implementation supplies this identity from the owning USER STA; the
    /// default deliberately does not invent one.
    fn win16_com_owner(&mut self) -> Result<crate::Win16ComHostOwnerIdentity, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM owner service is not connected",
        ))
    }

    /// Permanently end the explicit COM owner incarnation. This is a process
    /// owner boundary, not an individual Win16 task or window close.
    fn win16_com_shutdown(
        &mut self,
        _owner: crate::Win16ComHostOwnerIdentity,
        _operation: crate::Win16ComHostShutdownOperation,
    ) -> Result<crate::Win16ComHostShutdownStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM owner retirement service is not connected",
        ))
    }

    /// Submit one owned COM request to the owner STA. The returned step may be
    /// running, complete, or a checked callback; it is never itself evidence
    /// that an enclosing OLE1 API completed.
    fn win16_com_begin(
        &mut self,
        _owner: crate::Win16ComHostOwnerIdentity,
        _start: crate::Win16ComHostStart,
    ) -> Result<crate::Win16ComHostStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM request service is not connected",
        ))
    }

    /// Resume or poll an exact native COM operation after its callback frame.
    fn win16_com_continue(
        &mut self,
        _owner: crate::Win16ComHostOwnerIdentity,
        _continuation: crate::Win16ComHostContinue,
    ) -> Result<crate::Win16ComHostStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM continuation service is not connected",
        ))
    }

    /// Dequeue one callback frame for the exact owner incarnation. Callback
    /// delivery and native API terminal results have separate ownership and
    /// acknowledgement paths.
    fn win16_com_poll_callback(
        &mut self,
        _owner: crate::Win16ComHostOwnerIdentity,
    ) -> Result<Option<crate::Win16ComHostStep>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM callback queue is not connected",
        ))
    }

    /// Poll the terminal result retained for one exact owner/operation pair.
    /// The host keeps that result until the runtime acknowledges it after
    /// translating the HRESULT and reconciling every owned result token.
    fn win16_com_poll_terminal(
        &mut self,
        _owner: crate::Win16ComHostOwnerIdentity,
        _operation: crate::Win16ComHostOperationIdentity,
    ) -> Result<Option<crate::Win16ComHostStep>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM terminal queue is not connected",
        ))
    }

    /// Retire one exact terminal only after the runtime has consumed its
    /// result. A failed acknowledgement leaves the host-owned result pending.
    fn win16_com_acknowledge_terminal(
        &mut self,
        _owner: crate::Win16ComHostOwnerIdentity,
        _operation: crate::Win16ComHostOperationIdentity,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 COM terminal acknowledgement is not connected",
        ))
    }

    /// Execute a pointer-free request for a catalogued PE32 Win32 service.
    /// The default preserves hosts without a native Windows adapter.
    fn win32_import(
        &mut self,
        _call: crate::Win32HostImportCall,
    ) -> Result<crate::Win32HostImportResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host PE32 Win32 import services are unavailable",
        ))
    }
    fn win16_ole2disp_conversion(
        &mut self,
        _operation: crate::Win16Ole2DispConversionOperation,
    ) -> Result<crate::Win16Ole2DispConversionResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 Automation conversion services are unavailable",
        ))
    }
    fn win16_media_time(
        &mut self,
        _operation: crate::Win16HostMediaTimeOperation,
    ) -> Result<crate::Win16HostMediaTimeResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 multimedia timer services are unavailable",
        ))
    }
    /// Auxiliary audio without a physical device. Zero devices is the public
    /// result; other calls return `MMSYSERR_BADDEVICEID` and write nothing.
    fn win16_aux(
        &mut self,
        operation: crate::Win16HostAuxOperation,
    ) -> Result<crate::Win16HostAuxResult, RuntimeError> {
        match operation {
            crate::Win16HostAuxOperation::GetNumDevs => Ok(crate::Win16HostAuxResult::Count(0)),
            crate::Win16HostAuxOperation::GetDevCaps { .. } => {
                Ok(crate::Win16HostAuxResult::Capabilities {
                    result: crate::MMSYSERR_BADDEVICEID,
                    capabilities: None,
                })
            }
            crate::Win16HostAuxOperation::GetVolume { .. } => Ok(crate::Win16HostAuxResult::Volume {
                result: crate::MMSYSERR_BADDEVICEID,
                value: None,
            }),
            crate::Win16HostAuxOperation::SetVolume { .. }
            | crate::Win16HostAuxOperation::OutMessage { .. } => {
                Ok(crate::Win16HostAuxResult::Status(crate::MMSYSERR_BADDEVICEID))
            }
        }
    }
    fn win16_media_io(
        &mut self,
        _operation: crate::Win16HostMediaIoOperation,
    ) -> Result<crate::Win16HostMediaIoResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 multimedia I/O services are unavailable",
        ))
    }
    /// No physical joystick. A count of zero and `MMSYSERR_NODRIVER` are the
    /// Windows 3.1 results when the joystick driver is absent.
    fn win16_joystick(
        &mut self,
        operation: crate::Win16HostJoystickOperation,
    ) -> Result<crate::Win16HostJoystickResult, RuntimeError> {
        use crate::{Win16HostJoystickOperation as Operation, Win16HostJoystickResult as Reply};
        Ok(match operation {
            Operation::DeviceCount => Reply::Count(0),
            Operation::DevCaps { .. } => Reply::Caps {
                result: win16_abi::MMSYSERR_NODRIVER,
                caps: None,
            },
            Operation::Position { .. } => Reply::Position {
                result: win16_abi::MMSYSERR_NODRIVER,
                x: 0,
                y: 0,
                z: 0,
                buttons: 0,
            },
            Operation::ThresholdGet { .. } => Reply::Threshold {
                result: win16_abi::MMSYSERR_NODRIVER,
                value: 0,
            },
            Operation::ThresholdSet { .. }
            | Operation::SetCapture { .. }
            | Operation::ReleaseCapture { .. } => Reply::Status(win16_abi::MMSYSERR_NODRIVER),
        })
    }
    /// Session mixer. The default does not invent a device or a success code.
    fn win16_mixer(
        &mut self,
        _operation: crate::Win16HostMixerOperation,
    ) -> Result<crate::Win16HostMixerResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 mixer services are unavailable",
        ))
    }
    /// Execute an owned direct MSACM request. Guest memory, callbacks, and
    /// 16-bit handles must already have been translated by the runtime.
    fn win16_acm(
        &mut self,
        _operation: crate::Win16HostAcmOperation,
    ) -> Result<crate::Win16HostAcmResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host direct Win16 MSACM services are unavailable",
        ))
    }
    audio_runtime_host_ports!();
    fn win16_network(
        &mut self,
        _call: crate::Win16HostNetworkCall,
    ) -> Result<crate::Win16HostNetworkResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 network services are unavailable",
        ))
    }
    fn win16_peek_network_event(
        &mut self,
    ) -> Result<Option<crate::Win16HostNetworkEvent>, RuntimeError> {
        Ok(None)
    }
    fn win16_ack_network_event(
        &mut self,
        _source: crate::Win16GuestNotificationSource,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 network event acknowledgement is unavailable",
        ))
    }
    fn win16_ole2nls(
        &mut self,
        _operation: crate::Win16NlsOperation,
    ) -> Result<crate::Win16NlsHostResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 NLS services are unavailable",
        ))
    }
    fn win16_ime_profile(
        &mut self,
        _call: crate::Win16HostImeProfileCall,
    ) -> Result<crate::Win16HostImeProfileResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host legacy IME profiles are unavailable",
        ))
    }
    fn win16_path_info(
        &mut self,
        _operation: crate::Win16HostPathInfoOperation,
    ) -> Result<crate::Win16HostPathInfoResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 path information services are unavailable",
        ))
    }
    fn win16_file_system(
        &mut self,
        _call: crate::Win16HostFileSystemCall,
    ) -> Result<crate::Win16HostFileSystemResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file-system services are unavailable",
        ))
    }
    /// Numeric ANSI page selected for this Win16 task's text codec. This is
    /// separate from `DosHost::guest_code_page`, which is the DOS/OEM page.
    fn win16_ansi_code_page(&self) -> u32 {
        u32::from(self.guest_code_page().number())
    }
    fn decode_win16_ansi(&self, bytes: &[u8]) -> Result<String, RuntimeError> {
        self.guest_code_page().decode(bytes).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::InvalidInput,
                "decode Win16 task ANSI text",
                error,
            )
        })
    }
    fn encode_win16_ansi(&self, text: &str) -> Result<Vec<u8>, RuntimeError> {
        self.guest_code_page().encode(text).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::InvalidInput,
                "encode Win16 task ANSI text",
                error,
            )
        })
    }
    /// Resolve a DOS guest path whose canonical cwd components and new guest
    /// components remain separately tagged. The filesystem translates virtual
    /// 8.3 names only for `GuestInput` components, then returns an immutable
    /// canonical identity suitable for owner state and later activation.
    fn normalize_win16_dos_path(
        &mut self,
        owner: OwnerId,
        path: &crate::Win16GuestPath,
    ) -> Result<Option<crate::Win16CanonicalPath>, RuntimeError> {
        if path.namespace != crate::Win16PathNamespace::DosVirtual {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "DOS path normalization received a non-DOS namespace",
            ));
        }
        let call = crate::Win16HostFileSystemCall {
            owner,
            ansi_code_page: self.win16_ansi_code_page(),
            operation: crate::Win16HostFileSystemOperation::NormalizePath {
                path: path.clone(),
                follow_final: false,
                allow_missing_final: true,
            },
        };
        match self.win16_file_system(call)? {
            crate::Win16HostFileSystemResult::NormalizedPath(path) => Ok(path),
            _ => Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "host DOS path normalization returned the wrong result",
            )),
        }
    }
    /// Resolve an existing DOS directory, following its final entry so the
    /// retained owner cwd names the actual directory identity.
    fn normalize_win16_dos_directory(
        &mut self,
        owner: OwnerId,
        path: &crate::Win16GuestPath,
    ) -> Result<Option<crate::Win16CanonicalPath>, RuntimeError> {
        if path.namespace != crate::Win16PathNamespace::DosVirtual {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "DOS directory normalization received a non-DOS namespace",
            ));
        }
        let call = crate::Win16HostFileSystemCall {
            owner,
            ansi_code_page: self.win16_ansi_code_page(),
            operation: crate::Win16HostFileSystemOperation::NormalizePath {
                path: path.clone(),
                follow_final: true,
                allow_missing_final: false,
            },
        };
        match self.win16_file_system(call)? {
            crate::Win16HostFileSystemResult::NormalizedPath(path) => Ok(path),
            _ => Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "host DOS directory normalization returned the wrong result",
            )),
        }
    }
    /// Project a canonical owner directory to DOS's OEM virtual 8.3 spelling
    /// for AH=47h; implementations must not parse canonical components again.
    fn win16_dos_current_directory(
        &mut self,
        _owner: OwnerId,
        path: &crate::Win16CanonicalPath,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if path.drive > 25 {
            return Err(RuntimeError::new(
                DiagnosticKind::InvalidInput,
                "Win16 DOS cwd has an invalid drive",
            ));
        }
        Ok(self
            .guest_code_page()
            .encode(&path.components.join("\\"))
            .ok())
    }
    /// Project a canonical DOS path to the OEM virtual 8.3 spelling used by
    /// FileCDR without another guest-alias lookup.
    fn win16_dos_path_bytes(
        &mut self,
        _owner: OwnerId,
        path: &crate::Win16CanonicalPath,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if path.drive > 25 {
            return Ok(None);
        }
        let mut absolute = String::from(char::from(b'A' + path.drive));
        absolute.push_str(":\\");
        absolute.push_str(&path.components.join("\\"));
        Ok(self.guest_code_page().encode(&absolute).ok())
    }
    /// Activate the retained canonical DOS directory without parsing it through
    /// the alias namespace again or changing process-wide native cwd.
    fn activate_win16_dos_directory(
        &mut self,
        _owner: OwnerId,
        _path: &crate::Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }
    fn win16_shell_icons(
        &mut self,
        _call: crate::Win16HostShellIconCall,
    ) -> Result<crate::Win16HostShellIconResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host shell icon services are unavailable",
        ))
    }
    /// Optional diagnostics must not alter file positions, guest state or errors.
    /// The default keeps service-gate metadata work off in headless hosts.
    fn win16_service_trace_enabled(&self) -> bool {
        false
    }
    fn observe_win16_io(&mut self, _event: &crate::Win16IoEvent<'_>) {}
    fn win16_registry(
        &mut self,
        _operation: crate::Win16HostRegistryOperation,
    ) -> Result<crate::Win16HostRegistryResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 registry services are unavailable",
        ))
    }
    fn win16_keyboard(
        &mut self,
        _call: crate::Win16HostKeyboardCall,
    ) -> Result<crate::Win16HostKeyboardResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 keyboard services are unavailable",
        ))
    }
    /// Owned native callback events, consumed by runtime at a guest safe point.
    fn win16_take_guest_callback(
        &mut self,
    ) -> Result<Option<crate::Win16GuestCallbackEvent>, RuntimeError> {
        Ok(None)
    }
    /// Hosts without a readiness source retain deadline-driven polling.
    fn win16_scheduler_readiness(&self) -> Option<Win16SchedulerReadiness> { None }
    /// Native producers receive an opaque channel endpoint, never a guest FAR.
    fn win16_guest_callback_sender(&self) -> Option<crate::Win16GuestCallbackSender> {
        None
    }
    fn win16_register_window_message(&mut self, _name: Option<&[u8]>) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host registered window messages are unavailable",
        ))
    }
    fn win16_register_clipboard_format(
        &mut self,
        _name: Option<&[u8]>,
    ) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host clipboard format registration is unavailable",
        ))
    }
    fn win16_clipboard_format_name(
        &mut self,
        _format: u16,
        _buffer: Vec<u8>,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host clipboard format name lookup is unavailable",
        ))
    }
    fn win16_create_dc(
        &mut self,
        _driver: Option<&[u8]>,
        _device: Option<&[u8]>,
        _output: Option<&[u8]>,
        _devmode: Option<&crate::Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 device context creation is unavailable",
        ))
    }
    fn win16_create_ic(
        &mut self,
        _driver: Option<&[u8]>,
        _device: Option<&[u8]>,
        _output: Option<&[u8]>,
        _devmode: Option<&crate::Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 information context creation is unavailable",
        ))
    }
    fn win16_get_outline_text_metrics(
        &mut self,
        _dc: Win16HostDc,
    ) -> Result<Option<crate::Win16HostOutlineTextMetrics>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 outline text metrics are unavailable",
        ))
    }
    fn win16_get_text_metrics(
        &mut self,
        _dc: Win16HostDc,
    ) -> Result<Option<crate::Win16HostTextMetrics>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 text metrics are unavailable",
        ))
    }
    fn win16_get_text_face(
        &mut self,
        _dc: Win16HostDc,
        _count: i16,
        _output: Option<Vec<u8>>,
    ) -> Result<Option<crate::Win16HostTextFace>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 font face lookup is unavailable",
        ))
    }
    fn win16_gdi(
        &mut self,
        _operation: crate::Win16DrawingOperation,
    ) -> Result<crate::Win16DrawingResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 GDI drawing is unavailable",
        ))
    }
    fn win16_gdi_services(
        &mut self,
        _operation: crate::Win16GdiServicesOperation,
    ) -> Result<crate::Win16GdiServicesResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 GDI service is unavailable",
        ))
    }
    /// Owned spool tokens cross this boundary; guest HFILEs do not.
    fn win16_spool(
        &mut self,
        _operation: crate::Win16HostSpoolOperation,
    ) -> Result<crate::Win16HostSpoolResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 spool services are unavailable",
        ))
    }
    fn win16_network_print_queues(
        &mut self,
        _operation: crate::Win16HostNetworkQueueOperation,
    ) -> Result<crate::Win16HostNetworkQueueResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 network print queue services are unavailable",
        ))
    }
    fn win16_network_redirector(
        &mut self,
        _call: crate::Win16HostNetworkRedirectorCall,
    ) -> Result<crate::Win16HostNetworkRedirectorResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host network redirector is unavailable",
        ))
    }
    fn win16_create_gdi_object(
        &mut self,
        _operation: crate::Win16GdiObjectOperation,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 GDI object creation is unavailable",
        ))
    }
    fn win16_gdi_bitmap(
        &mut self,
        _operation: crate::Win16GdiBitmapOperation,
    ) -> Result<crate::Win16GdiBitmapResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DIB transfer is unavailable",
        ))
    }
    fn win16_gdi_device(
        &mut self,
        _operation: crate::Win16GdiDeviceOperation,
    ) -> Result<crate::Win16GdiDeviceResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 GDI device operation is unavailable",
        ))
    }
    fn win16_printer_capabilities(
        &mut self,
        _request: crate::Win16PrinterCapabilities,
    ) -> Result<crate::Win16PrinterCapabilitiesResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 printer capability query is unavailable",
        ))
    }
    fn win16_read_module(
        &mut self,
        _name: &[u8],
        _application_path: &[u8],
    ) -> Result<Result<Win16ModuleImage, u16>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 module file search is unavailable",
        ))
    }
    /// Resolve an executable name using the calling task's directory and PATH,
    /// returning an owned bounded image for LoadModule's DLL/EXE decision.
    fn win16_read_program_image(
        &mut self,
        _input: &crate::Win16HostProgramLoadInput,
    ) -> Result<Result<Win16ModuleImage, u16>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host task-aware program image loading is unavailable"))
    }
    /// KERNEL loader search with a path resolved in the calling Win16 task.
    /// `path` includes the default DLL extension when the name omitted one;
    /// only a simple `name` permits fallback to the Windows/system/app/PATH
    /// directories. The host process current directory is not task state.
    fn win16_read_task_module(
        &mut self,
        _name: &[u8],
        _application_path: &[u8],
        _path: &crate::Win16GuestPath,
    ) -> Result<Result<Win16ModuleImage, u16>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host task-aware Win16 module file search is unavailable",
        ))
    }
    /// Reports an informational or recoverable condition without changing
    /// guest registers or execution flow. Normal guest error codes stay quiet.
    fn report_diagnostic(&mut self, _diagnostic: &Diagnostic) {}
    /// Observe a completed DOS INT 21h service using copied guest register
    /// state. Implementations must not use this callback to alter execution.
    fn observe_dos_service(
        &mut self,
        _instruction_count: u64,
        _before: &GuestRegisters,
        _after: &GuestRegisters,
    ) {
    }
    fn epoch_seconds(&self) -> i64;
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError>;
    fn try_read_bios_key(&mut self) -> Result<Option<KeyStroke>, RuntimeError> {
        Ok(None)
    }
    fn pump_events(&mut self) -> Result<(), RuntimeError> {
        Ok(())
    }
    /// Whether this runtime host has a mouse input source for the guest.
    fn mouse_available(&self) -> bool {
        false
    }
    /// Take one host mouse event after `pump_events` has collected pending UI
    /// messages. Coordinates use the emulated 640x200 mouse text space.
    fn take_mouse_input(&mut self) -> Result<Option<MouseInput>, RuntimeError> {
        Ok(None)
    }
    /// Re-anchor host-to-guest mouse coordinate mapping for INT 33h function 04h.
    fn set_mouse_position(&mut self, _x: u16, _y: u16) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host mouse repositioning is unavailable",
        ))
    }
    fn render_text(&mut self, screen: &ConsoleSnapshot) -> Result<(), RuntimeError>;
    fn render_graphics(&mut self, _frame: &devices::vga::VgaFrame) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host graphics output is unavailable",
        ))
    }
    /// Establish the host thread's native USER message queue for a Win16 task.
    fn win16_initialize_user_queue(&mut self) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER message queue initialization is unavailable",
        ))
    }
    /// Bind one exact Win16 task incarnation to the host worker's already
    /// created USER queue. `None` means this host has no separate task queue;
    /// callers must not substitute the current queue for a foreign task.
    fn win16_bind_task_queue(
        &mut self,
        _owner: guest_core::OwnerId,
        _guest_htask: u16,
        _task_selector_generation: u64,
    ) -> Result<Option<crate::Win16HostTaskQueue>, RuntimeError> {
        Ok(None)
    }
    /// Retire an exact queue incarnation after its task and accepted receipts
    /// are quiescent. Native carrier tombstones remain until dequeue/teardown.
    fn win16_retire_task_queue(
        &mut self,
        _owner: guest_core::OwnerId,
        _guest_htask: u16,
        _task_selector_generation: u64,
        _queue: crate::Win16HostTaskQueue,
    ) -> Result<bool, RuntimeError> {
        Ok(false)
    }
    fn win16_register_window_class(
        &mut self,
        _spec: Win16HostClassSpec,
    ) -> Result<Option<Win16RegisteredClass>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 window class registration is unavailable",
        ))
    }
    /// Replace one resource on the native class that `window` belongs to.
    /// `window` must be a live host window of `class`; the host must confirm
    /// that exact pairing and never substitute another class or a borrowed
    /// HWND alias. `Ok(false)` means the replacement was refused and no class
    /// field changed, so the runtime keeps the previous guest value.
    fn win16_replace_class_resource(
        &mut self,
        _class: Win16HostClass,
        _window: Win16HostWindow,
        _resource: Win16HostClassResource,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 class resource replacement is unavailable",
        ))
    }
    fn win16_system_class_info(
        &mut self,
        _class: Win16HostSystemClass,
    ) -> Result<Option<Win16HostSystemClassInfo>, RuntimeError> {
        Ok(None)
    }
    fn win16_control_identity(
        &mut self,
        query: crate::Win16HostControlQuery,
    ) -> Result<crate::Win16HostControlQueryReply, RuntimeError> {
        Ok(crate::Win16HostControlQueryReply {
            window: query.window,
            dispatch: query.dispatch,
            identity: None,
        })
    }
    fn win16_window_enumeration(
        &mut self,
        _query: crate::Win16WindowEnumerationQuery,
    ) -> Result<crate::Win16WindowEnumerationReply, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host USER window enumeration is unavailable",
        ))
    }
    /// Yield the executing host thread for a Win16 task without a USER queue.
    fn win16_yield_thread(&mut self) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host thread yielding is unavailable",
        ))
    }
    /// Report executable linking/LibMain completion to an optional launch owner.
    /// `Err(0)` is a failed initialization, distinct from a loaded program.
    fn win16_program_load_result(&mut self, _result: Result<(), u16>) -> Result<(), RuntimeError> {
        Ok(())
    }
    fn win16_unregister_window_class(
        &mut self,
        _class: Win16HostClass,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 window class removal is unavailable",
        ))
    }
    fn win16_destroy_window(&mut self, _window: Win16HostWindow) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 native window destruction is unavailable",
        ))
    }
    /// Read style and iconic state for `Ctl3dDlgFramePaint`. `Ok(None)` means
    /// the token is not a live window. This must not call the window procedure.
    fn win16_ctl3d_frame(
        &mut self,
        _window: Win16HostWindow,
    ) -> Result<Option<crate::Win16HostCtl3dFrameFacts>, RuntimeError> {
        Ok(None)
    }
    /// Query only the exact opaque window incarnation. The host must return
    /// `Retired` only for a token it can prove was issued and later retired;
    /// unknown or mismatched identities remain errors.
    fn win16_host_window_liveness(
        &mut self,
        _window: Win16HostWindow,
    ) -> Result<Win16HostWindowLiveness, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 exact-window liveness query is unavailable",
        ))
    }
    /// Read child ancestry for one exact incarnation while USER is suspended.
    /// This must not invoke a callback, resume an operation, or treat a failed
    /// identity/parent query as a successful absent parent.
    fn win16_host_window_parent(
        &mut self,
        _window: Win16HostWindow,
    ) -> Result<crate::Win16HostWindowParentObservation, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 exact-window parent observation is unavailable",
        ))
    }
    fn win16_window_begin(
        &mut self,
        _operation: Win16WindowOperation,
    ) -> Result<Win16WindowStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 synchronous window operations are unavailable",
        ))
    }
    fn win16_window_resume(
        &mut self,
        _reply: Option<Win16WindowReply>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 window callback continuation is unavailable",
        ))
    }
    /// Begin one exact classic WM_DDE operation on the native USER worker.
    /// This operation has its own continuation stack and does not consume a
    /// GetMessage/WaitMessage proof or a DDEML transaction.
    fn win16_classic_dde_begin(
        &mut self,
        _call: crate::Win16HostClassicDdeCall,
    ) -> Result<crate::Win16HostClassicDdeStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host classic WM_DDE operations are unavailable",
        ))
    }
    /// Resume only the exact top classic WM_DDE operation, optionally with
    /// the callback answer for its currently suspended endpoint frame.
    fn win16_classic_dde_resume(
        &mut self,
        _resume: crate::Win16HostClassicDdeResume,
    ) -> Result<crate::Win16HostClassicDdeStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host classic WM_DDE continuation is unavailable",
        ))
    }
    /// Consume one source-retirement proof only after the runtime business
    /// journal has committed its exact terminal result.
    fn win16_classic_dde_source_retirement_consumed(
        &mut self,
        _proof: &crate::Win16HostClassicDdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host classic WM_DDE source retirement is unavailable",
        ))
    }
    /// Poll an exact native HDROP retirement at a guest safe point. The host
    /// retains the receipt until the runtime separately acknowledges it.
    fn win16_take_native_drop_retirement(
        &mut self,
    ) -> Result<Option<crate::Win16HostDropRetirementReceipt>, RuntimeError> {
        Ok(None)
    }
    fn win16_ack_native_drop_retirement(
        &mut self,
        _receipt: crate::Win16HostDropRetirementReceipt,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host native WM_DROPFILES retirement acknowledgement is unavailable",
        ))
    }
    /// Receive the next response without acknowledging a suspended callback,
    /// operation, or guest-work source.
    fn win16_window_receive_pending(&mut self) -> Result<Win16WindowStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 pending window response polling is unavailable",
        ))
    }
    /// Resume the exact native modal continuation published by the USER worker.
    fn win16_window_resume_modal_guest_work(
        &mut self,
        _operation_id: crate::Win16HostWindowOperationId,
        _scope_id: u64,
        _generation: u64,
        _marker_id: Option<u64>,
        _wake_generation: Option<u64>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 modal guest-work continuation is unavailable",
        ))
    }
    /// Cancel suspended operations before terminal guest cleanup. No guest
    /// procedure may be scheduled by subsequent destruction on this path.
    fn win16_window_abort(&mut self) -> Result<crate::Win16WindowAbortReceipt, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER terminal quiescence receipt is unavailable",
        ))
    }
    /// Retire one exact USER operation source after runtime-owned callback
    /// payloads, modal terminal slot, and full guest context have been cleaned.
    fn win16_window_terminal_ack(
        &mut self,
        _ack: crate::Win16WindowTerminalAck,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER terminal source acknowledgement is unavailable",
        ))
    }
    /// Read back whether the exact USER terminal ACK already retired its
    /// source. `false` is valid only for that ACK on the current exact live
    /// source top; unknown, changed, or non-top identities are errors.
    fn win16_window_terminal_acknowledged(
        &mut self,
        _receipt: &crate::Win16WindowAbortReceipt,
        _ack: &crate::Win16WindowTerminalAck,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER terminal ACK readback is unavailable",
        ))
    }
    /// Inspect the live shared USER/DDE pending-source ledger without
    /// consuming it. `None` means that exact ledger is empty; identity or
    /// receipt mismatches must return an error instead.
    fn win16_window_terminal_source_top(
        &mut self,
        _receipt: &crate::Win16WindowAbortReceipt,
    ) -> Result<Option<crate::Win16WindowTerminalSourceTop>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER/DDE terminal source-top query is unavailable",
        ))
    }
    /// Read back an exact USER normal-completion/source-retirement proof.
    /// `None` is reserved for the same validated operation still being live;
    /// unknown or mismatched identities must return an error.
    fn win16_window_source_retirement(
        &mut self,
        _operation: crate::Win16NativeWindowOperationProof,
        _worker_generation: u64,
    ) -> Result<Option<std::sync::Arc<crate::Win16WindowSourceRetiredProof>>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER normal source-retirement proof is unavailable",
        ))
    }
    /// Retry only the already-returned Complete cached by the same native
    /// USER operation owner. This must not submit work, receive a worker
    /// event, or repeat any output effect whose phase already committed.
    fn win16_window_retry_cached_completion(
        &mut self,
        _operation: crate::Win16NativeWindowOperationProof,
        _worker_generation: u64,
    ) -> Result<Win16WindowStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 cached normal completion retry is unavailable",
        ))
    }
    /// Release the exact bounded normal-completion tombstone after runtime
    /// projection, context restoration, and operation-frame retirement.
    fn win16_window_source_retirement_consumed(
        &mut self,
        _proof: &crate::Win16WindowSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 USER normal source-retirement consumption is unavailable",
        ))
    }
    fn win16_output_debug_string(&mut self, _message: &[u8]) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 debug output service is unavailable",
        ))
    }
    /// Present a Win16 USER MessageBox through the host ANSI window API.
    /// The byte strings are owned, NUL-free Windows ANSI text, not guest pointers.
    fn win16_message_box(
        &mut self,
        _text: &[u8],
        _caption: &[u8],
        _style: u16,
    ) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 message box forwarding is unavailable",
        ))
    }
    /// Convert copied bytes from the configured guest OEM page to host ANSI.
    fn win16_oem_to_ansi(&mut self, _source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 OEM-to-ANSI conversion is unavailable",
        ))
    }
    /// Classify one guest byte using the configured guest codec and native NLS.
    fn win16_classify_character(
        &mut self,
        _value: u8,
        _classification: win16_abi::Win16CharacterClassification,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 character classification is unavailable",
        ))
    }
    fn win16_ansi_lower_char(&mut self, _value: u16) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI character case conversion is unavailable",
        ))
    }
    fn win16_ansi_lower_string(&mut self, _source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI string case conversion is unavailable",
        ))
    }
    /// Convert text within its original guest byte capacity. Name
    /// normalization uses the separate, unbounded lowercase operation.
    fn win16_ansi_case_string_in_place(
        &mut self,
        _source: &[u8],
        _upper: bool,
    ) -> Result<Vec<u8>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 in-place case conversion is unavailable",
        ))
    }
    fn win16_ansi_upper_char(&mut self, _value: u16) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI uppercase character conversion is unavailable",
        ))
    }
    fn win16_ansi_upper_string(&mut self, _source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI uppercase string conversion is unavailable",
        ))
    }
    fn win16_ansi_case_buffer(
        &mut self,
        _source: &[u8],
        _upper: bool,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI case-buffer conversion is unavailable",
        ))
    }
    fn win16_ansi_compare(
        &mut self,
        _left: &[u8],
        _right: &[u8],
        _ignore_case: bool,
    ) -> Result<i16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI string comparison is unavailable",
        ))
    }
    /// Probe a one-to-four-byte prefix using the fixed Win16 guest ANSI page.
    /// Missing bytes are not NUL; unsupported encodings must return an error.
    fn win16_ansi_next_probe(
        &mut self, _source: &[u8],
    ) -> Result<Win16AnsiNextProbe, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI next-character lookup is unavailable",
        ))
    }
    fn win16_ansi_prev_offset(
        &mut self,
        _source: &[u8],
        _current: usize,
    ) -> Result<usize, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 ANSI previous-character lookup is unavailable",
        ))
    }
    fn win16_file_create(
        &mut self,
        _path: &crate::Win16GuestPath,
        _attributes: u16,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file creation forwarding is unavailable",
        ))
    }
    fn win16_file_open(
        &mut self,
        _path: &crate::Win16GuestPath,
        _mode: u16,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file opening forwarding is unavailable",
        ))
    }
    fn win16_open_file(
        &mut self,
        _path: &crate::Win16GuestPath,
        _search_name: Option<&str>,
        _style: u16,
        _previous_ofstruct: Vec<u8>,
    ) -> Result<Win16HostOpenFile, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 OpenFile forwarding is unavailable"))
    }
    fn win16_file_read(
        &mut self,
        _file: Win16HostFile,
        _count: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file reading forwarding is unavailable",
        ))
    }
    fn win16_file_seek(
        &mut self,
        _file: Win16HostFile,
        _offset: i32,
        _origin: u16,
    ) -> Result<Option<i32>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file seeking forwarding is unavailable",
        ))
    }
    fn win16_file_write(
        &mut self,
        _file: Win16HostFile,
        _data: &[u8],
    ) -> Result<Option<u32>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file writing forwarding is unavailable",
        ))
    }
    fn win16_file_close(
        &mut self,
        _file: Win16HostFile,
    ) -> Result<Win16HostFileClose, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 file closing forwarding is unavailable",
        ))
    }
    /// Commit the same owned open object without moving its cursor or
    /// changing access/sharing. A proven read-only disk open has no writes
    /// to commit; a backend must never reopen a pathname to obtain rights.
    fn win16_file_commit(
        &mut self,
        _file: Win16HostFile,
    ) -> Result<(), dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    /// Return (packed DOS local time, packed DOS local date) for the owned
    /// open object, including read-only files. No guest pointer crosses here.
    fn win16_file_write_time(
        &mut self,
        _file: Win16HostFile,
    ) -> Result<(u16, u16), dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    /// Update only last-write time through the retained object and its
    /// existing rights. Validate DOS calendar fields and local-zone rules.
    fn win16_file_set_write_time(
        &mut self,
        _file: Win16HostFile,
        _time: u16,
        _date: u16,
    ) -> Result<(), dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    /// Query the owned open mode before DOS inspects a caller buffer. This
    /// is authoritative host state, never a guest-writable SFT projection.
    fn win16_file_dos_access(
        &mut self,
        _file: Win16HostFile,
    ) -> Result<dos_kernel::DosFileAccess, dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    /// DOS transfers borrow host-owned buffers, never guest addresses. Keep
    /// short reads/writes, and validate access even for a zero-byte transfer.
    fn win16_dos_file_read(
        &mut self,
        _file: Win16HostFile,
        _output: &mut [u8],
    ) -> Result<usize, dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    /// Empty disk writes truncate/extend at the current position. Empty
    /// character-device writes do not apply disk truncation semantics.
    fn win16_dos_file_write(
        &mut self,
        _file: Win16HostFile,
        _input: &[u8],
    ) -> Result<usize, dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    /// DOS Start offsets use all 32 bits; Current/End offsets are signed.
    /// Reject an unrepresentable target before changing the shared cursor.
    fn win16_dos_file_seek(
        &mut self,
        _file: Win16HostFile,
        _offset: i32,
        _origin: dos_kernel::DosSeekOrigin,
    ) -> Result<u32, dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    fn win16_dos_file_close(
        &mut self,
        _file: Win16HostFile,
    ) -> Result<Win16HostFileClose, dos_kernel::DosHostError> {
        Err(dos_kernel::DosHostError::new(dos_kernel::DosErrorCode::InvalidFunction))
    }
    fn win16_lz_start(&mut self) -> Result<i16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ initialization is unavailable",
        ))
    }
    fn win16_lz_done(&mut self) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ shutdown is unavailable",
        ))
    }
    fn win16_lz_open_file(
        &mut self,
        _path: &crate::Win16GuestPath,
        _search_name: Option<&str>,
        _style: u16,
        _ofstruct: Vec<u8>,
    ) -> Result<Win16HostLzOpen, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ file open is unavailable",
        ))
    }
    fn win16_lz_init(
        &mut self,
        _file: Win16HostFile,
        _can_create_stream: bool,
    ) -> Result<Win16HostLzInit, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ stream initialization is unavailable",
        ))
    }
    fn win16_lz_read(
        &mut self,
        _file: Win16HostFile,
        _count: u16,
    ) -> Result<Option<Win16HostLzRead>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ read is unavailable",
        ))
    }
    fn win16_lz_seek(
        &mut self,
        _file: Win16HostFile,
        _offset: i32,
        _origin: u16,
    ) -> Result<Option<i32>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ seek is unavailable",
        ))
    }
    fn win16_lz_close(&mut self, _file: Win16HostFile) -> Result<Win16HostFileClose, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ close is unavailable",
        ))
    }
    fn win16_lz_copy(
        &mut self,
        _source: Win16HostFile,
        _destination: Win16HostFile,
    ) -> Result<Option<i32>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host LZ copy is unavailable",
        ))
    }
    fn win16_lz_get_expanded_name(
        &mut self,
        _source: &[u8],
        _path: &crate::Win16GuestPath,
        _search_name: Option<&str>,
    ) -> Result<Win16HostLzName, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host expanded file name is unavailable",
        ))
    }
    fn win16_ver_resource_size(
        &mut self,
        _path: &[u8],
        _resource_type: &crate::Win16HostResourceName,
        _resource_name: &crate::Win16HostResourceName,
    ) -> Result<Option<(u32, u32)>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host file resource size is unavailable",
        ))
    }
    fn win16_ver_resource(
        &mut self,
        _path: &[u8],
        _resource_type: &crate::Win16HostResourceName,
        _resource_name: &crate::Win16HostResourceName,
        _offset: u32,
        _count: u32,
        _initial: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host file resource read is unavailable",
        ))
    }
    fn win16_ver_file_info_size(
        &mut self,
        _path: &[u8],
    ) -> Result<Option<(u32, u32)>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host version information size is unavailable",
        ))
    }
    fn win16_ver_file_info(
        &mut self,
        _path: &[u8],
        _handle: u32,
        _initial: Vec<u8>,
    ) -> Result<Option<(Vec<u8>, u32)>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host version information read is unavailable",
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn win16_ver_find_file(
        &mut self,
        _flags: u16,
        _file: &[u8],
        _windows_dir: &[u8],
        _app_dir: &[u8],
        _dir_buffer: Vec<u8>,
        _dir_capacity: u16,
        _file_buffer: Vec<u8>,
        _file_capacity: u16,
    ) -> Result<(u32, Vec<u8>, u16, Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host version file search is unavailable",
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn win16_ver_install_file(
        &mut self,
        _flags: u16,
        _source: &[u8],
        _destination: &[u8],
        _source_dir: &[u8],
        _destination_dir: &[u8],
        _current_dir: &[u8],
        _scratch: Vec<u8>,
        _capacity: u16,
    ) -> Result<(u32, Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host version file installation is unavailable",
        ))
    }
    fn win16_ver_language_name(
        &mut self,
        _language: u16,
        _initial: Vec<u8>,
    ) -> Result<(Vec<u8>, u32), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host version language name is unavailable",
        ))
    }
    /// Returns an offset into the owned input, never a pointer into native memory.
    fn win16_ver_query_value(
        &mut self,
        _block: Vec<u8>,
        _sub_block: &[u8],
    ) -> Result<Option<(usize, u32)>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host version value query is unavailable",
        ))
    }
    fn win16_drive_kind(&mut self, _drive: u16) -> Result<Win16HostDriveKind, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 drive-type query is unavailable",
        ))
    }
    fn win16_set_handle_count(&mut self, _requested_count: u16) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 SetHandleCount forwarding is unavailable",
        ))
    }
    /// Set process-wide Win16 error flags and return the previous Windows mode.
    fn win16_set_error_mode(&mut self, _mode: u16) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 SetErrorMode forwarding is unavailable",
        ))
    }
    graphics_runtime_host_ports!();
    fn win16_global_add_atom(&mut self, _name: Win16HostAtomName<'_>) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 global atom insertion is unavailable",
        ))
    }
    fn win16_global_find_atom(
        &mut self,
        _name: Win16HostAtomName<'_>,
    ) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 global atom lookup is unavailable",
        ))
    }
    /// Confirm native reference deletion independently of the guest ATOM return.
    fn win16_global_delete_atom(&mut self, _atom: u16) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 global atom deletion is unavailable",
        ))
    }
    fn win16_global_get_atom_name(
        &mut self,
        _atom: u16,
        _capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 global atom name lookup is unavailable",
        ))
    }
    fn win16_wnet_get_caps(&mut self, _index: u16) -> Result<u16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host legacy network capability query is unavailable",
        ))
    }

    fn win16_get_tick_count(&mut self) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 tick count is unavailable",
        ))
    }
    fn win16_message_beep(&mut self, _kind: u32) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MessageBeep is unavailable",
        ))
    }
    fn win16_get_key_state(&mut self, _key: i32, _asynchronous: bool) -> Result<i16, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 key state is unavailable",
        ))
    }
    /// Read the screen pointer and the two keys DragDetect watches.
    ///
    /// `wait_for_change` asks the host to block until the sample differs from
    /// the previous poll in this process. A host that cannot wait returns the
    /// current sample; the runtime stops if that sample repeats.
    fn win16_drag_poll(&mut self, _wait_for_change: bool) -> Result<Win16DragSample, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 drag sample is unavailable",
        ))
    }
    fn win16_get_system_metrics(&mut self, _index: i32) -> Result<i32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 system metrics are unavailable",
        ))
    }
    fn win16_get_double_click_time(&mut self) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host double-click time query is unavailable",
        ))
    }
    fn win16_set_double_click_time(&mut self, _milliseconds: u32) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host double-click time update is unavailable",
        ))
    }
    fn win16_get_caret_blink_time(&mut self) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host caret blink time query is unavailable",
        ))
    }
    fn win16_set_caret_blink_time(&mut self, _milliseconds: u32) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host caret blink time update is unavailable",
        ))
    }
    fn win16_get_sys_color(&mut self, _index: i32) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host system color query is unavailable",
        ))
    }
    fn win16_swap_mouse_button(&mut self, _swap: bool) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host mouse-button swap is unavailable",
        ))
    }
    /// Read the native desktop-wide owned, visible top-level window predicate.
    /// An unavailable host query must not be represented as a negative answer.
    fn win16_any_popup(&mut self) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host AnyPopup query is unavailable",
        ))
    }
    fn win16_get_dialog_base_units(&mut self) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host dialog base units query is unavailable",
        ))
    }
    fn win16_profile_int(
        &mut self,
        _section: Option<&[u8]>,
        _key: Option<&[u8]>,
        _default: i32,
        _filename: &Win16ProfilePath,
    ) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 profile integer read is unavailable",
        ))
    }
    fn win16_system_profile_int(
        &mut self,
        _section: Option<&[u8]>,
        _key: Option<&[u8]>,
        _default: i32,
    ) -> Result<u32, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 system profile integer read is unavailable",
        ))
    }
    fn win16_profile_string(
        &mut self,
        _section: Option<&[u8]>,
        _key: Option<&[u8]>,
        _default: Option<&[u8]>,
        _filename: &Win16ProfilePath,
        _capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 profile string read is unavailable",
        ))
    }
    fn win16_system_profile_string(
        &mut self,
        _section: Option<&[u8]>,
        _key: Option<&[u8]>,
        _default: Option<&[u8]>,
        _capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 system profile string read is unavailable",
        ))
    }
    fn win16_profile_write(
        &mut self,
        _section: Option<&[u8]>,
        _key: Option<&[u8]>,
        _value: Option<&[u8]>,
        _filename: &Win16ProfilePath,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 profile write is unavailable",
        ))
    }
    fn win16_profile_section(
        &mut self,
        _section: Option<&[u8]>,
        _filename: &Win16ProfilePath,
        _capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 profile-section read is unavailable",
        ))
    }
    fn win16_system_profile_section(
        &mut self,
        _section: Option<&[u8]>,
        _capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 system profile-section read is unavailable",
        ))
    }
    fn win16_profile_section_write(
        &mut self,
        _section: Option<&[u8]>,
        _entries: Option<&[u8]>,
        _filename: &Win16ProfilePath,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 profile-section write is unavailable",
        ))
    }
    fn win16_system_profile_section_write(
        &mut self,
        _section: Option<&[u8]>,
        _entries: Option<&[u8]>,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 system profile-section write is unavailable",
        ))
    }

    /// Open one named communications device. The token is host-owned.
    fn win16_comm_open(
        &mut self,
        _device: Win16HostCommDevice,
        _in_queue: u16,
        _out_queue: u16,
    ) -> Result<Win16HostCommPort, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications port is unavailable",
        ))
    }

    /// Read bytes already available from one open port into `output`.
    fn win16_comm_read(
        &mut self,
        _port: Win16HostCommPort,
        _output: &mut [u8],
    ) -> Result<usize, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications read is unavailable",
        ))
    }

    /// Write bytes to one open port. The returned count is at most `input.len()`.
    fn win16_comm_write(
        &mut self,
        _port: Win16HostCommPort,
        _input: &[u8],
    ) -> Result<usize, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications write is unavailable",
        ))
    }

    /// Close one open port token. A second close of the same token fails.
    fn win16_comm_close(&mut self, _port: Win16HostCommPort) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications close is unavailable",
        ))
    }

    /// Apply serial parameters to one open device. `LPT` tokens cannot accept this.
    fn win16_comm_configure(
        &mut self,
        _port: Win16HostCommPort,
        _config: &Win16HostCommConfig,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications configuration is unavailable",
        ))
    }

    /// Apply break or a modem-control escape to one open serial device.
    fn win16_comm_control(
        &mut self,
        _port: Win16HostCommPort,
        _control: Win16HostCommControl,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications line control is unavailable",
        ))
    }

    /// Discard one driver queue. The guest unget byte is separate.
    fn win16_comm_flush(
        &mut self,
        _port: Win16HostCommPort,
        _queue: Win16HostCommQueue,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 communications flush is unavailable",
        ))
    }
}
