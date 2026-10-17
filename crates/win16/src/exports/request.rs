//! Owned, checked values that describe decoded Win16 export calls.

use super::user_family::Win16UserFamilyRequest;
use crate::user_abi::Msg16;
use crate::window_geometry::Rect16;
use crate::{Point16, Win16RegisterContext};

#[path = "request/request_modules.rs"]
mod request_modules;
pub use request_modules::{Win16UserNetworkBuffer, Win16UserNetworkRequest};
pub use request_modules::Win16UserHooksRequest;
pub use request_modules::Win16WinnlsRequest;
pub use request_modules::Win16PrintQueueRequest;
pub use request_modules::Win16KernelFileSystemRequest;
pub use request_modules::Win16KernelInstanceRequest;
pub use request_modules::Win16Ole1Request;
pub use request_modules::Win16UserMdiRequest;
pub use request_modules::Win16UserChildLookupRequest;
pub use request_modules::{Win16FontResourceInput, Win16GdiServicesRequest, Win16GdiSpoolRequest};
pub use request_modules::{NF_NORMAL, NF_TASKSWITCH, NF_RIP};
pub(super) use request_modules::decode_print_queue_export;
pub use request_modules::{
    DecodedWin16Call, DibColorTableKind, DibRgbQuad16, DocInfo16, GdiDeviceRequest,
    MMCKINFO16_SIZE, MMIOINFO16_ERROR_OFFSET, MMIOINFO16_SIZE, MMTIME16_SIZE, PaletteEntry16,
    PaletteTransferKind, PrintOperation, TIMECAPS16_SIZE, WAVEHDR16_BYTES_RECORDED_OFFSET,
    WAVEHDR16_FLAGS_OFFSET, WAVEHDR16_SIZE, WAVEINCAPS16_SIZE, WAVEOUTCAPS16_SIZE,
    Win16AcceleratorEntry, Win16AcceleratorResourceError, Win16AnsiCaseTarget, Win16AsyncLookup,
    Win16AtomName, Win16ClassDataRequest, Win16ClassName, Win16CommctrlRequest,
    Win16CommdlgRequest, Win16Ctl3dArgument,
    Win16MultimediaArgument, Win16MultimediaCall,
    Win16Ctl3dModule, Win16Ctl3dRequest, Win16DdeBuffer, Win16DdeRequest, Win16DdeTransactionData,
    Win16DestroyImageRequest, Win16GdiDrawingRequest, Win16GdiObjectsRequest, Win16GdiTextRequest,
    Win16GuestBuffer, Win16GuestImageKind, Win16GuestInOutBuffer, Win16HelpData, Win16HostQuery,
    Win16KernelAtomsRequest, Win16KernelDiagnosticRequest, Win16KernelFilesRequest,
    Win16KernelGlobalHeapRequest,
    Win16KernelGlobalMemoryRequest, Win16KernelLocalHeapRequest, Win16KernelMemoryRequest,
    Win16KernelModuleRequest, Win16KernelModulesRequest, Win16KernelPathInfoRequest,
    Win16KernelProfileSectionRequest, Win16KernelProfilesRequest, Win16KernelRequest,
    Win16KernelResourcesRequest, Win16KernelRuntimeRequest, Win16KernelSelectorsRequest,
    Win16KernelStringRequest, Win16KernelStringsRequest, Win16KernelTaskRequest,
    Win16KeyboardConversion, Win16KeyboardRequest, Win16LibraryCodePageRequest,
    Win16LibraryInterruptsRequest, Win16LibraryRequest, Win16LibraryStringsRequest,
    Win16LibraryToolhelpRequest, Win16LzExpandRequest, Win16MediaIoRequest, Win16MediaTimeRequest,
    Win16MidiDirection, Win16MidiRequest, Win16MidiStreamArgument,
    MIDIHDR16_SIZE, MIDIINCAPS16_SIZE, MIDIOUTCAPS16_SIZE, Win16MidiHeader16,
    Win16MidiInCaps16, Win16MidiOutCaps16,
    Win16SoundPlayApi, Win16SoundRequest,
    Win16MciOpenExtension, Win16MciOpenValue, Win16MciOutputBuffer, Win16MciParameters,
    Win16MciGuestRange, Win16MciRequest, Win16MciResourceName, Win16MciSetExtension,
    Win16MmckInfo16, Win16Mmtime16, Win16ModuleReference, Win16Ole2DispArgument, Win16Ole2DispCall,
    Win16Ole2DispConvertCall, Win16Ole2DispConvertInput, Win16Ole2DispConvertOperation,
    Win16Ole2DispLocaleFlags, Win16Ole2NlsRequest, Win16Ole2NlsString, Win16OutputBuffer,
    Win16PrinterRequest, Win16ProcReference, Win16ResourceName, Win16SelectInput,
    Win16ShellDropRequest, Win16ShellDriveRequest, Win16ShellExecutionRequest,
    Win16ShellIconRequest, Win16ShellRegistryRequest,
    Win16ShellRequest, Win16SocketSetInput, Win16StringComparison, Win16SystemRequest,
    Win16TimeCaps16, Win16ToolhelpRequest, Win16ToolhelpStackRequest, Win16CharacterClassification, Win16UserAnsiRequest,
    Win16UserAtomsRequest, Win16UserCursorAcceleratorRequest, Win16UserDrawingRequest,
    Win16UserGeometryRequest, Win16UserMenuRequest, Win16UserMessagesRequest, Win16UserRequest,
    Win16UserResourcesRequest, Win16UserRuntimeRequest, Win16UserScrollBarRequest,
    Win16UserStringFormatRequest,
    Win16UserSystemRequest, Win16UserCommRequest, Win16UserTextRequest, Win16UserUpdateRequest, Win16UserWindowRequest,
    Win16VerRequest, Win16WaveControl, Win16WaveDirection, Win16WaveHeader16,
    Win16WaveInputCapabilities16, Win16WaveOutputCapabilities16, Win16WaveParameter,
    Win16WaveRequest, Win16WindowDataRequest, Win16WindowPropertyName, Win16WindowPropertyRequest,
    Win16WinsockDecodeFailure, Win16WinsockRequest, decode_accelerator_resource,
};
pub(crate) use request_modules::{
    HELP_WINDOW_INFO16_HEADER_BYTES, HELP_WINDOW_INFO16_MIN_BYTES, HelpWindowInfo16HeaderWire,
    MultiKeyHelp16HeaderWire,
};
pub(super) use request_modules::{
    dde, decode_destroy_image, decode_device_capabilities, decode_kernel_memory,
    decode_kernel_module, decode_kernel_string, decode_kernel_task, decode_keyboard_export,
    decode_shell_drop_export, decode_shell_drive_type, decode_shell_execution_export,
    decode_shell_icon_export, decode_shell_registry_export,
    decode_system, decode_toolhelp, decode_toolhelp_stack, decode_wifeman_dbcs_lead_byte, network,
};
pub use request_modules::{class_data, gdi_device, window_data, window_properties};

/// USER window enumeration with a guest FAR callback and opaque LPARAM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WindowEnumerationRequest {
    Desktop { callback: u32, data: u32 },
    Children { parent: u16, callback: u32, data: u32 },
    Task { task: u16, callback: u32, data: u32 },
}

/// Decoded guest values for the runtime to execute or translate to a host request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ApiRequest {
    NetworkRedirector(Win16UserNetworkRequest),
    GdiServices(Win16GdiServicesRequest),
    GdiSpool(Win16GdiSpoolRequest),
    Ole1(Win16Ole1Request),
    Commctrl(Win16CommctrlRequest),
    Commdlg(Win16CommdlgRequest),
    Ctl3d(Win16Ctl3dRequest),
    KernelProfileSection(Win16KernelProfileSectionRequest),
    KernelPathInfo(Win16KernelPathInfoRequest),
    KernelFileSystem(Win16KernelFileSystemRequest),
    KernelDiagnostics(Win16KernelDiagnosticRequest),
    Ole2Nls(Win16Ole2NlsRequest),
    Winnls(Win16WinnlsRequest),
    PrintQueue(Win16PrintQueueRequest),
    Ole2Disp(Win16Ole2DispCall),
    Ole2DispConvert(Win16Ole2DispConvertCall),
    Winsock(Win16WinsockRequest),
    MediaTime(Win16MediaTimeRequest),
    MediaIo(Win16MediaIoRequest),
    Midi(Win16MidiRequest),
    /// A catalog-decoded Win16 multimedia export whose ABI is known, including
    /// the direct MSACM family. Host behavior is implemented in Rust runtime
    /// services rather than inferred from the descriptor itself.
    Multimedia(Win16MultimediaCall),
    Sound(Win16SoundRequest),
    /// Multimedia Control Interface exports and typed command parameters.
    Mci(Win16MciRequest),
    Dde(Win16DdeRequest),
    GdiDevice(GdiDeviceRequest),
    Printer(Win16PrinterRequest),
    ClassData(Win16ClassDataRequest),
    WindowData(Win16WindowDataRequest),
    WindowProperties(Win16WindowPropertyRequest),
    WindowEnumeration(Win16WindowEnumerationRequest),
    ShellIcon(Win16ShellIconRequest),
    ShellExecution(Win16ShellExecutionRequest),
    /// Windows 3.1 drag/drop calls and the documented Windows 4.x format-drive ABI.
    ShellDrop(Win16ShellDropRequest),
    ShellDrive(Win16ShellDriveRequest),
    DestroyImage(Win16DestroyImageRequest),
    KernelMemory(Win16KernelMemoryRequest),
    KernelTask(Win16KernelTaskRequest),
    KernelModule(Win16KernelModuleRequest),
    KernelString(Win16KernelStringRequest),
    Toolhelp(Win16ToolhelpRequest),
    ToolhelpStack(Win16ToolhelpStackRequest),
    System(Win16SystemRequest),
    /// WIN87EM's register-ABI x87 emulator entry. Its operation selector and
    /// input/output values are carried by the guest CPU register context.
    FpMath {
        context: Win16RegisterContext,
    },
    /// KERNEL calls grouped by memory, files, modules, resources, and lifecycle.
    Kernel(Win16KernelRequest),
    /// USER calls grouped by message, window, geometry, drawing, text, and resource roles.
    User(Win16UserRequest),
    /// Library-facing calls grouped separately from KERNEL and USER ABI services.
    Libraries(Win16LibraryRequest),
    /// USER redraw/update calls retain raw FAR bits for runtime-side checked
    /// conversion and guest writeback; zero remains a nullable FAR value.
    UserUpdate(Win16UserUpdateRequest),
    UserScrollBar(Win16UserScrollBarRequest),
    UserCursorAccelerator(Win16UserCursorAcceleratorRequest),
    /// Win16 startup handoff operating on the complete guest register context.
    InitTask {
        context: Win16RegisterContext,
    },
    KernelGlobalHeap(Win16KernelGlobalHeapRequest),
    /// GDI object and device-context operations.
    GdiObjects(Win16GdiObjectsRequest),
    /// GDI font and text operations.
    GdiText(Win16GdiTextRequest),
    /// GDI drawing, geometry, paths, and region operations.
    GdiDrawing(Win16GdiDrawingRequest),
    UserSystem(Win16UserSystemRequest),
    UserFamily(Win16UserFamilyRequest),
    Ver(Win16VerRequest),
    LzExpand(Win16LzExpandRequest),
    Shell(Win16ShellRequest),
    Keyboard(Win16KeyboardRequest),
    ShellRegistry(Win16ShellRegistryRequest),
}
