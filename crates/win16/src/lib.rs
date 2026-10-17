//! Bounded Win16 kernel primitives over the shared guest address space.
#![forbid(unsafe_code)]

pub use exports::{
    DibColorTableKind, DibRgbQuad16, DocInfo16, GdiDeviceRequest, PaletteEntry16,
    PaletteTransferKind, PrintOperation, Win16ClassDataRequest, Win16PrinterRequest,
    Win16WindowDataRequest,
    Win16WindowPropertyName, Win16WindowPropertyRequest,
};

pub mod call_frame;
pub mod winnls_abi;
pub use winnls_abi::ImeProfile16;
pub use exports::Win16WinnlsRequest;
pub use exports::{
    WINMEM32_INSUFFICIENT_MEMORY, WINMEM32_INSUFFICIENT_SELECTORS, WINMEM32_INVALID_ARGUMENT,
    WINMEM32_INVALID_FLAGS, WINMEM32_INVALID_FUNCTION, WINMEM32_MAX_16BIT_ALIAS_BYTES,
    WINMEM32_MAX_OBJECT_BYTES, WINMEM32_VERSION_1_00, Win16Winmem32Request,
};
pub use exports::Win16PrintQueueRequest;
pub use exports::Win16KernelInstanceRequest;
pub use exports::Win16Ole1Request;
pub use exports::Win16UserMdiRequest;
pub use exports::Win16UserChildLookupRequest;
pub use exports::{Win16UserNetworkBuffer, Win16UserNetworkRequest};
pub use exports::Win16UserHooksRequest;
pub use exports::{Win16FontResourceInput, Win16GdiServicesRequest, Win16GdiSpoolRequest};
pub use exports::{NF_NORMAL, NF_TASKSWITCH, NF_RIP};
pub mod comm_abi;
pub mod commdlg_abi;
pub mod exports;
pub mod gdi_abi;
pub mod gdi_dib;
pub mod generic_thunk;
pub mod global;
pub mod local_heap;
pub mod load_module;
pub mod msacm_abi;
pub mod network_print_abi;
pub mod owner_draw;
pub mod pdb;
pub mod printer_abi;
pub mod selector;
pub mod strings;
mod string_format;
pub mod task;
pub mod task_database;
pub mod toolhelp_abi;
pub mod user_abi;
pub mod user_service_abi;
pub mod version;

pub use call_frame::{
    ArgumentKind, ReturnAddressWidth, StackCleanup, Win16Argument, Win16CallFrame,
    Win16CallingConvention, Win16RegisterContext,
};
pub use exports::{
    DecodedWin16Call, ExportCallingConvention, ExportLookupTarget, FAR_EXPORT_RETURN_WIDTH,
    Win16MultimediaArgument, Win16MultimediaCall,
    KERNEL_ADD_ATOM, KERNEL_DELETE_ATOM, KERNEL_FIND_ATOM, KERNEL_GET_ATOM_HANDLE,
    KERNEL_GET_ATOM_NAME, KERNEL_INIT_ATOM_TABLE,
    KERNEL_EXIT_PROCESS, KERNEL_GET_CURRENT_TASK, KERNEL_GET_PRIVATE_PROFILE_INT,
    KERNEL_GET_PRIVATE_PROFILE_STRING, KERNEL_GET_VERSION, KERNEL_GET_WIN_FLAGS,
    KERNEL_GLOBAL_ALLOC, KERNEL_GLOBAL_FREE, KERNEL_GLOBAL_LOCK, KERNEL_GLOBAL_SIZE,
    KERNEL_GLOBAL_UNLOCK, KERNEL_INIT_TASK, KERNEL_LCLOSE, KERNEL_LCREAT, KERNEL_LLSEEK,
    KERNEL_LOPEN, KERNEL_LREAD, KERNEL_LWRITE, KERNEL_POST_EVENT, KERNEL_SET_ERROR_MODE,
    KERNEL_SET_HANDLE_COUNT, KERNEL_WAIT_EVENT, KERNEL_WRITE_PRIVATE_PROFILE_STRING,
    KERNEL_FILE_CDR, KERNEL_CREATE_DIRECTORY, KERNEL_REMOVE_DIRECTORY, KERNEL_DELETE_FILE,
    KERNEL_GET_CURRENT_DIRECTORY, KERNEL_SET_CURRENT_DIRECTORY, KERNEL_FIND_FIRST_FILE,
    KERNEL_FIND_NEXT_FILE, KERNEL_FIND_CLOSE, KERNEL_GET_FILE_ATTRIBUTES,
    KERNEL_SET_FILE_ATTRIBUTES, KERNEL_GET_DISK_FREE_SPACE,
    MAX_WIN16_STRING_BYTES, MMCKINFO16_SIZE, MMIOINFO16_ERROR_OFFSET, MMIOINFO16_SIZE,
    MMTIME16_SIZE, TIMECAPS16_SIZE, TOOLHELP_INTERRUPT_REGISTER, TOOLHELP_INTERRUPT_UNREGISTER,
    USER_ANSI_LOWER, USER_DEF_WINDOW_PROC, USER_ENUM_PROPS, USER_GET_ASYNC_KEY_STATE,
    USER_GET_CLASS_INFO, USER_GET_CURRENT_TIME, USER_GET_KEY_STATE, USER_GET_PROP,
    USER_GET_SYSTEM_METRICS, USER_GET_TICK_COUNT, USER_INIT_APP, USER_LOAD_STRING,
    USER_MESSAGE_BEEP, USER_MESSAGE_BOX, USER_REMOVE_PROP, USER_SET_MESSAGE_QUEUE, USER_SET_PROP,
    WAVEHDR16_BYTES_RECORDED_OFFSET, WAVEHDR16_FLAGS_OFFSET, WAVEHDR16_SIZE, WAVEINCAPS16_SIZE,
    WAVEOUTCAPS16_SIZE, WIN87EM_FP_MATH, Win16AcceleratorEntry, Win16AcceleratorResourceError,
    Win16AnsiCaseTarget, Win16ApiRequest, Win16AsyncLookup, Win16AtomName, Win16ClassName,
    Win16CommctrlRequest, Win16CommdlgRequest, Win16Ctl3dArgument, Win16Ctl3dModule,
    Win16Ctl3dRequest, Win16DataExportSource, Win16DdeBuffer, Win16DdeRequest,
    Win16DdeTransactionData, Win16DestroyImageRequest, Win16DialogTemplateRef,
    Win16EquateValueSource, Win16ExportAbiKind, Win16ExportDescriptor, Win16ExportId,
    Win16ExportStackCleanup, Win16GdiDrawingRequest, Win16GdiObjectsRequest, Win16GdiTextRequest,
    Win16GuestBuffer, Win16GuestImageKind, Win16GuestInOutBuffer, Win16HelpData, Win16HostQuery,
    Win16KernelAtomsRequest, Win16KernelDiagnosticRequest, Win16KernelFileSystemRequest,
    Win16KernelFilesRequest,
    Win16KernelGlobalHeapRequest,
    Win16KernelGlobalMemoryRequest, Win16KernelLocalHeapRequest, Win16KernelMemoryRequest,
    Win16KernelModuleRequest, Win16KernelModulesRequest, Win16KernelPathInfoRequest,
    Win16KernelProfileSectionRequest, Win16KernelProfilesRequest, Win16KernelRequest,
    Win16KernelResourcesRequest, Win16KernelRuntimeRequest, Win16KernelSelectorsRequest,
    Win16KernelStringRequest, Win16KernelStringsRequest, Win16KernelTaskRequest,
    Win16KeyboardConversion, Win16KeyboardRequest, Win16LibraryCodePageRequest,
    Win16LibraryInterruptsRequest, Win16LibraryRequest, Win16LibraryStringsRequest,
    Win16AuxCapabilities16, Win16AuxRequest, AUXCAPS16_SIZE, AUXCAPS_AUXIN,
    AUXCAPS_CDAUDIO, AUXCAPS_LRVOLUME, AUXCAPS_VOLUME, Win16LibraryToolhelpRequest,
    Win16LzExpandRequest, Win16MediaIoRequest, Win16MediaTimeRequest, JOYCAPS16_SIZE,
    JOYERR_NOCANDO, JOYERR_PARMS, JOYERR_UNPLUGGED, JOYINFO16_SIZE,
    JOYINFOEX16_BUTTONS_OFFSET, JOYINFOEX16_SIZE, JOYINFOEX16_X_OFFSET, JOYINFOEX16_Y_OFFSET,
    JOYINFOEX16_Z_OFFSET, JOY_RETURN_SUPPORTED, JOY_RETURNBUTTONS, JOY_RETURNX,
    JOY_RETURNY, JOY_RETURNZ, MMSYSERR_NODRIVER, Win16JoyCaps16,
    Win16JoyInfo16, Win16JoystickRequest, MAXPNAMELEN, MIXERCAPS16_SIZE,
    MIXERCONTROL16_SIZE, MIXERCONTROLDETAILS16_SIZE, MIXERLINE16_SIZE, MIXERLINECONTROLS16_SIZE,
    MIXER_LONG_NAME_CHARS, MIXER_SHORT_NAME_CHARS, Win16MixerCaps16, Win16MixerControl16,
    Win16MixerControlDetails16, Win16MixerLine16, Win16MixerLineControls16, Win16MixerRequest,
    Win16MidiDirection, Win16MidiRequest, Win16MidiStreamArgument, Win16MidiHeader16,
    Win16MidiInCaps16, Win16MidiOutCaps16, MIDIHDR16_SIZE, MIDIINCAPS16_SIZE,
    MIDIOUTCAPS16_SIZE,
    Win16MmckInfo16, Win16MmioInfo16, Win16Mmtime16, Win16Ole2DispArgument, Win16Ole2DispCall,
    Win16Ole2DispConvertCall, Win16Ole2DispConvertInput, Win16Ole2DispConvertOperation,
    Win16Ole2DispLocaleFlags, Win16Ole2NlsRequest, Win16Ole2NlsString, Win16OutputBuffer,
    Win16Parameter, Win16ParameterType, Win16ResourceName, Win16ReturnKind,
    Win16RuntimeSelectorEquate, Win16SelectInput, Win16ShellExecutionRequest, Win16ShellDropRequest,
    Win16ShellIconRequest, Win16ShellRegistryRequest, Win16ShellRequest, Win16SocketSetInput,
    Win16StringComparison, Win16SystemParametersInfoRequest, Win16SystemRequest, Win16TimeCaps16,
    Win16SoundPlayApi, Win16SoundRequest, Win16ToolhelpRequest, Win16ToolhelpStackRequest,
    Win16CharacterClassification, Win16UserAnsiRequest, Win16UserAtomsRequest,
    Win16UserClipboardRequest, Win16UserCursorAcceleratorRequest, Win16UserDialogRequest,
    Win16UserDrawingRequest, Win16UserFamilyRequest, Win16UserGeometryRequest,
    Win16UserSessionRequest,
    Win16UserDeclaredCall, Win16UserMenuRequest, Win16UserMessagesRequest, Win16UserRequest, Win16UserResourcesRequest,
    Win16UserRuntimeRequest, Win16UserScrollBarRequest, Win16UserSystemRequest, Win16UserCommRequest,
    Win16UserInputRequest,
    Win16UserStringFormatRequest, Win16UserTextRequest, Win16UserUpdateRequest, Win16UserWindowRequest,
    Win16VariableRuntimeState, Win16VerRequest, Win16WaveControl, Win16WaveDirection,
    Win16WaveHeader16, Win16WaveInputCapabilities16, Win16WaveOutputCapabilities16,
    Win16WaveParameter, Win16WaveRequest, Win16WinsockDecodeFailure, Win16WinsockRequest,
    decode_accelerator_resource, decode_export_call, decode_export_call_with_register_context,
    lookup_export,
};
pub use exports::{Win16ModuleReference, Win16ProcReference};
pub use global::{
    AllocationFlags, GlobalBlockInfo, GlobalHandle, GlobalHeap, GlobalHeapRegion,
    GuestMemoryOwner,
};
pub use local_heap::{LocalHeapInitError, LocalHeapInitPlan, prepare_local_heap_init};
pub use selector::{
    Access, AccessRights, DescriptorInfo, SegmentedPointer, SelectorAllocationView, SelectorRef,
    SelectorTable,
};
pub use task::{TaskInfo, TaskRegistry, TaskState};
pub use task_database::{
    TASK_DATABASE_DTA_OFFSET, TASK_DATABASE_ERROR_MODE_OFFSET, TASK_DATABASE_EVENT_COUNT_OFFSET,
    TASK_DATABASE_HINSTANCE_OFFSET, TASK_DATABASE_HMODULE_OFFSET, TASK_DATABASE_HPDB_OFFSET,
    TASK_DATABASE_HSELF_OFFSET, TASK_DATABASE_MAGIC, TASK_DATABASE_MAGIC_OFFSET,
    TASK_DATABASE_PREFIX_SIZE, TASK_DATABASE_SHOW_COMMAND_OFFSET, TASK_EVENT_COUNT_OFFSET,
    TaskDatabase,
};
pub use user_abi::{
    CreateStruct16, Msg16, Point16, WndClass16, createstruct16_offsets, msg16_offsets,
    wndclass16_offsets,
};
pub mod window_geometry;
pub mod window_nonclient;
pub use version::{
    WIN16_MACHINE_FEATURES, WINDOWS_COMPATIBILITY_PROFILE, Win16MachineFeatures,
    WindowsCompatibilityMode, WindowsCompatibilityProfile, handle_int2f_version_query,
};
pub use window_geometry::Rect16;

use guest_core::MemoryError;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OBJECT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_object_id() -> Result<u64, Win16Error> {
    NEXT_OBJECT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| Win16Error::IdentityExhausted)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Error {
    InvalidRange,
    RegisterContextRequired,
    /// A runtime-sized export frame must be decoded by its dedicated ABI path.
    VariableStackRequiresSpecialDecoder,
    /// A fixed generic-thunk export must be decoded by the generic-thunk path.
    GenericThunkRequiresSpecialDecoder,
    UnsupportedCallingConvention,
    UnsupportedRegisterContextExport,
    InvalidSelector,
    StaleSelector,
    ForeignSelector,
    SelectorTableFull,
    SelectorBlockInterior,
    LimitViolation {
        offset: u32,
        length: usize,
        limit: u32,
    },
    StackOffsetWrap {
        offset: u16,
        length: u32,
    },
    AccessDenied {
        access: Access,
    },
    InvalidHandle,
    StaleHandle,
    ForeignHandle,
    HandleTableFull,
    OutOfMemory,
    InvalidSize,
    Locked,
    LockUnderflow,
    LockCountOverflow,
    UnknownTask,
    TaskAlreadyExists,
    InvalidTaskState,
    GenerationExhausted,
    IdentityExhausted,
    ReallocRollbackFailed {
        write: MemoryError,
        rollback: MemoryError,
    },
    Memory(MemoryError),
}

impl std::fmt::Display for Win16Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Win16Error as E;
        match self {
            E::InvalidRange => f.write_str("Win16 memory range is invalid"),
            E::RegisterContextRequired => {
                f.write_str("Win16 export requires a guest register context")
            }
            E::VariableStackRequiresSpecialDecoder => {
                f.write_str("Win16 export requires its variable-stack ABI decoder")
            }
            E::GenericThunkRequiresSpecialDecoder => {
                f.write_str("Win16 generic-thunk export requires its dedicated decoder")
            }
            E::UnsupportedCallingConvention => {
                f.write_str("Win16 export calling convention is unsupported by the stack decoder")
            }
            E::UnsupportedRegisterContextExport => {
                f.write_str("Win16 register-context export has no decoder")
            }
            E::InvalidSelector => f.write_str("Win16 selector is invalid"),
            E::StaleSelector => f.write_str("Win16 selector reference is stale"),
            E::ForeignSelector => f.write_str("Win16 selector belongs to another descriptor table"),
            E::SelectorTableFull => f.write_str("Win16 selector table is full"),
            E::SelectorBlockInterior => {
                f.write_str("Win16 selector does not identify the start of a block")
            }
            E::LimitViolation {
                offset,
                length,
                limit,
            } => write!(
                f,
                "Win16 selector access at offset 0x{offset:08X} for {length} bytes exceeds limit 0x{limit:08X}"
            ),
            E::StackOffsetWrap { offset, length } => write!(
                f,
                "Win16 stack access at offset 0x{offset:04X} for {length} bytes wraps the 16-bit stack pointer"
            ),
            E::AccessDenied { access } => write!(
                f,
                "Win16 selector does not permit {} access",
                match access {
                    Access::Read => "read",
                    Access::Write => "write",
                    Access::Execute => "execute",
                }
            ),
            E::InvalidHandle => f.write_str("Win16 global handle is invalid"),
            E::StaleHandle => f.write_str("Win16 global handle is stale"),
            E::ForeignHandle => f.write_str("Win16 global handle belongs to another heap"),
            E::HandleTableFull => f.write_str("Win16 global handle table is full"),
            E::OutOfMemory => f.write_str("Win16 global memory allocation failed"),
            E::InvalidSize => f.write_str("Win16 size is invalid"),
            E::Locked => f.write_str("Win16 global memory block is locked"),
            E::LockUnderflow => f.write_str("Win16 global memory lock count is already zero"),
            E::LockCountOverflow => {
                f.write_str("Win16 global memory lock count cannot be increased")
            }
            E::UnknownTask => f.write_str("Win16 task is not registered"),
            E::TaskAlreadyExists => f.write_str("Win16 task is already registered"),
            E::InvalidTaskState => f.write_str("Win16 task state transition is invalid"),
            E::GenerationExhausted => f.write_str("Win16 object generation counter is exhausted"),
            E::IdentityExhausted => f.write_str("Win16 object identity counter is exhausted"),
            E::ReallocRollbackFailed { write, rollback } => write!(
                f,
                "Win16 memory reallocation failed ({write}) and rollback also failed ({rollback})"
            ),
            E::Memory(error) => write!(f, "guest memory operation failed: {error}"),
        }
    }
}

impl std::error::Error for Win16Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::ReallocRollbackFailed { write, .. } => Some(write),
            _ => None,
        }
    }
}

impl From<MemoryError> for Win16Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

#[cfg(test)]
mod tests;
pub use exports::{
    Win16MciGuestRange, Win16MciOpenExtension, Win16MciOpenValue, Win16MciOutputBuffer,
    Win16MciParameters, Win16MciRequest, Win16MciResourceName, Win16MciSetExtension,
};

pub use exports::Win16WindowEnumerationRequest;
