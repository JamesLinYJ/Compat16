//! Project-owned Win16 export identities, ABI descriptors, and checked request decoding.
//!
//! Descriptors define the guest call boundary used by this runtime: export
//! identity, calling convention, parameter slots, return width, and stack
//! cleanup. They do not select host behavior or delegate implementation to an
//! external compatibility layer.
//!
//! The catalog is data-driven by module plus ordinal or exported name. A
//! catalog hit only identifies an ABI request; this module performs no file,
//! process, or window operation and does not filter requests by application.

use crate::{ArgumentKind, StackCleanup};
#[path = "exports/call_user_network.rs"]
mod call_user_network;
pub use request::{Win16UserNetworkBuffer, Win16UserNetworkRequest};
pub use request::{Win16FontResourceInput, Win16GdiServicesRequest, Win16GdiSpoolRequest};
#[path = "exports/call_ole1.rs"]
mod call_ole1;
pub use request::Win16UserHooksRequest;
pub use request::Win16UserMdiRequest;
pub use request::Win16UserChildLookupRequest;
pub use request::Win16Ole1Request;

#[path = "exports/call_kernel_instance.rs"]
mod call_kernel_instance;
pub use request::Win16KernelInstanceRequest;
pub use request::{NF_NORMAL, NF_TASKSWITCH, NF_RIP};

mod call;
#[path = "exports/call_commctrl.rs"]
mod call_commctrl;
#[path = "exports/call_commdlg.rs"]
mod call_commdlg;
#[path = "exports/call_ctl3d.rs"]
mod call_ctl3d;
#[path = "exports/call_dde.rs"]
mod call_dde;
#[path = "exports/call_kernel_diagnostics.rs"]
mod call_kernel_diagnostics;
#[path = "exports/call_kernel_path_info.rs"]
mod call_kernel_path_info;
#[path = "exports/call_kernel_file_system.rs"]
mod call_kernel_file_system;
#[path = "exports/call_kernel_profile_sections.rs"]
mod call_kernel_profile_sections;
#[path = "exports/call_win16_media_io.rs"]
mod call_media_io;
#[path = "exports/call_mci.rs"]
mod call_mci;
#[path = "exports/call_win16_media_time.rs"]
mod call_media_time;
#[path = "exports/call_win16_midi.rs"]
mod call_midi;
#[path = "exports/call_win16_multimedia.rs"]
mod call_win16_multimedia;
#[path = "exports/call_sound.rs"]
mod call_sound;
#[path = "exports/call_network.rs"]
mod call_network;
#[path = "exports/call_ole2disp.rs"]
mod call_ole2disp;
#[path = "exports/call_ole2disp_convert.rs"]
mod call_ole2disp_convert;
#[path = "exports/call_ole2nls.rs"]
mod call_ole2nls;
#[path = "exports/call_winnls.rs"]
mod call_winnls;
pub use request::Win16WinnlsRequest;
#[path = "exports/call_print_queue.rs"]
mod call_print_queue;
pub use request::Win16PrintQueueRequest;
#[path = "exports/call_user_scroll_bar.rs"]
mod call_user_scroll_bar;
#[path = "exports/call_wave.rs"]
mod call_wave;
mod data_exports;
mod request;
pub use call::{
    FAR_EXPORT_RETURN_WIDTH, decode_export_call, decode_export_call_with_register_context,
};
pub use data_exports::{
    Win16DataExportSource, Win16EquateValueSource, Win16RuntimeSelectorEquate,
    Win16VariableRuntimeState, lookup_data_export_source,
};
pub use request::{
    DecodedWin16Call, MMCKINFO16_SIZE, MMIOINFO16_ERROR_OFFSET, MMIOINFO16_SIZE, MMTIME16_SIZE,
    TIMECAPS16_SIZE, WAVEHDR16_BYTES_RECORDED_OFFSET, WAVEHDR16_FLAGS_OFFSET, WAVEHDR16_SIZE,
    WAVEINCAPS16_SIZE, WAVEOUTCAPS16_SIZE, Win16AnsiCaseTarget, Win16ApiRequest, Win16AsyncLookup,
    Win16AtomName, Win16ClassName, Win16DdeBuffer, Win16DdeRequest, Win16DdeTransactionData,
    Win16DestroyImageRequest, Win16GdiDrawingRequest, Win16GdiObjectsRequest, Win16GdiTextRequest,
    Win16GuestBuffer, Win16GuestImageKind, Win16GuestInOutBuffer, Win16HostQuery,
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
    Win16LibraryToolhelpRequest, Win16LzExpandRequest, Win16MediaIoRequest, Win16MediaTimeRequest,
    Win16MidiDirection, Win16MidiRequest, Win16MidiStreamArgument,
    MIDIHDR16_SIZE, MIDIINCAPS16_SIZE, MIDIOUTCAPS16_SIZE, Win16MidiHeader16,
    Win16MidiInCaps16, Win16MidiOutCaps16,
    Win16SoundPlayApi, Win16SoundRequest,
    Win16MciGuestRange, Win16MciOpenExtension, Win16MciOpenValue, Win16MciOutputBuffer, Win16MciParameters,
    Win16MciRequest, Win16MciResourceName, Win16MciSetExtension,
    Win16MmckInfo16, Win16Mmtime16, Win16ModuleReference, Win16Ole2DispArgument, Win16Ole2DispCall,
    Win16Ole2DispConvertCall, Win16Ole2DispConvertInput, Win16Ole2DispConvertOperation,
    Win16Ole2DispLocaleFlags, Win16Ole2NlsRequest, Win16Ole2NlsString, Win16OutputBuffer,
    Win16ProcReference, Win16ResourceName, Win16SelectInput, Win16ShellDropRequest,
    Win16ShellDriveRequest, Win16ShellExecutionRequest,
    Win16ShellIconRequest, Win16ShellRegistryRequest, Win16ShellRequest, Win16SocketSetInput,
    Win16StringComparison, Win16SystemRequest, Win16TimeCaps16, Win16ToolhelpRequest,
    Win16ToolhelpStackRequest, Win16CharacterClassification, Win16UserAnsiRequest, Win16UserAtomsRequest,
    Win16UserDrawingRequest, Win16UserGeometryRequest, Win16UserMenuRequest,
    Win16UserMessagesRequest, Win16UserRequest, Win16UserResourcesRequest, Win16UserRuntimeRequest,
    Win16UserStringFormatRequest,
    Win16UserScrollBarRequest, Win16UserSystemRequest, Win16UserCommRequest, Win16UserTextRequest,
    Win16UserUpdateRequest, Win16UserWindowRequest, Win16VerRequest, Win16WaveControl,
    Win16WaveDirection, Win16WaveHeader16, Win16WaveInputCapabilities16,
    Win16WaveOutputCapabilities16, Win16WaveParameter, Win16WaveRequest, Win16WinsockDecodeFailure,
    Win16WinsockRequest,
    Win16MultimediaArgument, Win16MultimediaCall,
};
pub use request::{
    DibColorTableKind, DibRgbQuad16, DocInfo16, GdiDeviceRequest, PaletteEntry16,
    PaletteTransferKind, PrintOperation, Win16CommctrlRequest, Win16CommdlgRequest,
    Win16Ctl3dArgument, Win16Ctl3dModule, Win16Ctl3dRequest, Win16PrinterRequest,
    Win16ClassDataRequest, Win16WindowDataRequest, Win16WindowPropertyName,
    Win16WindowPropertyRequest,
    Win16WindowEnumerationRequest, class_data, window_data,
    window_properties,
};
pub use request::{
    Win16AcceleratorEntry, Win16AcceleratorResourceError, Win16HelpData,
    Win16UserCursorAcceleratorRequest, decode_accelerator_resource,
};

/// Maximum bytes inspected for one NUL-terminated Win16 API string, including
/// its terminator. This bound also prevents malformed guest strings from
/// causing unbounded decoding work.
pub const MAX_WIN16_STRING_BYTES: usize = 64 * 1024;

/// A name or ordinal from an NE import record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportLookupTarget<'a> {
    Ordinal(u16),
    Name(&'a [u8]),
}

/// Semantic role of an argument beyond its encoded stack width.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16ParameterType {
    Scalar,
    /// A signed scalar whose encoded width remains the one in `kind`.
    SignedScalar,
    FarString,
    /// A Win16 FARPROC represented by its guest selector:offset value.
    /// Decoding preserves the raw guest value; the runtime validates and
    /// translates it through the guest selector table before use.
    FarPointer,
    /// A far-string slot that also accepts an encoded single character when
    /// the high word of the 32-bit argument is zero.
    FarStringOrChar,
    /// A resource name or integer resource identifier passed in a far-pointer
    /// stack slot. The decoder distinguishes selector-zero MAKEINTRESOURCE
    /// values from checked guest ANSI strings.
    ResourceName,
    /// A string or integer atom passed in a far-pointer stack slot. The decoder
    /// distinguishes selector-zero MAKEINTATOM values from checked guest ANSI
    /// strings.
    AtomName,
    /// A class name or registered class atom passed in a far-pointer slot.
    /// The decoder distinguishes selector-zero MAKEINTATOM values from
    /// checked guest ANSI strings.
    ClassName,
    /// A possibly-null far string, with null kept distinct from an empty string.
    NullableFarString,
    FarBuffer,
    /// A guest far pointer to an output buffer; its capacity is another argument.
    FarOutputBuffer,
}

/// One declared argument, in source/declaration order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win16Parameter {
    pub name: &'static str,
    pub kind: ArgumentKind,
    pub parameter_type: Win16ParameterType,
}

/// Return value shape encoded by the Win16 export declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16ReturnKind {
    Word,
    /// A 32-bit scalar returned in the Win16 DX:AX pair.
    Dword,
    /// A 16:16 far pointer returned in the Win16 DX:AX pair.
    FarPointer,
    /// The export returns or updates the guest architectural register context.
    RegisterContext,
    Void,
}

/// How an export receives its arguments at the Win16 guest ABI boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16ExportAbiKind {
    /// Arguments are decoded from the near/far return-address stack frame.
    Stack,
    /// Arguments occupy a runtime-sized stack frame and require the export's
    /// dedicated decoder. The ordinary fixed-signature decoder must reject it.
    VariableStack,
    /// The guest architectural register context is the call argument/result.
    RegisterContext,
}

/// Catalog entry consumed by the runtime's import resolver and thunk path.
/// `abi_kind` selects the argument source. `VariableStack` descriptors expose
/// their declared fixed prefix in `parameters`, but require a dedicated decoder
/// to read any variable tail or establish stack cleanup. For
/// `RegisterContext` exports, `parameters` is empty and stack cleanup is fixed
/// at zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win16ExportDescriptor {
    pub id: Win16ExportId,
    pub abi_kind: Win16ExportAbiKind,
    pub parameters: &'static [Win16Parameter],
    /// Calling-convention class from the canonical semantic ABI signature.
    /// Generic varargs entrypoints use their API-specific frame decoder to
    /// establish physical stack order and cleanup.
    pub calling_convention: ExportCallingConvention,
    pub return_kind: Win16ReturnKind,
    /// Whether argument cleanup is statically known; the return address is
    /// separate. Variable frames never pretend their fixed prefix is the full
    /// argument area.
    pub stack_cleanup: Win16ExportStackCleanup,
}

/// Stack cleanup shape recorded by an export descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16ExportStackCleanup {
    /// Exact cleanup of fixed argument slots; the return address is excluded.
    Fixed(StackCleanup),
    /// The total argument area is dynamic and must be decoded per call.
    Variable,
}

impl Win16ExportDescriptor {
    pub const fn parameter_count(self) -> usize {
        self.parameters.len()
    }

    pub const fn module(self) -> &'static str {
        self.id.module()
    }

    pub const fn ordinal(self) -> u16 {
        self.id.ordinal()
    }

    pub const fn name(self) -> &'static str {
        self.id.name()
    }
}

#[path = "exports/menu_abi.rs"]
pub mod menu_abi;
#[path = "exports/user_family.rs"]
mod user_family;
pub use user_family::{
    Win16DialogTemplateRef, Win16SystemParametersInfoRequest, Win16UserClipboardRequest,
    Win16UserDialogRequest, Win16UserFamilyRequest, Win16UserSessionRequest,
};
#[path = "exports/declarations.rs"]
mod declarations;
pub use declarations::{
    ExportAbiMetadata, ExportArchitecture, ExportArgumentType, ExportAttributes,
    ExportCallingConvention, ExportDeclarationType, ExportEntryKind, ExportFlags, ExportMetadata,
    ExportOrdinalSource, ExportReturnModifier, ExportSignatureKind, ExportSourceLocation,
    WIN16_EXPORTS, lookup_export_metadata,
};
include!(concat!(env!("OUT_DIR"), "/win16_bindings.rs"));

#[cfg(test)]
#[path = "exports/manifest_lookup_tests.rs"]
mod manifest_lookup_tests;

#[cfg(test)]
#[path = "exports/call_rectangle_predicate_tests.rs"]
mod rectangle_predicate_tests;

/// The descriptor catalog establishes decoding into a project-owned request;
/// runtime dispatch and host behavior are tracked separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportImplementationState {
    /// A declaration exists, but this crate has no typed request descriptor.
    DeclaredOnly,
    /// A typed ABI descriptor can bind the import to a decoded request.
    BoundToRequest,
}

/// Join of one active declaration and its optional request decoder binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ExportResolution {
    pub declaration: &'static ExportMetadata,
    pub descriptor: Option<&'static Win16ExportDescriptor>,
    pub state: ExportImplementationState,
}

/// Resolve a Win16 declaration without implying that its runtime or native
/// host behavior has been integrated.
pub fn resolve_export(module: &[u8], target: ExportLookupTarget<'_>) -> Option<ExportResolution> {
    let declaration = lookup_export_metadata(module, target)?;
    let descriptor = lookup_export(
        declaration.module.as_bytes(),
        ExportLookupTarget::Ordinal(declaration.ordinal),
    );
    let state = if descriptor.is_some() {
        ExportImplementationState::BoundToRequest
    } else {
        ExportImplementationState::DeclaredOnly
    };
    Some(ExportResolution {
        declaration,
        descriptor,
        state,
    })
}

/// Catalogued guest ABI descriptors. Presence describes the call boundary;
/// application compatibility still requires runtime and host validation.
pub fn export_descriptors() -> &'static [Win16ExportDescriptor] {
    EXPORTS
}

/// Find an ABI descriptor by imported module and procedure name or ordinal.
/// Module and export names are ASCII case-insensitive; a conventional `.EXE`
/// or `.DLL` suffix on a module is accepted. Unknown names/ordinals remain
/// unresolved so the caller can continue its normal resolver path.
pub fn lookup_export(
    module: &[u8],
    target: ExportLookupTarget<'_>,
) -> Option<&'static Win16ExportDescriptor> {
    let declaration = lookup_export_metadata(module, target)?;
    EXPORTS.iter().find(|descriptor| {
        descriptor
            .id
            .module()
            .eq_ignore_ascii_case(declaration.module)
            && descriptor.id.ordinal() == declaration.ordinal
    })
}

#[cfg(test)]
#[path = "exports/call_void_text_region_tests.rs"]
mod void_text_region_tests;

#[cfg(test)]
#[path = "exports/call_line_dda_global_void_tests.rs"]
mod line_dda_global_void_tests;

#[cfg(test)]
#[path = "exports/abi_baseline_tests.rs"]
mod abi_baseline_tests;

#[cfg(test)]
#[path = "exports/call_catch_throw_tests.rs"]
mod catch_throw_tests;
