//! Family request DTOs collected beneath the public decoded-call type.

#[path = "user_ansi.rs"]
mod user_ansi;
pub use user_ansi::{Win16CharacterClassification, Win16UserAnsiRequest};

#[path = "user_menu.rs"]
mod user_menu;
pub use user_menu::Win16UserMenuRequest;

#[path = "user_messages.rs"]
mod user_messages;
pub use user_messages::Win16UserMessagesRequest;

#[path = "user_window.rs"]
mod user_window;
pub use user_window::Win16UserWindowRequest;

#[path = "user_child_lookup.rs"]
mod user_child_lookup;
pub use user_child_lookup::Win16UserChildLookupRequest;

#[path = "user_geometry.rs"]
mod user_geometry;
pub use user_geometry::Win16UserGeometryRequest;

#[path = "user_drawing.rs"]
mod user_drawing;
pub use user_drawing::Win16UserDrawingRequest;

#[path = "user_text.rs"]
mod user_text;
pub use user_text::Win16UserTextRequest;

#[path = "user_resources.rs"]
mod user_resources;
pub use user_resources::Win16UserResourcesRequest;

#[path = "user_atoms.rs"]
mod user_atoms;
pub use user_atoms::Win16UserAtomsRequest;

#[path = "user_runtime.rs"]
mod user_runtime;
pub use user_runtime::Win16UserRuntimeRequest;

#[path = "user_string_format.rs"]
mod user_string_format;
pub use user_string_format::Win16UserStringFormatRequest;
#[path = "user_declared.rs"]
mod user_declared;
pub use user_declared::Win16UserDeclaredCall;
#[path = "user_mdi.rs"]
mod user_mdi;
pub use user_mdi::Win16UserMdiRequest;

#[path = "kernel_runtime.rs"]
mod kernel_runtime;
pub use kernel_runtime::Win16KernelRuntimeRequest;

#[path = "kernel_instance.rs"]
mod kernel_instance;
pub use kernel_instance::Win16KernelInstanceRequest;

#[path = "kernel_strings.rs"]
mod kernel_strings;
pub use kernel_strings::Win16KernelStringsRequest;

#[path = "kernel_modules.rs"]
mod kernel_modules;
pub use kernel_modules::Win16KernelModulesRequest;

#[path = "kernel_resources.rs"]
mod kernel_resources;
pub use kernel_resources::Win16KernelResourcesRequest;

#[path = "kernel_selectors.rs"]
mod kernel_selectors;
pub use kernel_selectors::Win16KernelSelectorsRequest;

#[path = "kernel_global_memory.rs"]
mod kernel_global_memory;
pub use kernel_global_memory::Win16KernelGlobalMemoryRequest;

#[path = "kernel_local_heap.rs"]
mod kernel_local_heap;
pub use kernel_local_heap::Win16KernelLocalHeapRequest;

#[path = "kernel_atoms.rs"]
mod kernel_atoms;
pub use kernel_atoms::Win16KernelAtomsRequest;

#[path = "kernel_files.rs"]
mod kernel_files;
pub use kernel_files::Win16KernelFilesRequest;

#[path = "kernel_profiles.rs"]
mod kernel_profiles;
pub use kernel_profiles::Win16KernelProfilesRequest;

#[path = "kernel_remainder.rs"]
mod kernel_remainder;
pub use kernel_remainder::{Win16KernelRemainderRequest, is_kernel_register_remainder};

#[path = "ole_remainder.rs"]
mod ole_remainder;
pub use ole_remainder::Win16OleRemainderModule;

#[path = "library_strings.rs"]
mod library_strings;
pub use library_strings::Win16LibraryStringsRequest;

#[path = "library_interrupts.rs"]
mod library_interrupts;
pub use library_interrupts::Win16LibraryInterruptsRequest;

#[path = "library_toolhelp.rs"]
mod library_toolhelp;
pub use library_toolhelp::Win16LibraryToolhelpRequest;

#[path = "library_codepage.rs"]
mod library_codepage;
pub use library_codepage::Win16LibraryCodePageRequest;

#[path = "wave.rs"]
mod wave;
pub use wave::{
    WAVEHDR16_BYTES_RECORDED_OFFSET, WAVEHDR16_FLAGS_OFFSET, WAVEHDR16_SIZE, WAVEINCAPS16_SIZE,
    WAVEOUTCAPS16_SIZE, Win16WaveControl, Win16WaveDirection, Win16WaveHeader16,
    Win16WaveInputCapabilities16, Win16WaveOutputCapabilities16, Win16WaveParameter,
    Win16WaveRequest,
};

#[path = "gdi_text.rs"]
mod gdi_text;
pub use gdi_text::Win16GdiTextRequest;

#[path = "gdi_objects.rs"]
mod gdi_objects;
pub use gdi_objects::Win16GdiObjectsRequest;

#[path = "gdi_drawing.rs"]
mod gdi_drawing;
pub use gdi_drawing::Win16GdiDrawingRequest;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserRequest {
    Hooks(Win16UserHooksRequest),
    Mdi(Win16UserMdiRequest),
    ChildLookup(Win16UserChildLookupRequest),
    Ansi(Win16UserAnsiRequest),
    Menu(Win16UserMenuRequest),
    Messages(Win16UserMessagesRequest),
    Window(Win16UserWindowRequest),
    Geometry(Win16UserGeometryRequest),
    Drawing(Win16UserDrawingRequest),
    Text(Win16UserTextRequest),
    Resources(Win16UserResourcesRequest),
    Atoms(Win16UserAtomsRequest),
    Runtime(Win16UserRuntimeRequest),
    StringFormat(Win16UserStringFormatRequest),
    Comm(Win16UserCommRequest),
    Input(Win16UserInputRequest),
    Declared(Win16UserDeclaredCall),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelRequest {
    SwitchStackTo { stack_selector: u16, stack_pointer: u16, stack_top: u16 },
    SwitchStackBack { context: crate::Win16RegisterContext },
    /// Far Pascal arguments; completion requires a checked CPU transfer.
    Catch { buffer: u32 },
    Throw { buffer: u32, value: u16 },
    Instance(Win16KernelInstanceRequest),
    Runtime(Win16KernelRuntimeRequest),
    Strings(Win16KernelStringsRequest),
    Modules(Win16KernelModulesRequest),
    Resources(Win16KernelResourcesRequest),
    Selectors(Win16KernelSelectorsRequest),
    GlobalMemory(Win16KernelGlobalMemoryRequest),
    LocalHeap(Win16KernelLocalHeapRequest),
    Atoms(Win16KernelAtomsRequest),
    Files(Win16KernelFilesRequest),
    Profiles(Win16KernelProfilesRequest),
    /// KERNEL exports that were declaration-only. Guest scalars are not host pointers.
    Remainder(Win16KernelRemainderRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16LibraryRequest {
    /// COMPOBJ.18 compares two copied GUID records; no COM object or host
    /// pointer crosses the ABI boundary and neither input is retained.
    IsEqualGuid { left: [u8; 16], right: [u8; 16] },
    /// Declaration-only OLE stack export. Binding ids are `4000000`–`4999999`.
    OleRemainder {
        module: Win16OleRemainderModule,
        ordinal: u16,
    },
    /// Library and leftover OLE exports. Binding ids are `6000000`–`6999999`
    /// and `9200000`–`9299999`. The ordinal selects the catalog row. Guest
    /// far pointers stay on the stack.
    LibraryRemainder { ordinal: u16 },
    Strings(Win16LibraryStringsRequest),
    Interrupts(Win16LibraryInterruptsRequest),
    Toolhelp(Win16LibraryToolhelpRequest),
    CodePage(Win16LibraryCodePageRequest),
    Wave(Win16WaveRequest),
}
