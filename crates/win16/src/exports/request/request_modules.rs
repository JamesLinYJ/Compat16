//! Request type modules and the decoded API family index.

use super::*;
#[path = "user_network.rs"]
mod user_network;
pub use user_network::{Win16UserNetworkBuffer, Win16UserNetworkRequest};
#[path = "user_hooks.rs"]
mod user_hooks;
pub use user_hooks::Win16UserHooksRequest;
#[path = "gdi_services.rs"]
mod gdi_services;
pub use gdi_services::{Win16FontResourceInput, Win16GdiServicesRequest};
#[path = "gdi_spool.rs"]
mod gdi_spool;
pub use gdi_spool::Win16GdiSpoolRequest;
#[path = "ole1.rs"]
mod ole1;
pub use ole1::Win16Ole1Request;
#[path = "winnls.rs"]
mod winnls;
pub use winnls::Win16WinnlsRequest;
#[path = "winmem32.rs"]
mod winmem32;
pub use winmem32::{
    WINMEM32_INSUFFICIENT_MEMORY, WINMEM32_INSUFFICIENT_SELECTORS, WINMEM32_INVALID_ARGUMENT,
    WINMEM32_INVALID_FLAGS, WINMEM32_INVALID_FUNCTION, WINMEM32_MAX_16BIT_ALIAS_BYTES,
    WINMEM32_MAX_OBJECT_BYTES, WINMEM32_VERSION_1_00, Win16Winmem32Request, decode_winmem32,
};
#[path = "print_queue.rs"]
mod print_queue;
pub use print_queue::{Win16PrintQueueRequest, decode_print_queue_export};
#[path = "kernel_file_system.rs"]
mod kernel_file_system;
pub use kernel_file_system::Win16KernelFileSystemRequest;

#[path = "class_data.rs"]
pub mod class_data;
pub use class_data::Win16ClassDataRequest;
#[path = "window_data.rs"]
pub mod window_data;
pub use window_data::Win16WindowDataRequest;
#[path = "window_properties.rs"]
pub mod window_properties;
pub use window_properties::{Win16WindowPropertyName, Win16WindowPropertyRequest};
#[path = "gdi_device.rs"]
pub mod gdi_device;
pub use gdi_device::{
    DibColorTableKind, DibRgbQuad16, DocInfo16, GdiDeviceRequest, PaletteEntry16,
    PaletteTransferKind, PrintOperation,
};
#[path = "printer.rs"]
mod printer;
pub use printer::Win16PrinterRequest;
pub(in crate::exports) use printer::decode_device_capabilities;

#[path = "kernel_global_heap.rs"]
mod kernel_global_heap;
pub use kernel_global_heap::Win16KernelGlobalHeapRequest;
#[path = "user_system.rs"]
mod user_system;
pub use user_system::Win16UserSystemRequest;
mod user_comm;
pub use user_comm::Win16UserCommRequest;
#[path = "ver.rs"]
mod ver;
pub use ver::Win16VerRequest;
#[path = "lz_expand.rs"]
mod lz_expand;
pub use lz_expand::Win16LzExpandRequest;
#[path = "shell.rs"]
mod shell;
pub use shell::Win16ShellRequest;
#[path = "keyboard.rs"]
mod keyboard;
pub use keyboard::{Win16KeyboardConversion, Win16KeyboardRequest};
pub(in crate::exports) use keyboard::{decode_keyboard_export, decode_wifeman_dbcs_lead_byte};
#[path = "shell_registry.rs"]
mod shell_registry;
pub use shell_registry::Win16ShellRegistryRequest;
pub(in crate::exports) use shell_registry::decode_shell_registry_export;
#[path = "shell_icons.rs"]
mod shell_icons;
pub use shell_icons::{Win16DestroyImageRequest, Win16GuestImageKind, Win16ShellIconRequest};
pub(in crate::exports) use shell_icons::{decode_destroy_image, decode_shell_icon_export};
#[path = "shell_execution.rs"]
mod shell_execution;
pub use shell_execution::Win16ShellExecutionRequest;
pub(in crate::exports) use shell_execution::decode_shell_execution_export;
#[path = "shell_drop.rs"]
mod shell_drop;
pub use shell_drop::{Win16ShellDropRequest, decode_shell_drop_export};
#[path = "shell_drive.rs"]
mod shell_drive;
pub use shell_drive::{Win16ShellDriveRequest, decode_shell_drive_type};
#[path = "user_update.rs"]
mod user_update;
pub use user_update::Win16UserUpdateRequest;
#[path = "user_cursor_accelerator.rs"]
mod user_cursor_accelerator;
pub(crate) use user_cursor_accelerator::{
    HELP_WINDOW_INFO16_HEADER_BYTES, HELP_WINDOW_INFO16_MIN_BYTES, HelpWindowInfo16HeaderWire,
    MultiKeyHelp16HeaderWire,
};
pub use user_cursor_accelerator::{
    Win16AcceleratorEntry, Win16AcceleratorResourceError, Win16HelpData,
    Win16UserCursorAcceleratorRequest, decode_accelerator_resource,
};
#[path = "scroll_bar.rs"]
mod scroll_bar;
pub use scroll_bar::Win16UserScrollBarRequest;
#[path = "commctrl.rs"]
mod commctrl;
pub use commctrl::Win16CommctrlRequest;
#[path = "commdlg.rs"]
mod commdlg;
pub use commdlg::Win16CommdlgRequest;
#[path = "ctl3d.rs"]
mod ctl3d;
pub use ctl3d::{Win16Ctl3dArgument, Win16Ctl3dModule, Win16Ctl3dRequest};
#[path = "kernel_profile_sections.rs"]
mod kernel_profile_sections;
pub use kernel_profile_sections::Win16KernelProfileSectionRequest;
#[path = "kernel_path_info.rs"]
mod kernel_path_info;
pub use kernel_path_info::Win16KernelPathInfoRequest;
#[path = "kernel_diagnostics.rs"]
mod kernel_diagnostics;
pub use kernel_diagnostics::Win16KernelDiagnosticRequest;
#[path = "ole2nls.rs"]
mod ole2nls;
pub use ole2nls::{Win16Ole2NlsRequest, Win16Ole2NlsString};
#[path = "ole2disp.rs"]
mod ole2disp;
pub use ole2disp::{Win16Ole2DispArgument, Win16Ole2DispCall};
#[path = "ole2disp_convert.rs"]
mod ole2disp_convert;
pub use ole2disp_convert::{
    Win16Ole2DispConvertCall, Win16Ole2DispConvertInput, Win16Ole2DispConvertOperation,
    Win16Ole2DispLocaleFlags,
};
#[path = "network.rs"]
pub(in crate::exports) mod network;
pub use network::{
    Win16AsyncLookup, Win16GuestBuffer, Win16GuestInOutBuffer, Win16HostQuery, Win16SelectInput,
    Win16SocketSetInput, Win16WinsockDecodeFailure, Win16WinsockRequest,
};
#[path = "auxiliary.rs"]
mod aux;
pub use aux::{
    AUXCAPS16_SIZE, AUXCAPS_AUXIN, AUXCAPS_CDAUDIO, AUXCAPS_LRVOLUME, AUXCAPS_VOLUME,
    Win16AuxCapabilities16, Win16AuxRequest,
};
#[path = "media_time.rs"]
mod media_time;
pub use media_time::{
    MMTIME16_SIZE, TIMECAPS16_SIZE, Win16MediaTimeRequest, Win16Mmtime16, Win16TimeCaps16,
};
#[path = "joystick.rs"]
mod joystick;
pub use joystick::{
    JOYCAPS16_SIZE, JOYERR_NOCANDO, JOYERR_PARMS, JOYERR_UNPLUGGED, JOYINFO16_SIZE,
    JOYINFOEX16_BUTTONS_OFFSET, JOYINFOEX16_SIZE, JOYINFOEX16_X_OFFSET, JOYINFOEX16_Y_OFFSET,
    JOYINFOEX16_Z_OFFSET, JOY_RETURN_SUPPORTED, JOY_RETURNBUTTONS, JOY_RETURNX, JOY_RETURNY,
    JOY_RETURNZ, MMSYSERR_NODRIVER, Win16JoyCaps16, Win16JoyInfo16, Win16JoystickRequest,
};
#[path = "mixer.rs"]
mod mixer;
pub use mixer::{
    MAXPNAMELEN, MIXERCAPS16_SIZE, MIXERCONTROL16_SIZE, MIXERCONTROLDETAILS16_SIZE,
    MIXERLINE16_SIZE, MIXERLINECONTROLS16_SIZE, MIXER_LONG_NAME_CHARS, MIXER_SHORT_NAME_CHARS,
    Win16MixerCaps16, Win16MixerControl16, Win16MixerControlDetails16, Win16MixerLine16,
    Win16MixerLineControls16, Win16MixerRequest,
};
#[path = "media_io.rs"]
mod media_io;
pub use media_io::{
    MMCKINFO16_SIZE, MMIOINFO16_ERROR_OFFSET, MMIOINFO16_SIZE, Win16MediaIoRequest, Win16MmckInfo16,
};
#[path = "midi.rs"]
mod midi;
pub use midi::{Win16MidiDirection, Win16MidiRequest, Win16MidiStreamArgument};
#[path = "midi_wire.rs"]
mod midi_wire;
pub use midi_wire::{
    MIDIHDR16_SIZE, MIDIINCAPS16_SIZE, MIDIOUTCAPS16_SIZE, Win16MidiHeader16,
    Win16MidiInCaps16, Win16MidiOutCaps16,
};
#[path = "multimedia.rs"]
mod multimedia;
pub use multimedia::{Win16MultimediaArgument, Win16MultimediaCall};
#[path = "sound.rs"]
mod sound;
pub use sound::{Win16SoundPlayApi, Win16SoundRequest};

#[path = "mci.rs"]
mod mci;
pub use mci::{
    Win16MciGuestRange, Win16MciOpenExtension, Win16MciOpenValue, Win16MciOutputBuffer,
    Win16MciParameters, Win16MciRequest, Win16MciResourceName, Win16MciSetExtension,
};
#[path = "dde.rs"]
pub(in crate::exports) mod dde;
pub use dde::{Win16DdeBuffer, Win16DdeRequest, Win16DdeTransactionData};

#[path = "types.rs"]
mod types;
pub use types::*;
#[path = "kernel_memory.rs"]
mod kernel_memory;
pub use kernel_memory::Win16KernelMemoryRequest;
pub(in crate::exports) use kernel_memory::decode_kernel_memory;
#[path = "kernel_task.rs"]
mod kernel_task;
pub use kernel_task::Win16KernelTaskRequest;
pub(in crate::exports) use kernel_task::decode_kernel_task;
#[path = "kernel_module.rs"]
mod kernel_module;
pub use kernel_module::Win16KernelModuleRequest;
pub(in crate::exports) use kernel_module::decode_kernel_module;
#[path = "kernel_string.rs"]
mod kernel_string;
pub use kernel_string::Win16KernelStringRequest;
pub(in crate::exports) use kernel_string::decode_kernel_string;
#[path = "toolhelp.rs"]
mod toolhelp;
pub use toolhelp::{Win16ToolhelpRequest, NF_NORMAL, NF_TASKSWITCH, NF_RIP};
pub(in crate::exports) use toolhelp::decode_toolhelp;
#[path = "toolhelp_stack.rs"]
mod toolhelp_stack;
pub use toolhelp_stack::Win16ToolhelpStackRequest;
pub(in crate::exports) use toolhelp_stack::decode_toolhelp_stack;
#[path = "system.rs"]
mod system;
pub use system::Win16SystemRequest;
pub(in crate::exports) use system::decode_system;

#[path = "user_input.rs"]
mod user_input;
pub use user_input::Win16UserInputRequest;
#[path = "family_requests.rs"]
mod family_requests;
pub use family_requests::*;
