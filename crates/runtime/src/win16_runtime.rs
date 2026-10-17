//! Win16 NE module state and imported-export call boundary.

#[path = "win16_task.rs"]
mod task;
#[path = "win16_runtime_task_state.rs"]
mod task_state;
#[path = "win16_task_event_wait.rs"]
mod task_event_wait;
#[path = "win16_task_cleanup.rs"]
mod task_cleanup;
#[path = "win16_task_quiescence.rs"]
mod task_quiescence;
#[path = "win16_process_teardown.rs"]
mod process_teardown;
#[path = "win16_pdb.rs"]
mod pdb;
#[path = "win16_process_views.rs"]
mod process_views;
#[path = "win16_selector_ownership.rs"]
mod selector_ownership;
#[path = "win16_runtime_arena_backing.rs"]
mod runtime_arena_backing;
#[path = "win16_legacy_cpu_binding.rs"]
mod legacy_cpu_binding;
#[path = "win16_legacy_cpu_frame.rs"]
mod legacy_cpu_frame;
#[path = "win16_local.rs"]
mod local_heap;
#[path = "win16_local_shrink.rs"]
mod local_shrink;
#[path = "win16_stack_switch.rs"]
mod stack_switch;
#[path = "win16_kernel_yield.rs"]
mod kernel_yield;
#[path = "win16_local_atoms.rs"]
mod local_atoms;
#[path = "win16_data_growth.rs"]
mod data_growth;
#[path = "win16_user.rs"]
mod user;
#[path = "win16_math.rs"]
mod math;
#[path = "win16_mci.rs"]
mod mci;
#[path = "win16_netbios_call.rs"]
mod netbios_call;
#[path = "win16_netbios_wire.rs"]
mod netbios_wire;
#[path = "win16_netbios_async.rs"]
mod netbios_async;
#[path = "win16_netbios_validation.rs"]
mod netbios_validation;
#[path = "win16_execute.rs"]
mod execute;
#[path = "win16_scheduler_activity.rs"]
mod scheduler_activity;
#[path = "win16_com_operations.rs"]
mod com_operations;
#[path = "win16_dos_interrupts.rs"]
mod dos_interrupts;
#[path = "win16_dos_address_space.rs"]
mod dos_address_space;
#[path = "win16_interrupt_entry.rs"]
mod interrupt_entry;
#[path = "win16_proc.rs"]
mod proc;
#[path = "win16_toolhelp.rs"]
mod toolhelp;
#[path = "win16_toolhelp_memory.rs"]
mod toolhelp_memory;
#[path = "win16_toolhelp_system.rs"]
mod toolhelp_system;
#[path = "win16_toolhelp_limited.rs"]
mod toolhelp_limited;
#[path = "win16_toolhelp_notify.rs"]
mod toolhelp_notify;
#[path = "win16_toolhelp_notify_lifecycle.rs"]
mod toolhelp_notify_lifecycle;
#[path = "win16_toolhelp_notify_exit.rs"]
mod toolhelp_notify_exit;
#[path = "win16_toolhelp_notify_payload.rs"]
mod toolhelp_notify_payload;
#[path = "win16_toolhelp_interrupt.rs"]
mod toolhelp_interrupt;
#[path = "win16_toolhelp_stack.rs"]
mod toolhelp_stack;
#[path = "win16_kernel_memory.rs"]
mod kernel_memory;
#[path = "win16_kernel_instance.rs"]
mod kernel_instance;
#[path = "win16_gdi_services.rs"]
mod gdi_services;
#[path = "win16_metafile.rs"]
mod metafile;
#[path = "win16_kernel_task.rs"]
mod kernel_task;
#[path = "win16_window_task.rs"]
mod window_task;
#[path = "win16_kernel_module.rs"]
mod kernel_module;
#[path = "win16_kernel_string.rs"]
mod kernel_string;
#[path = "win16_system.rs"]
mod system;
#[path = "win16_kernel_services.rs"]
mod kernel_services;
#[path = "win16_kernel_path_info.rs"]
mod kernel_path_info;
#[path = "win16_temp_drive.rs"]
mod temp_drive;
#[path = "win16_kernel_register_calls.rs"]
mod kernel_register_calls;
#[path = "win16_kernel_diagnostics.rs"]
mod kernel_diagnostics;
#[path = "win16_kernel_file_system.rs"]
pub(crate) mod kernel_file_system;
#[path = "win16_ole2nls.rs"]
mod ole2nls;
#[path = "win16_winnls.rs"]
mod winnls;
#[path = "win16_print_queue.rs"]
mod print_queue;
#[path = "win16_ole1_server_callback.rs"]
mod win16_ole1_server_callback;
#[path = "win16_ole1_server_callbacks.rs"]
mod win16_ole1_server_callbacks;
#[path = "win16_ole1_server_dde.rs"]
mod win16_ole1_server_dde;
#[path = "win16_ole1_server_execute.rs"]
mod win16_ole1_server_execute;
#[path = "win16_ole1_server_registration.rs"]
mod win16_ole1_server_registration;
#[path = "win16_ole1_server_state.rs"]
mod win16_ole1_server_state;
#[path = "win16_ole1_server_wire.rs"]
mod win16_ole1_server_wire;
#[path = "win16_ole1.rs"]
mod ole1;
#[path = "win16_runtime_automation.rs"]
mod automation;
#[path = "win16_runtime_network.rs"]
mod network;
#[path = "win16_runtime_callback_finish.rs"]
mod callback_finish;
#[path = "win16_callback_teardown.rs"]
mod callback_teardown;
#[path = "win16_runtime_dde.rs"]
mod win16_runtime_dde;
#[path = "win16_runtime_bootstrap.rs"]
mod bootstrap;
#[path = "win16_dde_callback.rs"]
mod win16_dde_callback;
#[path = "win16_dde_callback_teardown.rs"]
mod win16_dde_callback_teardown;
#[path = "win16_runtime_dde_context.rs"]
mod dde_guest_context;
#[path = "win16_classic_dde_dispatch.rs"]
mod classic_dde_dispatch;
#[path = "win16_classic_dde_operation.rs"]
mod classic_dde_operation;
#[path = "win16_classic_dde_atoms.rs"]
mod classic_dde_atoms;
#[path = "win16_classic_dde_memory.rs"]
mod classic_dde_memory;
#[path = "win16_classic_dde_executor.rs"]
mod classic_dde_executor;
#[path = "win16_media_time.rs"]
mod media_time;
#[path = "win16_media_io.rs"]
mod media_io;
#[path = "win16_runtime_midi.rs"]
mod midi;
#[path = "win16_window_post.rs"]
mod window_post;
#[path = "win16_bitmap_resources.rs"]
mod bitmap_resources;
#[path = "win16_commctrl_toolbar.rs"]
mod commctrl_toolbar;
#[path = "win16_commctrl_menu_help.rs"]
mod commctrl_menu_help;
#[path = "win16_acm.rs"]
mod acm;
#[path = "win16_multimedia_buffers.rs"]
mod multimedia_buffers;
#[path = "win16_sound_queue.rs"]
mod sound_queue;
#[path = "win16_sound_render.rs"]
mod sound_render;
#[path = "win16_sound_state.rs"]
mod sound_state;
#[path = "win16_sound_calls.rs"]
mod sound_calls;
#[path = "win16_sound_play.rs"]
mod sound_play;
#[path = "win16_toolhelp_global.rs"]
mod toolhelp_global;
#[path = "win16_toolhelp_global_owner.rs"]
mod toolhelp_global_owner;
#[path = "win16_profile.rs"]
mod profile;
#[path = "win16_gdi.rs"]
mod gdi;
#[path = "win16_drawing.rs"]
mod drawing;
#[path = "win16_dc.rs"]
mod dc;
#[path = "win16_images.rs"]
mod images;
#[path = "win16_files.rs"]
mod files;
#[path = "win16_file_io.rs"]
mod file_io;
#[path = "win16_atoms.rs"]
mod atoms;
#[path = "win16_call_return.rs"]
mod call_return;
#[path = "win16_font_callback.rs"]
mod font_callback;
#[path = "win16_object_callback.rs"]
mod object_callback;
#[path = "win16_far_callback.rs"]
mod far_callback;
#[path = "win16_callback_entry.rs"]
mod callback_entry;
#[path = "win16_callback_scheduler.rs"]
mod callback_scheduler;
#[path = "win16_callback_scheduler_errors.rs"]
mod callback_scheduler_errors;
#[path = "win16_callback_scheduler_registration.rs"]
mod callback_scheduler_registration;
#[path = "win16_callback_lifo.rs"]
mod callback_lifo;
#[path = "win16_line_dda.rs"]
mod line_dda;
#[path = "win16_window_enumeration.rs"]
mod window_enumeration;
#[path = "win16_user_hooks.rs"]
mod user_hooks;
#[path = "win16_user_network.rs"]
mod user_network;
#[path = "win16_network_print_jobs.rs"]
mod network_print_jobs;
#[path = "win16_network_print_dispatch.rs"]
mod network_print_dispatch;
#[path = "win16_network_print_completion.rs"]
mod network_print_completion;
#[path = "win16_network_print_cleanup.rs"]
mod network_print_cleanup;
#[path = "win16_network_print_api.rs"]
mod network_print_api;
#[path = "win16_gdi_spool.rs"]
mod gdi_spool;
#[path = "win16_network_print_notifications.rs"]
mod network_print_notifications;
#[path = "win16_network_print_queue_data.rs"]
mod network_print_queue_data;
#[path = "win16_dispatch_user_hooks.rs"]
mod dispatch_user_hooks;
#[path = "win16_global_handle.rs"]
mod global_handle;
#[path = "win16_module.rs"]
mod module;
#[path = "win16_module_registry.rs"]
mod module_registry;
#[path = "win16_external_application.rs"]
mod external_application;
#[path = "win16_module_memory.rs"]
mod module_memory;
#[path = "win16_module_loading.rs"]
mod module_loading;
#[path = "win16_module_calls.rs"]
mod module_calls;
#[path = "win16_module_call_rollback.rs"]
mod module_call_rollback;
#[path = "win16_module_call_retirement.rs"]
mod module_call_retirement;
#[path = "win16_resources.rs"]
mod resources;
#[path = "win16_resource_calls.rs"]
mod resource_calls;
#[path = "win16_code_lifetime.rs"]
mod code_lifetime;
#[path = "win16_catch_throw.rs"]
mod catch_throw;
#[path = "win16_keyboard.rs"]
mod keyboard;
#[path = "win16_text.rs"]
mod text;
#[path = "win16_text_memory.rs"]
mod text_memory;
#[path = "win16_registered_names.rs"]
mod registered_names;
#[path = "win16_selector.rs"]
mod selector;
#[path = "win16_selector_errors.rs"]
mod selector_errors;
#[path = "win16_selector_mapping.rs"]
mod selector_mapping;
#[path = "win16_classes.rs"]
mod classes;
#[path = "win16_class_data.rs"]
mod class_data;
#[path = "win16_mdi_client_creation.rs"]
pub(crate) mod mdi_client_creation;
#[path = "win16_mdi_child_creation.rs"]
mod mdi_child_creation;
#[path = "win16_messages_mdi.rs"]
pub(crate) mod messages_mdi;
#[path = "win16_windows.rs"]
mod windows;
#[path = "win16_window_pending.rs"]
mod window_pending;
#[path = "win16_window_guest_work.rs"]
mod window_guest_work;
#[path = "win16_message_loop.rs"]
mod message_loop;
#[path = "win16_messages.rs"]
mod messages;
#[path = "win16_standard_controls.rs"]
mod standard_controls;
#[path = "win16_window_input.rs"]
mod window_input;
#[path = "win16_native_procedures.rs"]
mod native_procedures;
#[path = "win16_window_text.rs"]
mod window_text;
#[path = "win16_menu.rs"]
mod menu;
#[path = "win16_menu_calls.rs"]
mod menu_calls;
#[path = "win16_message_calls.rs"]
mod message_calls;
#[path = "win16_gdi_object_factories.rs"]
mod gdi_object_factories;
#[path = "win16_gdi_bitmap_transfer.rs"]
mod gdi_bitmap_transfer;
#[path = "win16_global_memory.rs"]
mod global_memory;
#[path = "win16_global_teardown.rs"]
mod global_teardown;
#[path = "win16_global_ownership.rs"]
mod global_ownership;
#[path = "win16_global_dos_memory.rs"]
mod global_dos_memory;
#[path = "win16_dos_global_state.rs"]
mod dos_global_state;
#[path = "win16_global_pages.rs"]
mod global_pages;
#[path = "win16_compat_calls_ver.rs"]
mod compat_ver;
#[path = "win16_compat_calls_lzexpand.rs"]
mod compat_lzexpand;
#[path = "win16_compat_calls_shell_icons.rs"]
mod compat_shell_icons;
#[path = "win16_compat_calls_shell.rs"]
mod compat_shell;
#[path = "win16_compat_calls_shell_drop.rs"]
mod compat_shell_drop;
#[path = "win16_compat_calls_shell_drive.rs"]
mod compat_shell_drive;
#[path = "win16_compat_calls_shell_registry.rs"]
mod compat_registry;
#[path = "win16_compat_calls_keyboard.rs"]
mod compat_keyboard;
#[path = "win16_user_services_paint.rs"]
mod user_services_paint;
#[path = "win16_user_services_update_region.rs"]
mod user_services_update_region;
#[path = "win16_user_services_system.rs"]
mod user_services_system;
#[path = "win16_user_services_dialog.rs"]
mod user_services_dialog;
#[path = "win16_user_services_controls.rs"]
mod user_services_controls;
#[path = "win16_user_services_system_parameters.rs"]
mod user_services_system_parameters;
#[path = "win16_user_family_calls.rs"]
mod user_family_calls;
#[path = "win16_commctrl.rs"]
mod commctrl;
#[path = "win16_commdlg.rs"]
mod commdlg;
#[path = "win16_compat_calls_shell_execution.rs"]
mod compat_shell_execution;
#[path = "win16_guest_ranges.rs"]
pub(crate) mod guest_ranges;
#[path = "win16_runtime_scroll_bar.rs"]
mod scroll_bar;
#[path = "win16_user_cursor_accelerator.rs"]
mod user_cursor_accelerator;
#[path = "win16_ctl3d.rs"]
mod ctl3d;
#[path = "win16_kernel_profile_sections.rs"]
mod profile_sections;
#[path = "win16_user_services_draw.rs"]
mod user_services_draw;
#[path = "win16_dib_memory.rs"]
mod win16_dib_memory;
#[path = "win16_window_operations.rs"]
mod window_operations;
#[path = "win16_window_data.rs"]
mod window_data;
#[path = "win16_window_subclass.rs"]
mod window_subclass;
#[path = "win16_window_parent_observation.rs"]
mod window_parent_observation;
#[path = "win16_window_properties.rs"]
mod window_properties;
#[path = "win16_native_function_callback.rs"]
mod native_function_callback;
#[path = "win16_gray_string.rs"]
mod gray_string;
#[path = "win16_window_payloads.rs"]
mod window_payloads;
#[path = "win16_window_payload_input.rs"]
mod window_payload_input;
#[path = "win16_window_drop_completion.rs"]
mod window_drop_completion;
#[path = "win16_owner_draw_payloads.rs"]
mod owner_draw_payloads;
#[path = "win16_geometry.rs"]
mod geometry;
#[path = "win16_dispatch_routes.rs"]
mod dispatch_routes;
#[path = "win16_dispatch_kernel.rs"]
mod dispatch_kernel;
#[path = "win16_dispatch_user.rs"]
mod dispatch_user;
#[path = "win16_dispatch_gdi.rs"]
mod dispatch_gdi;
#[path = "win16_dispatch_libraries.rs"]
mod dispatch_libraries;
#[path = "win16_dispatch.rs"]
mod dispatch;
#[path = "win16_generic_thunks.rs"]
mod generic_thunks;
#[path = "win16_thunk_capability.rs"]
mod thunk_capability;
#[path = "win16_gdi_device_services.rs"]
mod gdi_device_services;
#[path = "win16_printer_services.rs"]
mod printer_services;
#[path = "win16_wing_bitmap.rs"]
mod wing_bitmap;
#[path = "win16_wing_bitmap_retirement.rs"]
mod wing_bitmap_retirement;
#[path = "win16_runtime_pe32.rs"]
mod pe32_dispatch;

use std::collections::{BTreeMap, BTreeSet};

use formats::{
    FarAddress, FormatError, NeImportTarget, NeImportValue, NeLoadedModule, NeModule,
    load_ne_segments,
};
use graphics::MessageQueue;
use guest_core::memory::Memory;
use guest_core::{GuestMemory, OwnerId, PhysAddr, Registers, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, GlobalHandle, GlobalHeap, SegmentedPointer, SelectorRef,
    SelectorTable, TASK_DATABASE_MAGIC, TASK_DATABASE_PREFIX_SIZE,
    TaskDatabase, TaskRegistry, Win16ExportDescriptor, Win16ReturnKind, lookup_export,
};
use dos_global_state::Win16DosGlobalBlock;

pub(crate) use process_views::Win16ProcessBootstrap;
use self::win16_runtime_dde as runtime_dde;
use runtime_dde::{
    Win16DdeCallbackReadback, Win16DdeContinuation, Win16DdeFinish,
};
use self::win16_dde_callback as dde_callback;
use dde_callback::{Win16DdeCallbackFinish, Win16DdeCallbackOrigin};

use crate::win16_loader::Win16LoadResolver;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostFile};

pub(crate) const WIN16_ARENA_BASE: u32 = 0x0110_0000;
pub(crate) const WIN16_MEMORY_END: u32 = 0x0410_0000;
pub(crate) const PE32_MEMORY_BASE: u32 = WIN16_MEMORY_END;
/// Dedicated process-owned PE32 RAM tail; the NE heap remains below this base.
pub(crate) const PE32_MEMORY_END: u32 = 0x0810_0000;
const SERVICE_GATE_BYTES: u32 = 0x0001_0000;
// DOS JFT handles 0..254 occupy the byte-sized INT 21h namespace. WNet HFILEs
// share the runtime's WORD allocator but start beyond that range, so routing
// their AH=3E/AH=40 calls cannot alias a DOS kernel handle.
const FIRST_GUEST_HFILE: u16 = 255;
const INVALID_GUEST_HFILE: u16 = u16::MAX;
// The DOS service layer reports 5.00 to applications; KERNEL.GetVersion
// places that DOS version in the high word of its Win16 return value.
const COMPAT_DOS_VERSION_WORD: u16 = 0x0500;
// NE segment-table flag from the Windows 3.x NE format: movable segment.
const NE_SEGMENT_MOVEABLE: u16 = 0x0010;

enum ImportBinding {
    Supported(&'static Win16ExportDescriptor),
    Unavailable {
        module: Vec<u8>,
        target: NeImportTarget,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallbackKind {
    Font,
    GdiObject,
    AcmEnumeration,
    LineDda,
    WindowEnumeration,
    UserHook,
    Ole1,
    Window,
    NativeFunction,
    Dde,
    ClassicDde,
    Module,
    Resource,
    Asynchronous,
    Mci,
    FileCdr,
    ToolhelpNotify,
    ToolhelpInterrupt,
}

fn retire_callback_binding_from_stacks(
    callback_kinds: &mut Vec<CallbackKind>,
    callback_frame_ids: &mut Vec<CallbackFrameId>,
    kind: CallbackKind,
    callback_id: CallbackFrameId,
) -> Result<(), crate::RuntimeError> {
    if callback_kinds.len() != callback_frame_ids.len() {
        return Err(crate::RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "Win16 callback kind and identity stacks have different depths",
        ));
    }
    if callback_kinds.last() != Some(&kind) || callback_frame_ids.last() != Some(&callback_id) {
        return Err(crate::RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "Win16 callback is not the exact shared LIFO top",
        ));
    }
    callback_kinds.pop();
    callback_frame_ids.pop();
    Ok(())
}

/// Identity shared by the exact runtime LIFO binding for every callback family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CallbackFrameId(pub(super) u64);

/// Preserves the public OleRevokeServer caller while the next exact
/// document/server Release callback is being entered. This record exists
/// only between a completed child Release and the successful entry (or
/// explicit inline API result) of its parent/sibling continuation.
#[derive(Clone)]
pub(super) struct Ole1ServerReleaseCascadeContinuation {
    pub(super) callback_id: CallbackFrameId,
    pub(super) owner: OwnerId,
    pub(super) completed_target: win16_ole1_server_state::Ole1ReleaseTarget,
    pub(super) target: win16_ole1_server_state::Ole1ReleaseTarget,
    pub(super) return_to: (u16, u16, u32),
    pub(super) return_kind: Win16ReturnKind,
    pub(super) saved: Registers,
}

/// Complete interrupted guest context retained until a safe-point DDE frame
/// has been acknowledged. `registers` separately anchors code-selector roots.
pub(super) struct DdeGuestExecutionContext {
    frame: crate::Win16HostDdeCallbackFrame,
    cpu_owner: u64,
}

impl ImportBinding {
    fn matches(&self, module: &[u8], target: &NeImportTarget) -> bool {
        match self {
            Self::Supported(descriptor) => {
                let lookup = match target {
                    NeImportTarget::Ordinal(number) => ExportLookupTarget::Ordinal(*number),
                    NeImportTarget::Name(name) => ExportLookupTarget::Name(name),
                };
                lookup_export(module, lookup).is_some_and(|found| found.id == descriptor.id)
            }
            Self::Unavailable {
                module: existing,
                target: previous,
            } => {
                if existing.eq_ignore_ascii_case(module) && previous == target {
                    return true;
                }
                // Capability changes preserve the gate slot. Names and
                // ordinals resolving to the same descriptor remain aliases.
                let descriptor = |module: &[u8], target: &NeImportTarget| {
                    lookup_export(
                        module,
                        match target {
                            NeImportTarget::Ordinal(number) => ExportLookupTarget::Ordinal(*number),
                            NeImportTarget::Name(name) => ExportLookupTarget::Name(name),
                        },
                    )
                };
                match (descriptor(existing, previous), descriptor(module, target)) {
                    (Some(left), Some(right)) => left.id == right.id,
                    _ => false,
                }
            }
        }
    }

    fn name(&self) -> String {
        match self {
            Self::Supported(descriptor) => format!("{}!{}", descriptor.module(), descriptor.name()),
            Self::Unavailable { module, target } => {
                let symbol = match target {
                    NeImportTarget::Ordinal(number) => format!("#{number}"),
                    NeImportTarget::Name(name) => String::from_utf8_lossy(name).into_owned(),
                };
                format!("{}!{symbol}", String::from_utf8_lossy(module))
            }
        }
    }
}

use windows::{WindowOperationFrame, WindowOperationLifecycle};

pub(crate) struct Win16State {
    ole1_client_documents: ole1::Win16Ole1ClientDocuments,
    ole1_callbacks: Vec<ole1::Win16Ole1CallbackFrame>,
    ole1_server_release_cascades: Vec<Ole1ServerReleaseCascadeContinuation>,
    ole1_server_state: win16_ole1_server_state::Ole1ServerState,
    ole1_com_callback_resumes: Vec<crate::Win16ComHostResume>,
    ole1_com_callback_resume_failures: Vec<(
        crate::Win16ComHostOwnerIdentity,
        crate::Win16ComHostCallbackFrame,
    )>,
    com_operations: com_operations::Win16ComOperationTable,
    print_queues: print_queue::Win16PrintQueueState,
    pub(crate) selectors: SelectorTable,
    gate_selector: Selector,
    callback_gate_selector: Selector,
    bindings: Vec<ImportBinding>,
    builtin_data_exports:
        BTreeMap<&'static str, crate::win16_builtin_data_exports::BootstrappedBuiltinData>,
    runtime_selector_aliases:
        crate::win16_builtin_data_exports::RuntimeSelectorAliasCatalog,
    native_thunks_available: bool,
    pe32_dispatch: pe32_dispatch::Pe32ThunkDispatcher,
    win32_imports: crate::win32_import_state::Win32ImportState,
    network: crate::win16_network::Win16NetworkState,
    netbios: netbios_async::Win16NetbiosState,
    acm: acm::Win16AcmState,
    mci: mci::Win16MciState,
    midi: midi::Win16MidiState,
    media_services: crate::win16_media_services::Win16MediaServicesState,
    wave_audio: multimedia_buffers::Win16WaveState,
    sound: sound_state::Win16SoundState,
    automation: crate::win16_automation::Win16AutomationState,
    dos_caller_addresses: dos_address_space::Win16DosCallerAddresses,
    dde: crate::win16_dde::Win16DdeState,
    classic_dde: classic_dde_dispatch::ClassicDdeRuntimeState,
    dde_runtime_quiesced: bool,
    dde_abort_receipt: Option<crate::Win16DdeAbortReceipt>,
    dde_retired_callback_tokens: Vec<crate::Win16GuestCallbackToken>,
    dde_retired_guest_blocks: Vec<crate::win16_dde::Win16DdeRetiredGuestBlock>,
    dde_callbacks: Vec<dde_callback::Win16DdeCallbackFrame>,
    dde_guest_contexts: Vec<DdeGuestExecutionContext>,
    dde_context_restores: Vec<DdeGuestExecutionContext>,
    callback_kinds: Vec<CallbackKind>,
    callback_frame_ids: Vec<CallbackFrameId>,
    next_callback_frame_id: u64,
    callback_owners_quiesced: bool,
    callback_scheduler: callback_scheduler::Win16CallbackScheduler,
    legacy_cpu_frames: Vec<legacy_cpu_frame::Win16LegacyCpuFrame>,
    next_legacy_cpu_frame: u64,
    task_event_waits: Vec<task_event_wait::PendingTaskEventWait>,
    active_dispatch_call_owner: Option<u64>,
    active_dispatch_return: Option<x86_cpu::LegacyRegisterTransfer>,
    vm_start_tick: Option<u32>,
    font_callbacks: Vec<font_callback::FontCallbackFrame>,
    object_callbacks: Vec<object_callback::ObjectCallbackFrame>,
    line_dda_callbacks: Vec<line_dda::LineDdaCallbackFrame>,
    window_enumerations: Vec<window_enumeration::WindowEnumerationFrame>,
    deferred_window_batches: window_operations::DeferredWindowBatches,
    user_hooks: user_hooks::Win16UserHooks,
    window_callbacks: Vec<windows::WindowCallbackFrame>,
    retired_window_payloads: Vec<windows::RetiredWindowPayloadOwner>,
    native_function_callbacks: Vec<native_function_callback::NativeFunctionCallbackFrame>,
    window_operations: Vec<windows::WindowOperationFrame>,
    window_abort_receipt: Option<crate::Win16WindowAbortReceipt>,
    /// Captured only around real USER API dispatch; push_window_operation
    /// consumes it to retain the exact guest-entry architecture.
    window_dispatch_context: Option<x86_cpu::CpuContext>,
    next_window_operation: u64,
    window_procedures: BTreeMap<u16, windows::WindowProcedure>,
    /// DLGPROC returns BOOL16 and follows the Dialog Manager's contract.
    /// Keep its FAR procedure and module instance separate from WndProc.
    dialog_procedures: BTreeMap<u16, (u32, u16)>,
    window_data: BTreeMap<u16, window_data::Win16WindowDataState>,
    native_procedures: native_procedures::NativeProcedureGates,
    untranslated_window_messages: BTreeSet<u32>,
    #[allow(dead_code)]
    pub(crate) loaded: NeLoadedModule,
    #[allow(dead_code)]
    heap: GlobalHeap,
    #[allow(dead_code)]
    tasks: TaskRegistry,
    psp_selector: SelectorRef,
    process_views: process_views::Win16ProcessViews,
    instance_selector: SelectorRef,
    automatic_data: Option<crate::win16_loader::StaticDataReservation>,
    instance_handle: u16,
    task_handles: BTreeMap<OwnerId, u16>,
    first_task_handle: u16,
    /// Guest task priority, queue word, lock, and last-error. No host pointers.
    task_controls: kernel_task::TaskControls,
    module_path: Vec<u8>,
    modules: module_registry::ModuleRegistry,
    /// Exact identities left after incomplete selector cleanup. Keep their
    /// generations accounted for until state teardown; never retry a stale free.
    external_selector_cleanup: Vec<external_application::ExternalSelectorReservation>,
    module_callbacks: Vec<module_calls::ModuleCallFrame>,
    module_startup: module_calls::ModuleStartupState,
    program_load_reported: bool,
    resources: resources::ResourceState,
    resource_handlers: BTreeMap<(u16, usize), u32>,
    resource_callbacks: Vec<resource_calls::ResourceCallFrame>,
    far_returns: Vec<code_lifetime::FarCallResume>,
    next_far_call_id: u64,
    next_interrupt_id: u64,
    catch_records: catch_throw::CatchRecords,
    interrupt_returns: Vec<interrupt_entry::InterruptResume>,
    module_reap_pending: bool,
    user_queue: Option<MessageQueue>,
    /// Exact guest task identity paired with the host worker USER queue
    /// incarnation. HTASK alone is not a native thread or queue identity.
    user_task_queue: Option<(OwnerId, u16, u64, crate::Win16HostTaskQueue)>,
    next_app_notification_sequence: u64,
    proc_instances: proc::ProcInstances,
    interrupt_callbacks: BTreeMap<u16, SegmentedPointer>,
    /// Guest-side identities resolve the private SDK INTERRUPT callback field
    /// without exposing a host pointer or reusing an HTASK as a callback token.
    toolhelp_interrupt_handles: BTreeMap<u16, toolhelp_interrupt::Win16ToolhelpInterruptRegistration>,
    next_toolhelp_interrupt_handle: u32,
    toolhelp_notify: toolhelp_notify::Win16ToolhelpNotifyRegistry,
    toolhelp_notify_frames: Vec<toolhelp_notify_lifecycle::Win16ToolhelpNotifyEventFrame>,
    toolhelp_task_exit: toolhelp_notify_exit::Win16ToolhelpTaskExitState,
    toolhelp_interrupt_frames: Vec<toolhelp_interrupt::Win16ToolhelpInterruptFrame>,
    /// Partial selector roots remain owned until task teardown can retry release.
    toolhelp_interrupt_retained_selector_owners: Vec<toolhelp_interrupt::Win16ToolhelpRetainedSelectorOwner>,
    /// Guest stacks whose release failed remain owned until teardown retries it.
    toolhelp_interrupt_retained_stacks: Vec<toolhelp_interrupt::Win16ToolhelpRetainedStack>,
    /// A deferred event that could not safely resume blocks later guest steps.
    toolhelp_interrupt_stopped_event: Option<toolhelp_interrupt::Win16ToolhelpStoppedEvent>,
    /// Protected-mode DOS vector overrides retain checked selector identities.
    /// An explicit None is a cleared vector, distinct from no override.
    protected_dos_vectors: BTreeMap<u8, Option<SegmentedPointer>>,
    real_mode_vector_aliases: BTreeMap<(u16, u16), SelectorRef>,
    guest_gdi: gdi::GuestGdiHandles,
    wing_bitmaps: wing_bitmap::Win16WingBitmapState,
    guest_images: images::GuestImageHandles,
    guest_accelerators: user_cursor_accelerator::GuestAcceleratorHandles,
    win87em_install_count: u32,
    win87em_exception_handler: Option<SegmentedPointer>,
    files: BTreeMap<u16, Win16HostFile>,
    next_file: u16,
    /// Owner-scoped WNet identities share the HFILE WORD allocator with
    /// ordinary files; native spooler tokens remain opaque and task-owned.
    network_print_jobs: BTreeMap<OwnerId, network_print_jobs::Win16NetworkPrintJobs>,
    global_handles: BTreeMap<u16, GlobalHandle>,
    global_selectors: BTreeMap<u16, SelectorRef>,
    /// Runtime-owned HGLOBAL projections paired with one exact native queue
    /// lease. The native HDROP and this guest allocation have separate
    /// lifetimes; `native_pending` remains true across PM_NOREMOVE peeks.
    queued_drop_files: Vec<QueuedDropFileGlobal>,
    /// A guest may request DragFinish while a PM_NOREMOVE lease is still
    /// native-pending. Once that exact lease is removed, suppress its later
    /// delivery even if GlobalFree has already erased the HGLOBAL record.
    finished_queued_drop_leases:
        Vec<(crate::Win16HostDropFilesLease, crate::Win16HostWindow)>,
    dos_global_blocks: BTreeMap<u16, Win16DosGlobalBlock>,
    orphaned_dos_leases: Vec<dos_kernel::DosBlockLease>,
    allocated_selector_aliases: BTreeMap<u16, SelectorRef>,
    /// Independent descriptors returned specifically by KERNEL.175. They
    /// remain distinct from AllocCStoDSAlias and are the only valid
    /// PrestoChangoSelector destinations.
    api_allocated_selectors: BTreeMap<u16, SelectorRef>,
    /// Canonical owner records for guest-created views. Each record includes
    /// its exact selector generation and one or more real backing leases.
    selector_backing_leases: BTreeMap<u16, selector_ownership::SelectorBackingEntry>,
    /// Exact records for fixed runtime chunks inside the Win16 reservation.
    runtime_arena_backing: runtime_arena_backing::RuntimeArenaBackingRegistry,
    /// MapLS descriptors expose a tracked guest-heap address through an LDT
    /// selector bit. They are distinct from guest GlobalAlloc selectors.
    mapls_selectors: BTreeMap<u16, selector_ownership::MapLsEntry>,
    mapls_bases: BTreeMap<u32, u16>,
    window_classes: classes::GuestWindowClasses,
    window_handles: BTreeMap<u16, crate::Win16HostWindow>,
    /// System-class role retained per live guest HWND. In particular, only an
    /// HWND created from the exact predefined MDIClient alias may select the
    /// client form of Win16 MDI messages.
    window_system_classes: BTreeMap<u16, crate::Win16HostSystemClass>,
    /// Exact MDI child HWNDs claimed from a live MDI create continuation.
    /// Parentage alone is insufficient because ordinary controls can also be
    /// children of an MDI client.
    mdi_children: BTreeSet<u16>,
    /// Exact runtime creation generation for each guest HWND whose native
    /// creation operation exposed an identity to the host. A receipt for an
    /// older HWND incarnation cannot retire a reused guest handle.
    window_creations: BTreeMap<u16, crate::Win16CreationId>,
    /// Guest child-to-parent relations used to retire dialog/control aliases.
    window_parents: BTreeMap<u16, u16>,
    /// Latest host-observed parent per exact native HWND incarnation. The
    /// inner `None` records an observed top-level parent, distinct from no
    /// observation while a CreateWindow callback is in progress.
    window_parent_observations:
        BTreeMap<crate::Win16HostWindow, Option<crate::Win16HostWindow>>,
    /// Runtime-owned guest aliases that must be destroyed during task cleanup.
    /// Borrowed HWND aliases returned by USER are deliberately excluded.
    owned_window_handles: BTreeSet<u16>,
    clipboard_state: user_services_controls::GuestClipboardState,
    common_dialog_state: commdlg::Win16CommonDialogState,
    kernel_file_system: kernel_file_system::Win16KernelFileSystemState,
    pending_kernel_diagnostic_effects: Vec<kernel_diagnostics::Win16KernelDiagnosticEffect>,
    window_teardown_state: WindowTeardownState,
    guest_menus: menu::GuestMenus,
    timers: message_calls::Win16TimerRegistrations,
    next_window_handle: u16,
    next_window_creation: u64,
    loaded_segment_handles: BTreeMap<u16, u16>,
    discarded_handles: BTreeSet<u16>,
    reported_global_flags: BTreeSet<u16>,
    reported_global_realloc_flags: BTreeSet<u16>,
    compat: crate::win16_host_compat::Win16CompatState,
}

struct QueuedDropFileGlobal {
    lease: crate::Win16HostDropFilesLease,
    window: crate::Win16HostWindow,
    guest_handle: u16,
    allocation: GlobalHandle,
    files: crate::Win16HostDropFiles,
    native_pending: bool,
    /// DragFinish is void. If GlobalFree is attempted while PM_NOREMOVE still
    /// owns the exact MSG, finish it after queue retirement can safely release
    /// this runtime-owned snapshot.
    finish_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowTeardownState { Live, AbortPending, NativeQuiescent, Closed }

impl Win16State {
    pub(crate) fn set_work_executor(&mut self, work: parallel_work::SharedExecutor) {
        self.sound.work = work;
    }

    pub(crate) fn is_service_gate(&self, selector: u16) -> bool {
        selector == self.gate_selector.0
    }

    pub(crate) fn is_callback_gate(&self, selector: u16) -> bool {
        selector == self.callback_gate_selector.0
    }

    pub(crate) fn unavailable_imports(&self) -> Vec<String> {
        self.bindings
            .iter()
            .filter_map(|entry| match entry {
                ImportBinding::Unavailable { .. } => Some(entry.name()),
                ImportBinding::Supported(_) => None,
            })
            .collect()
    }

}

#[cfg(test)]
#[path = "win16_test_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "win16_destroy_receipt_tests.rs"]
mod destroy_receipt_tests;
