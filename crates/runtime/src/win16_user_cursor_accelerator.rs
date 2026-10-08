//! Runtime translation for USER cursor, accelerator, and WinHelp calls.

use std::sync::Arc;

use formats::{NeResourceId, extract_ne_resource};
use guest_core::{Registers, memory::Memory};
use win16_abi::{
    Msg16, Win16AcceleratorEntry, Win16HelpData, Win16ResourceName, Win16ReturnKind,
    Win16UserCursorAcceleratorRequest,
};

use super::{Win16State, windows::WindowReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAccelEntry,
    Win16HostAccelerator, Win16HostHelpData, Win16HostQueuedMessage,
    Win16HostUserCursorAcceleratorOperation, Win16HostWindow,
    Win16MessageParam, Win16MessageSource, Win16WindowOperation,
};

const RT_ACCELERATOR: u16 = 9;
const MAX_ACCELERATOR_RESOURCE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
struct GuestAccelerator {
    owner_module: u16,
    resource_id: NeResourceId,
    host_table: Win16HostAccelerator,
}

/// A TranslateAccelerator operation retains this lease through any native
/// synchronous WndProc callback and releases it only when the worker completes.
#[derive(Clone, Debug)]
pub(super) struct Win16AcceleratorLease(Arc<GuestAccelerator>);

impl Win16AcceleratorLease {
    pub(super) fn host_table(&self) -> Win16HostAccelerator {
        self.0.host_table
    }

    pub(super) fn owner_module(&self) -> u16 {
        self.0.owner_module
    }
}

#[derive(Clone, Debug)]
pub(super) enum Win16UserCursorAcceleratorContinuation {
    SetCursor,
    ShowCursor,
    WinHelp,
    LoadAccelerators {
        guest_handle: u16,
        owner_module: u16,
        resource_id: NeResourceId,
    },
    TranslateAccelerator {
        lease: Win16AcceleratorLease,
    },
}

#[derive(Default)]
pub(super) struct GuestAcceleratorHandles {
    entries: Vec<(u16, Arc<GuestAccelerator>)>,
    next_handle: u16,
}

impl GuestAcceleratorHandles {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_handle: 1,
        }
    }

    fn by_handle(&self, handle: u16) -> Option<Win16AcceleratorLease> {
        self.entries.iter().find_map(|(candidate, entry)| {
            (*candidate == handle).then(|| Win16AcceleratorLease(Arc::clone(entry)))
        })
    }

    fn by_resource(&self, owner_module: u16, resource_id: &NeResourceId) -> Option<u16> {
        self.entries.iter().find_map(|(handle, entry)| {
            (entry.owner_module == owner_module
                && same_resource_id(&entry.resource_id, resource_id))
            .then_some(*handle)
        })
    }

    fn reserve_handle(&mut self) -> Result<u16, RuntimeError> {
        self.entries.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a Win16 accelerator handle",
                error,
            )
        })?;
        for _ in 0..u16::MAX {
            let candidate = self.next_handle.max(1);
            self.next_handle = candidate.wrapping_add(1).max(1);
            if self.entries.iter().all(|(used, _)| *used != candidate) {
                return Ok(candidate);
            }
        }
        Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 accelerator handle table is full",
        ))
    }

    pub(super) fn insert_reserved(
        &mut self,
        handle: u16,
        owner_module: u16,
        resource_id: NeResourceId,
        host_table: Win16HostAccelerator,
    ) {
        // The runtime reserves capacity and a free guest WORD before starting
        // the native creation request. LoadAccelerators does not deliver a
        // synchronous application callback, so no other guest table insert
        // can consume this reserved slot while the USER worker is running.
        debug_assert!(self.entries.iter().all(|(used, _)| *used != handle));
        self.entries.push((
            handle,
            Arc::new(GuestAccelerator {
                owner_module,
                resource_id,
                host_table,
            }),
        ));
    }

    pub(super) fn module_roots(&self) -> impl Iterator<Item = u16> + '_ {
        self.entries.iter().map(|(_, entry)| entry.owner_module)
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn begin_user_cursor_accelerator(
        &mut self,
        request: Win16UserCursorAcceleratorRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        match request {
            Win16UserCursorAcceleratorRequest::SetCursor { cursor } => {
                let host_cursor = if cursor == 0 {
                    None
                } else if let Some(cursor) = self.guest_images.cursor(cursor) {
                    Some(cursor)
                } else {
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                };
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::UserCursorAccelerator(
                        Win16HostUserCursorAcceleratorOperation::SetCursor {
                            cursor: host_cursor,
                        },
                    ),
                    WindowReturn::UserCursorAccelerator(
                        Win16UserCursorAcceleratorContinuation::SetCursor,
                    ),
                    return_to,
                )
            }
            Win16UserCursorAcceleratorRequest::ShowCursor { show } => self.begin_window_operation(
                registers,
                memory,
                host,
                Win16WindowOperation::UserCursorAccelerator(
                    Win16HostUserCursorAcceleratorOperation::ShowCursor { show },
                ),
                WindowReturn::UserCursorAccelerator(
                    Win16UserCursorAcceleratorContinuation::ShowCursor,
                ),
                return_to,
            ),
            Win16UserCursorAcceleratorRequest::WinHelp {
                window,
                help_file,
                command,
                data,
            } => {
                let data = match data {
                    Win16HelpData::Ignored => Win16HostHelpData::Ignored,
                    Win16HelpData::Scalar(value) => Win16HostHelpData::Scalar(value),
                    Win16HelpData::String(value) => Win16HostHelpData::String(value),
                    Win16HelpData::MultiKey {
                        key_list,
                        key_phrase,
                    } => Win16HostHelpData::MultiKey {
                        key_list,
                        key_phrase,
                    },
                    Win16HelpData::WindowPosition {
                        x,
                        y,
                        width,
                        height,
                        max_state,
                        member,
                    } => Win16HostHelpData::WindowPosition {
                        x,
                        y,
                        width,
                        height,
                        max_state,
                        member,
                    },
                    Win16HelpData::NullPointer => Win16HostHelpData::NullPointer,
                    Win16HelpData::Unsupported { .. } => {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            format!("Win16 WinHelp command 0x{command:04X} has an undocumented data contract; USER returned FALSE")));
                        return self.user_cursor_accelerator_return(registers, return_to, 0);
                    }
                };
                let native_window = match self.accelerator_host_window(window) {
                    Some(value) => Some(value),
                    None if window == 0 => None,
                    None => return self.user_cursor_accelerator_return(registers, return_to, 0),
                };
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::UserCursorAccelerator(
                        Win16HostUserCursorAcceleratorOperation::WinHelp {
                            window: native_window,
                            help_file,
                            command,
                            data,
                        },
                    ),
                    WindowReturn::UserCursorAccelerator(
                        Win16UserCursorAcceleratorContinuation::WinHelp,
                    ),
                    return_to,
                )
            }
            Win16UserCursorAcceleratorRequest::LoadAccelerators { instance, name } => {
                let Some(owner_module) = self.module_handle_for_instance(instance) else {
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                };
                let resource_id = ne_resource_id(name);
                if let Some(handle) = self
                    .guest_accelerators
                    .by_resource(owner_module, &resource_id)
                {
                    return self.user_cursor_accelerator_return(
                        registers,
                        return_to,
                        u32::from(handle),
                    );
                }
                let Some(bytes) = self.accelerator_resource(owner_module, &resource_id, host)?
                else {
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                };
                let entries = match win16_abi::exports::decode_accelerator_resource(&bytes) {
                    Ok(entries) => entries,
                    Err(error) => {
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::CompatibilityGap,
                            format!(
                                "Win16 RT_ACCELERATOR was not loaded: {}; USER returned NULL",
                                error.reason()
                            ),
                        ));
                        return self.user_cursor_accelerator_return(registers, return_to, 0);
                    }
                };
                let mut host_entries = Vec::new();
                host_entries
                    .try_reserve_exact(entries.len())
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve owned Win16 accelerator entries",
                            error,
                        )
                    })?;
                host_entries.extend(entries.iter().map(host_accelerator_entry));
                let guest_handle = self.guest_accelerators.reserve_handle()?;
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::UserCursorAccelerator(
                        Win16HostUserCursorAcceleratorOperation::LoadAccelerators {
                            entries: host_entries,
                        },
                    ),
                    WindowReturn::UserCursorAccelerator(
                        Win16UserCursorAcceleratorContinuation::LoadAccelerators {
                            guest_handle,
                            owner_module,
                            resource_id,
                        },
                    ),
                    return_to,
                )
            }
            Win16UserCursorAcceleratorRequest::TranslateAccelerator {
                window,
                accelerator,
                message,
            } => {
                let Some(lease) = self.guest_accelerators.by_handle(accelerator) else {
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                };
                let native_window = match self.accelerator_host_window(window) {
                    Some(value) => Some(value),
                    None if window == 0 => None,
                    None => return self.user_cursor_accelerator_return(registers, return_to, 0),
                };
                let message_window = match self.accelerator_host_window(message.hwnd) {
                    Some(value) => Some(value),
                    None if message.hwnd == 0 => None,
                    None => return self.user_cursor_accelerator_return(registers, return_to, 0),
                };
                let queued = accelerator_message(message, message_window);
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::UserCursorAccelerator(
                        Win16HostUserCursorAcceleratorOperation::TranslateAccelerator {
                            window: native_window,
                            table: lease.host_table(),
                            message: queued,
                        },
                    ),
                    WindowReturn::UserCursorAccelerator(
                        Win16UserCursorAcceleratorContinuation::TranslateAccelerator { lease },
                    ),
                    return_to,
                )
            }
        }
    }

    pub(in crate::win16_runtime) fn user_accelerator_module_roots(&self) -> Vec<u16> {
        self.guest_accelerators.module_roots().collect()
    }

    fn user_cursor_accelerator_return(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
        value: u32,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(
            registers,
            return_to.0,
            return_to.1,
            return_to.2,
            value,
            Win16ReturnKind::Word,
        )
    }

    fn accelerator_host_window(&self, handle: u16) -> Option<Win16HostWindow> {
        self.window_handles.get(&handle).copied()
    }

    fn accelerator_resource(
        &self,
        owner_module: u16,
        id: &NeResourceId,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let Some(record) = self.modules.records.get(&owner_module) else {
            return Ok(None);
        };
        let Some(definition) = record.definition.as_ref() else {
            return Ok(None);
        };
        let Some(resource) = definition
            .resource_types
            .iter()
            .filter(|resource_type| resource_type.id == NeResourceId::Numeric(RT_ACCELERATOR))
            .flat_map(|resource_type| &resource_type.resources)
            .find(|resource| same_resource_id(&resource.id, id))
        else {
            return Ok(None);
        };
        if resource.byte_length > MAX_ACCELERATOR_RESOURCE_BYTES {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 RT_ACCELERATOR exceeds the bounded resource parser size; USER returned NULL",
            ));
            return Ok(None);
        }
        extract_ne_resource(&record.image, resource)
            .map(Some)
            .map_err(crate::runtime_error)
    }
}

fn host_accelerator_entry(entry: &Win16AcceleratorEntry) -> Win16HostAccelEntry {
    Win16HostAccelEntry {
        flags: entry.flags,
        key: entry.key,
        command: entry.command,
    }
}

fn ne_resource_id(name: Win16ResourceName) -> NeResourceId {
    match name {
        Win16ResourceName::Id(id) => NeResourceId::Numeric(id),
        Win16ResourceName::Name(name) => NeResourceId::Name(name),
    }
}

fn same_resource_id(left: &NeResourceId, right: &NeResourceId) -> bool {
    match (left, right) {
        (NeResourceId::Numeric(left), NeResourceId::Numeric(right)) => left == right,
        (NeResourceId::Name(left), NeResourceId::Name(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

fn accelerator_message(message: Msg16, window: Option<Win16HostWindow>) -> Win16HostQueuedMessage {
    Win16HostQueuedMessage {
        source: Win16MessageSource::GuestMessage,
        window,
        message: message.message,
        w_param: message.w_param,
        l_param: Win16MessageParam::GuestBits(message.l_param),
        time: message.time,
        point: crate::Win16HostPoint {
            x: i32::from(message.pt.x),
            y: i32::from(message.pt.y),
        },
    }
}
