//! Runtime translation for USER cursor, accelerator, and WinHelp calls.

use std::sync::Arc;

use formats::{NeResource, NeResourceId, extract_ne_resource};
use guest_core::{Registers, memory::Memory};
use win16_abi::{
    Msg16, Win16AcceleratorEntry, Win16HelpData, Win16ResourceName, Win16ReturnKind,
    Win16UserCursorAcceleratorRequest,
};

use super::{Win16State, windows::WindowReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAccelEntry,
    Win16HostAccelerator, Win16HostHelpData, Win16HostQueuedMessage,
    Win16HostUserCursorAcceleratorOperation, Win16HostWindow, Win16MessageParam,
    Win16MessageSource, Win16WindowOperation,
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
    GetCursor,
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
            (entry.owner_module == owner_module && entry.resource_id == *resource_id)
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
            Win16UserCursorAcceleratorRequest::GetCursor => self.begin_window_operation(
                registers,
                memory,
                host,
                Win16WindowOperation::UserCursorAccelerator(
                    Win16HostUserCursorAcceleratorOperation::GetCursor,
                ),
                WindowReturn::UserCursorAccelerator(
                    Win16UserCursorAcceleratorContinuation::GetCursor,
                ),
                return_to,
            ),
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
                // FindResource treats "#258" as integer id 258, and names
                // LoadAccelerators as the loader for that accelerator resource.
                // A table that is already loaded is the same guest handle for
                // either spelling.
                let Some(located) = self.accelerator_resource(instance, &name, host)? else {
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                };
                let owner_module = located.owner_module;
                let resource_id = located.resource.id.clone();
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
                if located.resource.byte_length > MAX_ACCELERATOR_RESOURCE_BYTES {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "Win16 RT_ACCELERATOR exceeds the bounded resource parser size; USER returned NULL",
                    ));
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                }
                let Some(record) = self.modules.records.get(&owner_module) else {
                    return self.user_cursor_accelerator_return(registers, return_to, 0);
                };
                let bytes = extract_ne_resource(&record.image, &located.resource)
                    .map_err(crate::runtime_error)?;
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

    /// Locate one RT_ACCELERATOR by the same name rules as FindResource.
    /// The returned id is the id stored in the module, so a numeric id and
    /// its "#digits" name share one loaded table.
    fn accelerator_resource(
        &self,
        instance: u16,
        name: &Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<LocatedAccelerator>, RuntimeError> {
        let info =
            self.find_resource(instance, name, &Win16ResourceName::Id(RT_ACCELERATOR), host)?;
        if info == 0 {
            return Ok(None);
        }
        let Some(metadata) = self.resource_metadata(instance, info) else {
            return Ok(None);
        };
        let candidates = {
            let Some(record) = self.modules.records.get(&metadata.key.module) else {
                return Ok(None);
            };
            let Some(entry) = record
                .definition
                .as_ref()
                .and_then(|definition| definition.resource_types.get(metadata.type_index))
            else {
                return Ok(None);
            };
            let mut candidates = Vec::new();
            candidates
                .try_reserve(entry.resources.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve Win16 accelerator resource candidates",
                        error,
                    )
                })?;
            candidates.extend(
                entry
                    .resources
                    .iter()
                    .filter(|resource| {
                        resource.file_offset == metadata.offset
                            && resource.byte_length == metadata.length
                    })
                    .cloned(),
            );
            candidates
        };
        let Some(resource) =
            self.accelerator_at_info(metadata.key.module, info, &candidates, host)?
        else {
            return Ok(None);
        };
        Ok(Some(LocatedAccelerator {
            owner_module: metadata.key.module,
            resource,
        }))
    }

    fn accelerator_at_info(
        &self,
        module: u16,
        info: u16,
        candidates: &[NeResource],
        host: &mut impl RuntimeHost,
    ) -> Result<Option<NeResource>, RuntimeError> {
        if candidates.len() == 1 {
            return Ok(candidates.first().cloned());
        }
        for resource in candidates {
            let requested = match &resource.id {
                NeResourceId::Numeric(id) => Win16ResourceName::Id(*id),
                NeResourceId::Name(name) => Win16ResourceName::Name(name.clone()),
            };
            if self.find_resource(
                module,
                &requested,
                &Win16ResourceName::Id(RT_ACCELERATOR),
                host,
            )? == info
            {
                return Ok(Some(resource.clone()));
            }
        }
        Ok(None)
    }
}

struct LocatedAccelerator {
    owner_module: u16,
    resource: NeResource,
}

fn host_accelerator_entry(entry: &Win16AcceleratorEntry) -> Win16HostAccelEntry {
    Win16HostAccelEntry {
        flags: entry.flags,
        key: entry.key,
        command: entry.command,
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

#[cfg(test)]
mod tests {
    use formats::{NeResource, NeResourceId, NeResourceType};
    use win16_abi::Win16ResourceName;

    use super::super::test_support::{NoHost, tiny_ne_executable};
    use crate::{Runtime, Win16HostAccelerator};

    fn add_accelerator(runtime: &mut Runtime, id: NeResourceId, bytes: &[u8]) -> (usize, usize) {
        let state = runtime.win16.as_mut().unwrap();
        let module = state.modules.main;
        let record = state.modules.records.get_mut(&module).unwrap();
        let offset = record.image.len();
        record.image.extend_from_slice(bytes);
        let definition = record.definition.as_mut().unwrap();
        definition.header.resource_table_offset = 0x100;
        if !definition
            .resource_types
            .iter()
            .any(|entry| entry.id == NeResourceId::Numeric(super::RT_ACCELERATOR))
        {
            definition.resource_types.push(NeResourceType {
                id: NeResourceId::Numeric(super::RT_ACCELERATOR),
                resources: Vec::new(),
            });
        }
        definition
            .resource_types
            .iter_mut()
            .find(|entry| entry.id == NeResourceId::Numeric(super::RT_ACCELERATOR))
            .unwrap()
            .resources
            .push(NeResource {
                id,
                file_offset: offset,
                byte_length: bytes.len(),
                flags: 0,
                handle: 0,
                usage: 0,
            });
        (offset, bytes.len())
    }

    #[test]
    fn resource_metadata_accelerator_pound_name_selects_ordinal_table() {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\ACCEL.NE").unwrap();
        let bytes = [0x80, 0x41, 0x00, 0x01, 0x00];
        add_accelerator(&mut runtime, NeResourceId::Numeric(258), &bytes);
        let state = runtime.win16.as_mut().unwrap();
        let module = state.modules.main;
        let mut host = NoHost;
        let by_id = state
            .accelerator_resource(module, &Win16ResourceName::Id(258), &mut host)
            .unwrap()
            .unwrap();
        let by_pound = state
            .accelerator_resource(0, &Win16ResourceName::Name(b"#258".to_vec()), &mut host)
            .unwrap()
            .unwrap();
        assert_eq!(by_id.owner_module, module);
        assert_eq!(by_pound.owner_module, module);
        assert_eq!(by_id.resource.id, NeResourceId::Numeric(258));
        assert_eq!(by_pound.resource.id, NeResourceId::Numeric(258));
        let image = &state.modules.records.get(&module).unwrap().image;
        assert_eq!(
            formats::extract_ne_resource(image, &by_pound.resource).unwrap(),
            bytes
        );
        assert!(
            state
                .accelerator_resource(0, &Win16ResourceName::Id(259), &mut host)
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .accelerator_resource(0, &Win16ResourceName::Name(b"#259".to_vec()), &mut host)
                .unwrap()
                .is_none()
        );
        state.guest_accelerators.insert_reserved(
            7,
            module,
            NeResourceId::Numeric(258),
            Win16HostAccelerator(1),
        );
        assert_eq!(
            state
                .guest_accelerators
                .by_resource(module, &by_pound.resource.id),
            Some(7)
        );
    }

    #[test]
    fn resource_metadata_accelerator_shared_bytes_keep_each_ordinal() {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\ACCEL.NE").unwrap();
        let bytes = [0x80, 0x42, 0x00, 0x02, 0x00];
        let (offset, length) = add_accelerator(&mut runtime, NeResourceId::Numeric(1), &bytes);
        let state = runtime.win16.as_mut().unwrap();
        let module = state.modules.main;
        state
            .modules
            .records
            .get_mut(&module)
            .unwrap()
            .definition
            .as_mut()
            .unwrap()
            .resource_types
            .iter_mut()
            .find(|entry| entry.id == NeResourceId::Numeric(super::RT_ACCELERATOR))
            .unwrap()
            .resources
            .push(NeResource {
                id: NeResourceId::Numeric(2),
                file_offset: offset,
                byte_length: length,
                flags: 0,
                handle: 0,
                usage: 0,
            });
        let mut host = NoHost;
        let first = state
            .accelerator_resource(0, &Win16ResourceName::Id(1), &mut host)
            .unwrap()
            .unwrap();
        let second = state
            .accelerator_resource(0, &Win16ResourceName::Name(b"#2".to_vec()), &mut host)
            .unwrap()
            .unwrap();
        assert_eq!(first.resource.id, NeResourceId::Numeric(1));
        assert_eq!(second.resource.id, NeResourceId::Numeric(2));
        assert_eq!(first.owner_module, second.owner_module);
    }
}
