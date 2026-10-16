//! Per-callback owned HANDLETABLE16/METARECORD16 and native table acknowledgement.

use super::*;
use win16_abi::Access;

pub(super) struct MetafileCallbackPayload {
    table: u32,
    count: u16,
    committed: bool,
}

impl Win16State {
    pub(in crate::win16_runtime) fn retain_metafile_callback(
        &mut self,
        registers: &Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        callback: Win16HostCallback,
        dc: crate::Win16HostDc,
        record: Vec<u8>,
        count: u16,
        host_operation: crate::Win16HostWindowOperationId,
        native_source: crate::Win16NativeCallbackSource,
    ) -> Result<(), RuntimeError> {
        let (guest_dc, procedure, parameter) =
            match self.window_operations.last().and_then(|f| f.continuation()) {
                Some(super::super::windows::WindowReturn::EnumMetafile {
                    dc: guest,
                    host_dc,
                    procedure,
                    parameter,
                }) if *host_dc == dc
                    && native_source == (crate::Win16NativeCallbackSource::Metafile { dc }) =>
                {
                    (*guest, *procedure, *parameter)
                }
                _ => {
                    return Err(invariant(
                        "WMF callback differs from its exact API continuation",
                    ));
                }
            };
        self.native_function_callbacks
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain WMF callback owner",
                    error,
                )
            })?;
        let callback_id = self.reserve_callback_frame_id()?;
        self.push_callback_kind(CallbackKind::NativeFunction, callback_id)?;
        self.native_function_callbacks
            .push(NativeFunctionCallbackFrame {
                callback_id,
                callback,
                procedure,
                arguments: Vec::new(),
                metafile: None,
                entry_pending: true,
                borrowed_dc: None,
                borrowed_bitmaps: Vec::new(),
                saved: registers.clone(),
                active_call: None,
                allocation: None,
                allocation_locked: false,
                host_operation,
                native_source,
                entry_error: None,
                guest_return: None,
                return_error: None,
                native_resume_error: None,
                resumed_step: None,
            });
        let setup = (|| {
            let crate::Win16HostMetafileResult::Table(tokens) =
                host.win16_metafile(crate::Win16HostMetafileOperation::CallbackTable { callback })?
            else {
                return Err(invariant(
                    "WMF callback table query returned another result kind",
                ));
            };
            if tokens.len() != usize::from(count) || formats::parse_wmf_record(&record).is_err() {
                return Err(invariant(
                    "native WMF callback supplied inconsistent record or table extents",
                ));
            }
            let mut bytes = Vec::with_capacity(tokens.len() * 2 + record.len());
            for token in tokens {
                let guest = match token {
                    None => 0,
                    Some(token) => self.guest_gdi.existing_object(token).ok_or_else(|| {
                        invariant("WMF enumeration table introduced an unpublished object")
                    })?,
                };
                bytes.extend_from_slice(&guest.to_le_bytes());
            }
            let record_offset = bytes.len();
            bytes.extend_from_slice(&record);
            let allocation = self
                .heap
                .alloc(
                    memory,
                    PROPERTY_CALLBACK_OWNER,
                    u32::try_from(bytes.len()).map_err(|_| {
                        invariant("WMF callback buffer exceeds guest address space")
                    })?,
                    AllocationFlags::fixed().with_zero_init(),
                )
                .map_err(crate::runtime_error)?;
            self.native_function_callbacks
                .last_mut()
                .expect("frame retained")
                .allocation = Some(allocation);
            let pointer = self
                .heap
                .lock(allocation, &mut self.selectors, memory)
                .map_err(crate::runtime_error)?;
            self.native_function_callbacks
                .last_mut()
                .expect("frame retained")
                .allocation_locked = true;
            self.write_text_bytes(memory, pointer, &bytes)?;
            let record_pointer = self
                .selectors
                .add_bytes(pointer, record_offset as u32)
                .map_err(crate::runtime_error)?;
            let frame = self
                .native_function_callbacks
                .last_mut()
                .expect("frame retained");
            frame.arguments = vec![
                Win16FarCallbackArgument::Word(guest_dc),
                Win16FarCallbackArgument::HugeGuestPointer {
                    far: pointer.far_value(),
                    access: Access::Write,
                    bytes: u32::from(count) * 2,
                },
                Win16FarCallbackArgument::HugeGuestPointer {
                    far: record_pointer.far_value(),
                    access: Access::Write,
                    bytes: record.len() as u32,
                },
                Win16FarCallbackArgument::Word(count),
                Win16FarCallbackArgument::Dword(parameter),
            ];
            frame.metafile = Some(MetafileCallbackPayload {
                table: pointer.far_value(),
                count,
                committed: false,
            });
            Ok(())
        })();
        setup.map_err(|error| self.fail_native_function_callback_entry(callback_id, error))
    }

    pub(in crate::win16_runtime) fn metafile_callback_for_table(
        &self,
        table: u32,
        count: u16,
    ) -> Option<Win16HostCallback> {
        self.native_function_callbacks
            .iter()
            .rev()
            .find_map(|frame| {
                frame
                    .metafile
                    .as_ref()
                    .filter(|payload| payload.table == table && payload.count == count)
                    .map(|_| frame.callback)
            })
    }

    pub(super) fn commit_metafile_callback_table(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(frame) = self.native_function_callbacks.last() else {
            return Ok(());
        };
        let Some(payload) = frame.metafile.as_ref().filter(|p| !p.committed) else {
            return Ok(());
        };
        let callback = frame.callback;
        let pointer = self
            .selectors
            .pointer_from_far(payload.table)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, usize::from(payload.count) * 2)?;
        let mut tokens = Vec::with_capacity(usize::from(payload.count));
        for word in bytes.chunks_exact(2) {
            let word = u16::from_le_bytes([word[0], word[1]]);
            tokens.push(if word == 0 {
                None
            } else {
                self.guest_gdi.object(word)
            });
        }
        match host.win16_metafile(crate::Win16HostMetafileOperation::CommitCallbackTable {
            callback,
            objects: tokens,
        })? {
            crate::Win16HostMetafileResult::TableCommitted => {
                self.native_function_callbacks
                    .last_mut()
                    .expect("frame retained")
                    .metafile
                    .as_mut()
                    .expect("payload retained")
                    .committed = true;
                Ok(())
            }
            _ => Err(invariant(
                "WMF table acknowledgement returned another result kind",
            )),
        }
    }
}
fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
