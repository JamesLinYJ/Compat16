//! Checked native function callbacks with explicit FAR PASCAL arguments.

#[path = "win16_native_function_callback_finish.rs"]
mod finish;
#[path = "win16_metafile_callback.rs"]
mod metafile;

use std::sync::Arc;

use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers, memory::Memory};
use win16_abi::{AllocationFlags, GlobalHandle, Win16Error};

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::{CallbackKind, Win16State};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostCallback,
    Win16HostPropertyCallbackName, Win16HostWindow, Win16WindowReply,
};
use x86_cpu::Cpu;

// Private callback storage must not join a guest task's GlobalFreeAll owner.
const PROPERTY_CALLBACK_OWNER: OwnerId = OwnerId(u32::MAX);
const MAX_PROPERTY_NAME_BYTES: usize = 255;

pub(super) struct NativeFunctionCallbackFrame {
    pub(super) callback_id: super::CallbackFrameId,
    callback: Win16HostCallback,
    procedure: u32,
    arguments: Vec<Win16FarCallbackArgument>,
    metafile: Option<metafile::MetafileCallbackPayload>,
    entry_pending: bool,
    borrowed_dc: Option<(u16, crate::Win16HostDc)>,
    borrowed_bitmaps: Vec<crate::Win16HostGdiObject>,
    saved: Registers,
    active_call: Option<Win16FarCallbackFrame>,
    allocation: Option<GlobalHandle>,
    allocation_locked: bool,
    pub(super) host_operation: crate::Win16HostWindowOperationId,
    native_source: crate::Win16NativeCallbackSource,
    entry_error: Option<Arc<RuntimeError>>,
    guest_return: Option<u32>,
    return_error: Option<Arc<RuntimeError>>,
    native_resume_error: Option<Arc<RuntimeError>>,
    resumed_step: Option<crate::Win16WindowStep>,
}

impl Win16State {
    pub(super) fn native_function_has_returned_value(&self) -> bool {
        self.native_function_callbacks.last().is_some_and(|frame| frame.guest_return.is_some())
    }

    pub(super) fn terminal_native_function_callback_identity(
        &self,
        callback_id: super::CallbackFrameId,
    ) -> Option<(
        crate::Win16HostCallback,
        crate::Win16HostWindowOperationId,
        crate::Win16NativeCallbackSource,
    )> {
        let frame = self
            .native_function_callbacks
            .iter()
            .rev()
            .find(|frame| frame.callback_id == callback_id)?;
        Some((frame.callback, frame.host_operation, frame.native_source))
    }

    pub(super) fn retain_gray_string_callback(
        &mut self,
        registers: &Registers,
        callback: Win16HostCallback,
        dc: crate::Win16HostDc,
        count: i16,
        host_operation: crate::Win16HostWindowOperationId,
        native_source: crate::Win16NativeCallbackSource,
    ) -> Result<bool, RuntimeError> {
        let (procedure, data) = match self
            .window_operations
            .last()
            .and_then(|frame| frame.continuation())
        {
            Some(super::windows::WindowReturn::GrayString {
                procedure,
                data,
                count: expected,
            }) if *procedure != 0
                && *expected == count
                && native_source == (crate::Win16NativeCallbackSource::GrayString { dc }) =>
            {
                (*procedure, *data)
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "GrayString callback differs from its exact API continuation",
                ));
            }
        };
        self.native_function_callbacks
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain native drawing callback owner",
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
                arguments: vec![Win16FarCallbackArgument::Word(0), Win16FarCallbackArgument::Dword(data),
                    Win16FarCallbackArgument::Word(count as u16)],
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
        let Some(guest_dc) = self.guest_gdi.allocate_dc(dc) else {
            // Like the timer's unentered callback path, resume native USER
            // with FALSE without constructing a guest CPU call or alias.
            self.retire_callback_binding(CallbackKind::NativeFunction, callback_id)?;
            self.native_function_callbacks.pop();
            return Ok(false);
        };
        let frame = self
            .native_function_callbacks
            .last_mut()
            .expect("new callback retained");
        frame.arguments[0] = Win16FarCallbackArgument::Word(guest_dc);
        frame.borrowed_dc = Some((guest_dc, dc));
        Ok(true)
    }

    pub(super) fn retain_window_property_callback(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        name: Win16HostPropertyCallbackName,
        data: u16,
        host_operation: crate::Win16HostWindowOperationId,
        native_source: crate::Win16NativeCallbackSource,
    ) -> Result<(), RuntimeError> {
        let (procedure, guest_window) = self.pending_window_property_enum().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native function callback has no pending native function operation",
            )
        })?;
        if self.window_handles.get(&guest_window) != Some(&native_window) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native function callback window identity changed during enumeration",
            ));
        }

        self.native_function_callbacks
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain exact Win16 native function callback owner",
                    error,
                )
            })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let saved = registers.clone();
        self.push_callback_kind(CallbackKind::NativeFunction, callback_id)?;
        self.native_function_callbacks
            .push(NativeFunctionCallbackFrame {
                callback_id,
                callback,
                procedure,
                arguments: vec![Win16FarCallbackArgument::Word(guest_window), Win16FarCallbackArgument::Dword(0),
                    Win16FarCallbackArgument::Word(data)],
                metafile: None,
                borrowed_dc: None,
                borrowed_bitmaps: Vec::new(),
                entry_pending: true,
                saved,
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
            self.refresh_pending_window_parents(host)?;
            let name_argument = match name {
                Win16HostPropertyCallbackName::Atom(atom) => u32::from(atom),
                Win16HostPropertyCallbackName::String(bytes) => {
                    self.allocate_property_name(callback_id, memory, &bytes)?
                }
            };
            let frame = self.native_function_callbacks.last_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 native function callback owner disappeared during native retention",
                )
            })?;
            if frame.callback_id != callback_id
                || frame.active_call.is_some()
                || !frame.entry_pending
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 native function retention changed its exact callback owner",
                ));
            }
            frame.arguments[1] = Win16FarCallbackArgument::Dword(name_argument);
            Ok(())
        })();
        if let Err(error) = setup {
            return Err(self.fail_native_function_callback_entry(callback_id, error));
        }
        Ok(())
    }

    /// Enter only at a real full-CPU safe point. The native property frame,
    /// callback ID, copied name and source identity remain installed if setup
    /// fails, so terminal cleanup can retire the exact owner later.
    pub(in crate::win16_runtime) fn service_pending_native_function_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some((
            callback_id,
            procedure,
            arguments,
            entry_pending,
            active,
            failure,
            guest_return,
        )) = self.native_function_callbacks.last().map(|frame| {
            (
                frame.callback_id,
                frame.procedure,
                frame.arguments.clone(),
                frame.entry_pending,
                frame.active_call.is_some(),
                frame.entry_error.as_ref().map(Arc::clone),
                frame.guest_return,
            )
        })
        else {
            return Ok(false);
        };
        if let Some(error) = failure {
            return Err(
                super::callback_lifo::shared_runtime_error(error).with_context(
                    "Win16 native function entry setup remains owned by its exact frame",
                ),
            );
        }
        if !entry_pending || active || guest_return.is_some() {
            return Ok(false);
        }
        if self.require_callback_top(CallbackKind::NativeFunction)? != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "pending native function entry is not the exact shared callback top",
            ));
        }

        let entered = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            &arguments,
            // Each API declares its complete prototype-order argument vector;
            // Pascal placement and callee cleanup remain one checked contract.
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        );
        match entered {
            Ok(active_call) => {
                let frame = self
                    .native_function_callbacks
                    .last_mut()
                    .filter(|frame| {
                        frame.callback_id == callback_id
                            && frame.active_call.is_none()
                            && frame.entry_pending
                    })
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "native function callback owner changed during checked CPU entry",
                        )
                    })?;
                frame.active_call = Some(active_call);
                frame.entry_pending = false;
                Ok(true)
            }
            Err(error) => Err(self.fail_native_function_callback_entry(callback_id, error)),
        }
    }

    fn fail_native_function_callback_entry(
        &mut self,
        callback_id: super::CallbackFrameId,
        error: RuntimeError,
    ) -> RuntimeError {
        let frame = self
            .native_function_callbacks
            .last_mut()
            .expect("native function callback owner retained after setup failure");
        debug_assert_eq!(frame.callback_id, callback_id);
        let kind = error.kind();
        let error = Arc::new(error);
        if frame.entry_error.is_none() {
            frame.entry_error = Some(Arc::clone(&error));
        }
        RuntimeError::with_source(kind, "Win16 native function callback setup failed", error)
    }

    pub(super) fn retain_function_bitmap(
        &mut self,
        dc: crate::Win16HostDc,
        object: crate::Win16HostGdiObject,
    ) -> Result<(), RuntimeError> {
        let frame = self
            .native_function_callbacks
            .iter_mut()
            .rev()
            .find(|frame| frame.borrowed_dc.is_some_and(|(_, native)| native == dc))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "borrowed function bitmap has no live callback DC owner",
                )
            })?;
        if !frame.borrowed_bitmaps.contains(&object) {
            frame.borrowed_bitmaps.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain borrowed function bitmap identity",
                    error,
                )
            })?;
            frame.borrowed_bitmaps.push(object);
        }
        Ok(())
    }

    fn release_native_function_payload(&mut self) -> Result<(), RuntimeError> {
        let bitmaps = std::mem::take(
            &mut self
                .native_function_callbacks
                .last_mut()
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "function bitmap cleanup has no exact callback frame",
                    )
                })?
                .borrowed_bitmaps,
        );
        for bitmap in bitmaps {
            self.guest_gdi.retire_object_aliases(bitmap);
        }

        if let Some((guest, native)) = self
            .native_function_callbacks
            .last()
            .and_then(|frame| frame.borrowed_dc)
        {
            if !self.guest_gdi.forget_dc(guest, native) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native drawing callback lost its exact borrowed guest HDC",
                ));
            }
            self.native_function_callbacks
                .last_mut()
                .expect("frame checked")
                .borrowed_dc = None;
        }
        let (allocation, locked) = {
            let frame = self.native_function_callbacks.last().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 native function callback frame disappeared during cleanup",
                )
            })?;
            (frame.allocation, frame.allocation_locked)
        };
        let Some(allocation) = allocation else {
            return Ok(());
        };
        if locked {
            self.heap
                .unlock(allocation, &mut self.selectors)
                .map_err(crate::runtime_error)?;
            self.native_function_callbacks
                .last_mut()
                .expect("frame checked")
                .allocation_locked = false;
        }
        self.heap
            .free(allocation, &mut self.selectors)
            .map_err(crate::runtime_error)?;
        self.native_function_callbacks
            .last_mut()
            .expect("frame checked")
            .allocation = None;
        Ok(())
    }

    fn allocate_property_name(
        &mut self,
        callback_id: super::CallbackFrameId,
        memory: &mut Memory,
        bytes: &[u8],
    ) -> Result<u32, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PROPERTY_NAME_BYTES || bytes.contains(&0) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native function supplied an invalid string property name",
            ));
        }
        let length = bytes.len() + 1;
        let allocation = self
            .heap
            .alloc(
                memory,
                PROPERTY_CALLBACK_OWNER,
                u32::try_from(length).map_err(|_| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "Win16 native function callback name is too long",
                    )
                })?,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(|error| match error {
                Win16Error::OutOfMemory | Win16Error::HandleTableFull => RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 heap cannot allocate an native function name",
                ),
                other => crate::runtime_error(other),
            })?;
        let frame = self.native_function_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "native function name allocation has no retained callback owner",
            )
        })?;
        if frame.callback_id != callback_id || frame.allocation.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native function name allocation changed its exact callback owner",
            ));
        }
        frame.allocation = Some(allocation);
        let pointer = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Err(crate::runtime_error(error)),
        };
        self.native_function_callbacks
            .last_mut()
            .expect("native function callback owner retained")
            .allocation_locked = true;
        let mut data = bytes.to_vec();
        data.push(0);
        if let Err(error) = self.selectors.write(memory, pointer, &data) {
            return Err(crate::runtime_error(error));
        }
        Ok(pointer.far_value())
    }

    pub(super) fn native_function_code_references(&self) -> Vec<u32> {
        let mut references =
            Vec::with_capacity(self.native_function_callbacks.len().saturating_mul(2));
        for frame in &self.native_function_callbacks {
            if let Some(active_call) = &frame.active_call {
                references.extend(active_call.code_references());
            } else {
                references.push(frame.procedure);
                references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            }
        }
        references
    }

    pub(super) fn close_native_function_callbacks(&mut self) -> Result<(), RuntimeError> {
        if !self.native_function_callbacks.is_empty()
            || self.callback_kinds.contains(&CallbackKind::NativeFunction)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native function callback owner must retire through the shared callback LIFO",
            ));
        }
        Ok(())
    }
}
