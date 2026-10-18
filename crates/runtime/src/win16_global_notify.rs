//! Task-owned GlobalNotify and resumable global-heap discard decisions.

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::global_memory::GlobalMemoryCaller;
use super::{CallbackFrameId, CallbackKind, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};
use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers, memory::Memory};
use std::collections::BTreeMap;
use win16_abi::global::{
    GMEM_MODIFY, GMEM_MOVEABLE, GMEM_NOCOMPACT, GMEM_NODISCARD, GlobalCompactStep,
};
use win16_abi::{Access, GlobalHandle, SegmentedPointer, SelectorRef, Win16Error, Win16ReturnKind};
use x86_cpu::Cpu;

#[path = "win16_global_notify_callback.rs"]
mod callback;

#[derive(Default)]
pub(super) struct GlobalNotifyState {
    registrations: BTreeMap<OwnerId, SegmentedPointer>,
    frames: Vec<Frame>,
}

#[derive(Clone, Copy)]
pub(super) enum GlobalHeapOperation {
    Compact {
        minimum_free: u32,
    },
    Allocate {
        flags: u16,
        size: u32,
        caller: u16,
    },
    Reallocate {
        handle: u16,
        identity: Option<GlobalHandle>,
        size: u32,
        flags: u16,
        caller: u16,
    },
}

struct Frame {
    id: CallbackFrameId,
    owner: OwnerId,
    saved: Registers,
    return_to: (u16, u16, u32),
    operation: GlobalHeapOperation,
    skipped: Vec<GlobalHandle>,
    candidate: Option<(u16, GlobalHandle)>,
    call: Option<Win16FarCallbackFrame>,
    caller: Option<u64>,
    parked: Option<u64>,
    minimum_free: u32,
    remaining_paragraphs: u16,
    reported_enough: bool,
    budget_initialized: bool,
    completed: Option<u32>,
    returned: bool,
    terminal: bool,
}

impl GlobalNotifyState {
    pub(super) fn code_references(&self) -> impl Iterator<Item = u32> + '_ {
        self.registrations
            .values()
            .map(|pointer| pointer.far_value())
            .chain(self.frames.iter().flat_map(|frame| {
                [
                    (u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()),
                    (u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1),
                ]
                .into_iter()
                .chain(frame.call.iter().flat_map(|call| call.code_references()))
            }))
    }

    pub(super) fn has_active_frames(&self) -> bool {
        !self.frames.is_empty()
    }

    pub(super) fn update_selector(&mut self, old: SelectorRef, new: SelectorRef) {
        for pointer in self.registrations.values_mut() {
            if pointer.selector() == old {
                *pointer = SegmentedPointer::new(new, pointer.offset());
            }
        }
    }

    pub(super) fn retire_task(&mut self, owner: OwnerId) -> Result<(), RuntimeError> {
        if self.frames.iter().any(|frame| frame.owner == owner) {
            return Err(invariant(
                "GlobalNotify task retirement still has a heap continuation",
            ));
        }
        self.registrations.remove(&owner);
        Ok(())
    }
}

impl Win16State {
    pub(super) fn kernel_global_notify(
        &mut self,
        procedure: u32,
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        let owner = self.current_task_owner()?;
        if procedure == 0 {
            self.global_notify.registrations.remove(&owner);
        } else {
            let pointer = self
                .selectors
                .pointer_from_far(procedure)
                .map_err(crate::runtime_error)?;
            self.selectors
                .translate(pointer, Access::Execute, 1, memory)
                .map_err(crate::runtime_error)?;
            self.global_notify.registrations.insert(owner, pointer);
        }
        self.module_reap_pending = true;
        // The catalog's Void contract preserves AX/DX; this is no success BOOL.
        Ok(0)
    }

    pub(super) fn kernel_memory_freed(&mut self, paragraphs: u16) -> u32 {
        let Some(frame) = self
            .global_notify
            .frames
            .last_mut()
            .filter(|frame| frame.call.is_some())
        else {
            return 0;
        };
        if paragraphs != 0 {
            frame.reported_enough |= paragraphs >= frame.remaining_paragraphs;
            // KERNEL's WORD arithmetic wraps after an over-report; DX is zero.
            frame.remaining_paragraphs = frame.remaining_paragraphs.wrapping_sub(paragraphs);
        }
        u32::from(frame.remaining_paragraphs)
    }

    pub(super) fn begin_global_heap_operation(
        &mut self,
        operation: GlobalHeapOperation,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let owner = self.current_task_owner()?;
        let pending_discard = match operation {
            GlobalHeapOperation::Reallocate {
                handle,
                identity: Some(identity),
                size: 0,
                flags,
                ..
            } if flags & (GMEM_MODIFY | GMEM_MOVEABLE) == GMEM_MOVEABLE => self
                .global_discard_callback(identity, memory)?
                .map(|procedure| (handle, identity, procedure)),
            _ => None,
        };
        // Ordinary successful memory calls must not acquire temporary CPU
        // alias pins: GlobalReAlloc can legitimately resize a caller's DS.
        if let GlobalHeapOperation::Compact { minimum_free } = operation {
            if self.global_notify.registrations.is_empty()
                || self
                    .heap
                    .maximum_available()
                    .map_err(crate::runtime_error)?
                    >= minimum_free
            {
                let value = self.kernel_global_compact(minimum_free, memory)?;
                return self.return_immediate_global_heap(operation, value, cpu, return_to);
            }
        } else if pending_discard.is_none() {
            let value = self.try_global_heap_operation(operation, memory, host)?;
            let (size, flags, invalid) = match operation {
                GlobalHeapOperation::Allocate { size, flags, .. } => (size, flags, false),
                GlobalHeapOperation::Reallocate {
                    size,
                    flags,
                    identity,
                    ..
                } => (size, flags, identity.is_none()),
                GlobalHeapOperation::Compact { .. } => unreachable!(),
            };
            if value != 0
                || size == 0
                || invalid
                || flags & GMEM_MODIFY != 0
                || self
                    .heap
                    .maximum_available()
                    .map_err(crate::runtime_error)?
                    >= size
                || flags & (GMEM_NOCOMPACT | GMEM_NODISCARD) == (GMEM_NOCOMPACT | GMEM_NODISCARD)
            {
                return self.return_immediate_global_heap(operation, value, cpu, return_to);
            }
        }
        let id = self.reserve_callback_frame_id()?;
        self.global_notify.frames.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain global-heap continuation",
                error,
            )
        })?;
        self.push_callback_kind(CallbackKind::GlobalNotify, id)?;
        self.global_notify.frames.push(Frame {
            id,
            owner,
            saved: cpu.regs.clone(),
            return_to,
            operation,
            skipped: Vec::new(),
            candidate: None,
            call: None,
            caller: None,
            parked: None,
            minimum_free: 0,
            remaining_paragraphs: 0,
            reported_enough: false,
            budget_initialized: false,
            completed: None,
            returned: false,
            terminal: false,
        });
        let caller = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
        self.global_notify
            .frames
            .last_mut()
            .expect("published heap owner")
            .caller = Some(caller);
        let parked = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
        self.global_notify
            .frames
            .last_mut()
            .expect("published heap owner")
            .parked = Some(parked);
        if let Some((handle, identity, procedure)) = pending_discard {
            self.global_notify
                .frames
                .last_mut()
                .expect("heap owner")
                .candidate = Some((handle, identity));
            self.enter_global_notify(procedure, handle, cpu, dos, memory)?;
            return Ok(None);
        }
        let minimum = match operation {
            GlobalHeapOperation::Compact { minimum_free } => minimum_free,
            GlobalHeapOperation::Allocate { size, .. } => size,
            GlobalHeapOperation::Reallocate { size, identity, .. } => {
                if let Some(identity) = identity {
                    self.skip_global_discard(identity)?;
                }
                size
            }
        };
        self.start_global_heap_compaction(minimum)?;
        self.drive_global_heap_operation(cpu, dos, memory, host)?;
        Ok(None)
    }

    fn return_immediate_global_heap(
        &mut self,
        operation: GlobalHeapOperation,
        value: u32,
        cpu: &mut Cpu,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let kind = match operation {
            GlobalHeapOperation::Compact { .. } => Win16ReturnKind::Dword,
            GlobalHeapOperation::Allocate { .. } => {
                cpu.regs.eax = value;
                cpu.regs.ebx = value;
                cpu.regs.ecx = value;
                cpu.regs.es = 0;
                Win16ReturnKind::Word
            }
            GlobalHeapOperation::Reallocate { .. } => {
                super::dispatch_kernel::finish_global_heap_call(&mut cpu.regs);
                Win16ReturnKind::Word
            }
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            value,
            kind,
        )
    }

    fn start_global_heap_compaction(&mut self, minimum: u32) -> Result<(), RuntimeError> {
        let largest = self
            .heap
            .maximum_available()
            .map_err(crate::runtime_error)?;
        let frame = self
            .global_notify
            .frames
            .last_mut()
            .ok_or_else(|| invariant("missing heap owner"))?;
        frame.minimum_free = minimum;
        frame.remaining_paragraphs = minimum.saturating_sub(largest).div_ceil(16) as u16;
        frame.budget_initialized = false;
        Ok(())
    }

    fn skip_global_discard(&mut self, identity: GlobalHandle) -> Result<(), RuntimeError> {
        let frame = self
            .global_notify
            .frames
            .last_mut()
            .ok_or_else(|| invariant("missing heap owner"))?;
        frame.skipped.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain global discard decisions",
                error,
            )
        })?;
        frame.skipped.push(identity);
        Ok(())
    }

    fn global_discard_callback(
        &self,
        identity: GlobalHandle,
        memory: &Memory,
    ) -> Result<Option<SegmentedPointer>, RuntimeError> {
        let Ok(info) = self.heap.info(identity) else {
            return Ok(None);
        };
        if !info.notify_on_discard
            || !info.discardable
            || !info.movable
            || info.discarded
            || info.lock_count != 0
            || info.page_lock_count != 0
            || info.owner != self.current_task_owner()?
            || info.guest_owner.map(|owner| owner.raw()) != Some(self.current_task_handle()?)
        {
            return Ok(None);
        }
        let Some(&procedure) = self.global_notify.registrations.get(&info.owner) else {
            return Ok(None);
        };
        self.selectors
            .translate(procedure, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        Ok(Some(procedure))
    }

    fn try_global_heap_operation(
        &mut self,
        operation: GlobalHeapOperation,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match operation {
            GlobalHeapOperation::Compact { .. } => {
                self.heap.maximum_available().map_err(crate::runtime_error)
            }
            GlobalHeapOperation::Allocate {
                flags,
                size,
                caller,
            } => self
                .global_alloc_with_caller(flags, size, caller, memory, host)
                .map(u32::from),
            GlobalHeapOperation::Reallocate {
                handle,
                identity,
                size,
                flags,
                caller,
            } => {
                if identity.is_none() || self.global_handles.get(&handle).copied() != identity {
                    return Ok(0);
                }
                self.kernel_global_realloc_with_caller(
                    handle,
                    size,
                    flags,
                    Some(GlobalMemoryCaller::GuestCode(caller)),
                    memory,
                    host,
                )
                .map(u32::from)
            }
        }
    }

    fn drive_global_heap_operation(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        loop {
            let frame = self
                .global_notify
                .frames
                .last()
                .ok_or_else(|| invariant("missing heap owner"))?;
            if frame.terminal || frame.owner != self.current_task_owner()? {
                return Err(invariant("heap owner is not executable"));
            }
            if frame.completed.is_some() {
                return self.return_global_heap_operation(cpu, dos, memory);
            }
            if frame.call.is_some() {
                return Ok(());
            }
            let operation = frame.operation;
            let flags = match operation {
                GlobalHeapOperation::Allocate { flags, .. }
                | GlobalHeapOperation::Reallocate { flags, .. } => flags,
                GlobalHeapOperation::Compact { .. } => 0,
            };
            let mut updates = Vec::new();
            let step = self.heap.compact_step(
                frame.minimum_free,
                &frame.skipped,
                flags & GMEM_NOCOMPACT == 0,
                flags & GMEM_NODISCARD == 0 && !frame.reported_enough,
                memory,
                &mut self.selectors,
                &mut updates,
            );
            self.apply_selector_updates(&updates);
            self.sync_discarded_global_handles();
            match step {
                Ok(GlobalCompactStep::Complete(_))
                | Err(Win16Error::OutOfMemory | Win16Error::SelectorTableFull) => {
                    let value = self.try_global_heap_operation(operation, memory, host)?;
                    self.global_notify
                        .frames
                        .last_mut()
                        .expect("heap owner")
                        .completed = Some(value);
                }
                Ok(GlobalCompactStep::DiscardCandidate(identity)) => {
                    let largest = self
                        .heap
                        .maximum_available()
                        .map_err(crate::runtime_error)?;
                    let frame = self.global_notify.frames.last_mut().expect("heap owner");
                    if !frame.budget_initialized {
                        frame.remaining_paragraphs =
                            frame.minimum_free.saturating_sub(largest).div_ceil(16) as u16;
                        frame.budget_initialized = true;
                    }
                    self.skip_global_discard(identity)?;
                    if let Some(procedure) = self.global_discard_callback(identity, memory)? {
                        let Some(handle) = self
                            .global_handles
                            .iter()
                            .find_map(|(&handle, &value)| (value == identity).then_some(handle))
                        else {
                            return Err(invariant(
                                "notifiable heap allocation has no guest HGLOBAL",
                            ));
                        };
                        self.global_notify
                            .frames
                            .last_mut()
                            .expect("heap owner")
                            .candidate = Some((handle, identity));
                        self.enter_global_notify(procedure, handle, cpu, dos, memory)?;
                        return Ok(());
                    }
                    self.commit_global_discard(identity)?;
                }
                Err(error) => {
                    return Err(
                        crate::runtime_error(error).with_context("Win16 global-heap compaction")
                    );
                }
            }
        }
    }

    fn commit_global_discard(&mut self, identity: GlobalHandle) -> Result<(), RuntimeError> {
        let updates = match self.heap.discard(identity, &mut self.selectors) {
            Ok(updates) => updates,
            Err(
                Win16Error::InvalidHandle
                | Win16Error::Locked
                | Win16Error::SelectorBlockInterior
                | Win16Error::OutOfMemory,
            ) => return Ok(()),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        self.apply_selector_updates(&updates);
        self.sync_discarded_global_handles();
        Ok(())
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[cfg(test)]
#[path = "win16_global_notify_tests.rs"]
mod tests;
