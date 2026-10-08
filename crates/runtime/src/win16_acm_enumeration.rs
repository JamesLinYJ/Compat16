//! Resumable Win16 BOOL callbacks for synchronous ACM enumerations.
//!
//! The native adapter snapshots typed driver records during its synchronous
//! enumeration. Runtime then invokes guest FAR PASCAL callbacks one at a time
//! on the emulated CPU and returns the native MMRESULT only after the guest
//! callback returns FALSE or every captured record has been delivered.

use dos_kernel::DosKernel;
use guest_core::{OwnerId, Registers, memory::Memory};
use win16_abi::{Access, AllocationFlags, GlobalHandle, SegmentedPointer, Win16ReturnKind};
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U32};

use super::{CallbackKind, Win16State, acm_invariant, acm_native_result_error,
    combine_acm_failures};
use crate::win16_runtime::global_memory::GlobalTeardownResult;
use super::super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostAcmEnumerationRecord,
    Win16HostAcmItemDetails, Win16HostAcmNativeOperation, Win16HostAcmTagDetails,
    Win16HostAcmObjectKind,
};
use x86_cpu::Cpu;

const DRIVER_RECORD_BYTES: usize = 0;
const TAG_RECORD_BYTES: usize = win16_abi::msacm_abi::ACMFORMATTAGDETAILS16_BYTES;
const ITEM_RECORD_BYTES: usize = win16_abi::msacm_abi::ACMFORMATDETAILS16_BYTES;
const MAX_CALLBACK_ALLOCATION: usize = 0x1_0000;

pub(super) struct AcmEnumerationFrame {
    callback_id: super::super::CallbackFrameId,
    pub(super) saved: Registers,
    pub(super) return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    pub(super) callback: u32,
    instance: u32,
    result: u32,
    records: Vec<Win16HostAcmEnumerationRecord>,
    next_index: usize,
    allocation: Option<GlobalHandle>,
    allocation_locked: bool,
    data: Option<SegmentedPointer>,
    active_call: Option<Win16FarCallbackFrame>,
}

impl Win16State {
    pub(super) fn begin_acm_enumeration(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        callback: u32,
        instance: u32,
        result: u32,
        records: Vec<Win16HostAcmEnumerationRecord>,
    ) -> Result<Option<u8>, RuntimeError> {
        if records.is_empty() {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, result, return_kind);
        }
        let setup = (|| {
            self.acm.reserve_owner_slots(records.len())?;
            self.acm.enumerations.try_reserve(1).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve Win16 ACM enumeration continuation", error))?;
            self.callback_kinds.try_reserve(1).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve Win16 callback nesting entry", error))?;
            records.iter().try_fold(0usize, |largest, record| {
                callback_record_extent(record).map(|extent| largest.max(extent))
            })
        })();
        let allocation_bytes = match setup {
            Ok(bytes) => bytes,
            Err(primary) => return Err(self.preserve_failed_enumeration_records(
                records, host, primary)),
        };
        let callback_id = self.reserve_callback_frame_id()?;
        self.acm.enumerations.push(AcmEnumerationFrame {
            callback_id, saved: cpu.regs.clone(), return_to, return_kind, callback, instance,
            result, records, next_index: 0, allocation: None, allocation_locked: false,
            data: None, active_call: None,
        });
        self.push_callback_kind(CallbackKind::AcmEnumeration, callback_id)?;
        if allocation_bytes > MAX_CALLBACK_ALLOCATION {
            return self.fail_acm_enumeration_start(cpu, dos, memory, host,
                RuntimeError::new(Kind::ResourceExhausted,
                    "MSACM enumeration record exceeds one Win16 selector"),
                Some(super::MMSYSERR_NOMEM));
        }
        if allocation_bytes != 0 {
            match allocate_guest_callback_buffer(self, memory, allocation_bytes) {
                Ok((allocation, data)) => {
                    let frame = self.acm.enumerations.last_mut().ok_or_else(||
                        acm_invariant("MSACM enumeration frame disappeared during allocation"))?;
                    frame.allocation = Some(allocation);
                    frame.allocation_locked = true;
                    frame.data = Some(data);
                }
                Err(error) if error.kind() == Kind::ResourceExhausted => {
                    return self.fail_acm_enumeration_start(cpu, dos, memory, host,
                        error, Some(super::MMSYSERR_NOMEM));
                }
                Err(error) => return self.fail_acm_enumeration_start(
                    cpu, dos, memory, host, error, None),
            }
        }
        if let Err(error) = self.schedule_acm_enumeration_callback(cpu, dos, memory) {
            let guest_result = (error.kind() == Kind::ResourceExhausted)
                .then_some(super::MMSYSERR_NOMEM);
            return self.fail_acm_enumeration_start(
                cpu, dos, memory, host, error, guest_result);
        }
        Ok(None)
    }

    fn fail_acm_enumeration_start(
        &mut self,
        cpu: &mut Cpu,
        _dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        error: RuntimeError,
        guest_result: Option<u32>,
    ) -> Result<Option<u8>, RuntimeError> {
        match self.discard_acm_enumeration(memory, host) {
            Ok(frame) => {
                cpu.regs = frame.saved;
                match guest_result {
                    Some(result) => {
                        let resource_exhaustion = result == super::MMSYSERR_NOMEM
                            && error.kind() == Kind::ResourceExhausted;
                        match self.complete_return(&mut cpu.regs, frame.return_to.0,
                            frame.return_to.1, frame.return_to.2, result, frame.return_kind)
                        {
                            Ok(completion) => {
                                if resource_exhaustion {
                                    report_acm_enumeration_resource_exhaustion(host, error);
                                }
                                Ok(completion)
                            }
                            Err(return_error) => Err(combine_acm_failures(error, return_error,
                                "MSACM enumeration failed and returning its guest result also failed")),
                        }
                    }
                    None => Err(error),
                }
            }
            Err(cleanup) => Err(combine_acm_failures(error, cleanup,
                "MSACM enumeration failed and callback-owner cleanup also failed")),
        }
    }

    fn preserve_failed_enumeration_records(
        &mut self,
        records: Vec<Win16HostAcmEnumerationRecord>,
        host: &mut impl RuntimeHost,
        primary: RuntimeError,
    ) -> RuntimeError {
        match self.release_unowned_enumeration_records(&records, host, None) {
            Ok(()) => primary,
            Err(cleanup) => {
                self.acm.orphaned_enumeration = Some(records);
                combine_acm_failures(primary, cleanup,
                    "MSACM enumeration setup failed and borrowed identities remain owned")
            }
        }
    }

    pub(super) fn retry_orphaned_acm_enumeration(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(records) = self.acm.orphaned_enumeration.take() else { return Ok(()); };
        match self.release_unowned_enumeration_records(&records, host, None) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.acm.orphaned_enumeration = Some(records);
                Err(error)
            }
        }
    }

    fn release_unowned_enumeration_records(
        &self,
        records: &[Win16HostAcmEnumerationRecord],
        host: &mut impl RuntimeHost,
        releasing_frame: Option<usize>,
    ) -> Result<(), RuntimeError> {
        let mut failure = None;
        for record in records {
            let driver_id = enumeration_driver_id(record);
            // A native identity is borrowed by each returned record batch.
            // Retain that exact host token while any other frame or orphan
            // batch still owns a record, even before it publishes a guest alias.
            let retained_by_other_frame = self.acm.enumerations.iter()
                .enumerate()
                .any(|(index, frame)| Some(index) != releasing_frame
                    && frame.records.iter().any(|other|
                        enumeration_driver_id(other) == driver_id));
            let retained_by_orphan = self.acm.orphaned_enumeration.as_ref()
                .is_some_and(|orphaned| orphaned.iter().any(|other|
                    enumeration_driver_id(other) == driver_id));
            if retained_by_other_frame
                || retained_by_orphan
                || self.acm.handles.values().any(|entry| entry.host == driver_id)
            {
                continue;
            }
            let error = match host.win16_acm(
                crate::Win16HostAcmOperation::DriverIdRelease { driver_id })
            {
                Ok(crate::Win16HostAcmResult::Scalar(0))
                | Ok(crate::Win16HostAcmResult::Scalar(super::MMSYSERR_INVALHANDLE)) => None,
                Ok(crate::Win16HostAcmResult::Scalar(result)) => Some(acm_native_result_error(
                    Win16HostAcmNativeOperation::DriverIdRelease, result)),
                Ok(_) => Some(acm_invariant(
                    "ACM enumeration identity release returned the wrong host result")),
                Err(error) => Some(error),
            };
            if let Some(error) = error {
                failure = Some(match failure.take() {
                    None => error,
                    Some(primary) => combine_acm_failures(primary, error,
                        "multiple ACM enumeration identities could not be released"),
                });
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn schedule_acm_enumeration_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self.acm.enumerations.last().ok_or_else(||
            acm_invariant("MSACM enumeration continuation is missing"))?;
        let record = frame.records.get(frame.next_index).ok_or_else(||
            acm_invariant("MSACM enumeration record is missing"))?;
        let record = try_clone_record(record)?;
        let callback = frame.callback;
        let instance = frame.instance;
        let driver_id = match &record {
            Win16HostAcmEnumerationRecord::Driver { driver_id, .. }
            | Win16HostAcmEnumerationRecord::Tag { driver_id, .. }
            | Win16HostAcmEnumerationRecord::Item { driver_id, .. } => *driver_id,
        };
        let mut callback_arguments = Vec::new();
        callback_arguments.try_reserve_exact(4).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve MSACM guest callback arguments", error))?;
        let guest_driver_id = self.acm.store_handle(
            Win16HostAcmObjectKind::DriverId, driver_id)?;
        match record {
            Win16HostAcmEnumerationRecord::Driver { support, .. } => {
                callback_arguments.push(Win16FarCallbackArgument::Word(guest_driver_id));
                callback_arguments.push(Win16FarCallbackArgument::Dword(instance));
                callback_arguments.push(Win16FarCallbackArgument::Dword(support));
            }
            Win16HostAcmEnumerationRecord::Tag { support, details, .. } => {
                let (record_far, nested_far) = self.write_tag_record(memory, details)?;
                callback_arguments.push(Win16FarCallbackArgument::Word(guest_driver_id));
                callback_arguments.push(Win16FarCallbackArgument::GuestPointer {
                    far: record_far, access: Access::Read, bytes: TAG_RECORD_BYTES as u32,
                });
                callback_arguments.push(Win16FarCallbackArgument::Dword(instance));
                callback_arguments.push(Win16FarCallbackArgument::Dword(support));
                let _ = nested_far;
            }
            Win16HostAcmEnumerationRecord::Item { support, details, .. } => {
                let record_far = self.write_item_record(memory, details)?;
                callback_arguments.push(Win16FarCallbackArgument::Word(guest_driver_id));
                callback_arguments.push(Win16FarCallbackArgument::GuestPointer {
                    far: record_far, access: Access::Read,
                    bytes: ITEM_RECORD_BYTES as u32,
                });
                callback_arguments.push(Win16FarCallbackArgument::Dword(instance));
                callback_arguments.push(Win16FarCallbackArgument::Dword(support));
            }
        }
        let saved = self.acm.enumerations.last().ok_or_else(||
            acm_invariant("MSACM enumeration frame disappeared"))?.saved.clone();
        cpu.regs = saved;
        let active_call = self.enter_guest_far_callback_checked(cpu, dos, memory, callback,
            &callback_arguments, Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word)?;
        let frame = self.acm.enumerations.last_mut().ok_or_else(||
            acm_invariant("MSACM enumeration frame disappeared"))?;
        frame.next_index += 1;
        frame.active_call = Some(active_call);
        Ok(())
    }

    fn write_tag_record(
        &mut self, memory: &mut Memory, details: Win16HostAcmTagDetails,
    ) -> Result<(u32, u32), RuntimeError> {
        let data = self.acm.enumerations.last().and_then(|frame| frame.data)
            .ok_or_else(|| acm_invariant("MSACM tag enumeration has no callback buffer"))?;
        let nested_far = data.far_value();
        let wire = win16_abi::msacm_abi::AcmTagDetails16Wire {
            structure_bytes: U32::new(TAG_RECORD_BYTES as u32),
            tag_index: U32::new(details.index),
            tag: U32::new(details.tag),
            format_or_filter_bytes: U32::new(details.data_bytes),
            support: U32::new(details.support),
            standard_count: U32::new(details.standard_count),
            tag_name: details.name,
        };
        self.selectors.write(memory, data, wire.as_bytes())
            .map_err(crate::runtime_error)?;
        Ok((data.far_value(), nested_far))
    }

    fn write_item_record(
        &mut self, memory: &mut Memory, details: Win16HostAcmItemDetails,
    ) -> Result<u32, RuntimeError> {
        let data = self.acm.enumerations.last().and_then(|frame| frame.data)
            .ok_or_else(|| acm_invariant("MSACM item enumeration has no callback buffer"))?;
        let nested = self.selectors.add_bytes(data, ITEM_RECORD_BYTES as u32)
            .map_err(crate::runtime_error)?;
        let nested_far = nested.far_value();
        let nested_length = u32::try_from(details.data.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "MSACM enumeration format data exceeds DWORD", error)
        })?;
        let wire = win16_abi::msacm_abi::AcmItemDetails16Wire {
            structure_bytes: U32::new(ITEM_RECORD_BYTES as u32),
            index: U32::new(details.index),
            tag: U32::new(details.tag),
            support: U32::new(details.support),
            data_far: U32::new(nested_far),
            data_bytes: U32::new(nested_length),
            name: details.name,
        };
        self.selectors.write(memory, data, wire.as_bytes())
            .map_err(crate::runtime_error)?;
        if !details.data.is_empty() {
            self.selectors.write(memory, nested, &details.data)
                .map_err(crate::runtime_error)?;
        }
        Ok(data.far_value())
    }

    pub(in crate::win16_runtime) fn finish_acm_enumeration(
        &mut self, cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::AcmEnumeration)?;
        if self.acm.enumerations.last().is_none_or(|frame| frame.callback_id != callback_id) {
            return Err(acm_invariant(
                "MSACM callback binding differs from its enumeration frame",
            ));
        }
        let mut active = self.acm.enumerations.last_mut()
            .and_then(|frame| frame.active_call.take()).ok_or_else(||
            RuntimeError::new(Kind::GuestFault,
                "Win16 callback gate has no active MSACM enumeration call"))?;
        let keep_going = match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active) {
            Ok(value) => value as u16 != 0,
            Err(error) => {
                self.acm.enumerations.last_mut().expect("frame checked").active_call = Some(active);
                return Err(error);
            }
        };
        if let Err(error) = self.release_guest_far_callback_owner(&mut active, dos, memory) {
            self.acm.enumerations.last_mut().expect("frame checked").active_call = Some(active);
            return Err(error);
        }
        let has_more = self.acm.enumerations.last()
            .is_some_and(|frame| frame.next_index < frame.records.len());
        if keep_going && has_more {
            self.acm.enumerations.last_mut().expect("frame checked").active_call = None;
            if let Err(error) = self.schedule_acm_enumeration_callback(cpu, dos, memory) {
                return self.fail_acm_callback(cpu, memory, host, error);
            }
            return Ok(());
        }
        self.acm.enumerations.last_mut().expect("frame checked").active_call = Some(active);
        let frame = self.acm.enumerations.last().ok_or_else(||
            acm_invariant("MSACM enumeration frame disappeared"))?;
        let (saved, return_to, result, return_kind) = (
            frame.saved.clone(), frame.return_to, frame.result, frame.return_kind,
        );
        cpu.regs = saved;
        self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
            return_to.2, result, return_kind)?;
        self.discard_acm_enumeration(memory, host)?;
        Ok(())
    }

    /// Native ACM enumeration is synchronous: host callbacks copy every row
    /// before returning, and asynchronous ACM callbacks are rejected. There
    /// is no persistent native producer to stop before terminal cleanup.
    pub(in crate::win16_runtime) fn quiesce_acm_callback_owners(
        &mut self,
        _cpu: &mut x86_cpu::Cpu,
        _memory: &mut Memory,
        _host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Cancel only the top ACM callback frame during terminal LIFO unwind.
    /// This does not finish the guest callback or synthesize its return value.
    pub(in crate::win16_runtime) fn cancel_acm_callback_frame(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !matches!(self.callback_kinds.last(), Some(CallbackKind::AcmEnumeration)) {
            return Ok(false);
        }
        if self.acm.enumerations.is_empty() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "top MSACM callback kind has no enumeration frame"));
        }
        let callback_id = self.require_callback_top(CallbackKind::AcmEnumeration)?;
        if self.acm.enumerations.last().is_none_or(|frame| frame.callback_id != callback_id) {
            return Err(acm_invariant(
                "top MSACM callback identity differs from its enumeration frame",
            ));
        }
        if let Some(mut active_call) = self.acm.enumerations.last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended, CallbackKind::AcmEnumeration, callback_id, cpu, dos, memory,
                &mut active_call,
            ) {
                self.acm.enumerations.last_mut().expect("frame checked").active_call = Some(active_call);
                return Err(error);
            }
            self.acm.enumerations.last_mut().expect("frame checked").active_call = Some(active_call);
        }
        self.discard_acm_enumeration(memory, host)?;
        Ok(true)
    }

    fn fail_acm_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        error: RuntimeError,
    ) -> Result<(), RuntimeError> {
        if self.acm.enumerations.last().is_some_and(|frame| frame.active_call.is_some()) {
            return Err(error);
        }
        match self.discard_acm_enumeration(memory, host) {
            Ok(frame) => {
                cpu.regs = frame.saved;
                if error.kind() == Kind::ResourceExhausted {
                    match self.complete_return(&mut cpu.regs, frame.return_to.0,
                        frame.return_to.1, frame.return_to.2,
                        super::MMSYSERR_NOMEM, frame.return_kind)
                    {
                        Ok(_) => {
                            report_acm_enumeration_resource_exhaustion(host, error);
                            Ok(())
                        }
                        Err(return_error) => Err(combine_acm_failures(error, return_error,
                            "MSACM callback failed and returning MMSYSERR_NOMEM also failed")),
                    }
                } else {
                    Err(error)
                }
            }
            Err(cleanup) => Err(combine_acm_failures(error, cleanup,
                "MSACM callback dispatch failed and frame cleanup also failed")),
        }
    }

    fn discard_acm_enumeration(
        &mut self, _memory: &mut Memory, host: &mut impl RuntimeHost,
    ) -> Result<AcmEnumerationFrame, RuntimeError> {
        if self.acm.enumerations.is_empty() {
            return Err(acm_invariant("MSACM enumeration frame disappeared during cleanup"));
        }
        let callback_id = self.require_callback_top(CallbackKind::AcmEnumeration)?;
        if self.acm.enumerations.last().is_none_or(|frame| frame.callback_id != callback_id) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MSACM enumeration callback nesting order is damaged"));
        }
        let index = self.acm.enumerations.len() - 1;
        if let Some(allocation) = self.acm.enumerations[index].allocation {
            if self.acm.enumerations[index].allocation_locked {
                self.heap.unlock(allocation, &mut self.selectors).map_err(crate::runtime_error)?;
                self.acm.enumerations[index].allocation_locked = false;
            }
            match self.free_runtime_global_on_teardown(allocation)? {
                GlobalTeardownResult::Freed => {
                    self.acm.enumerations[index].allocation = None;
                }
                retained @ GlobalTeardownResult::Retained { .. } => {
                    let cause = retained.retained_error("MSACM enumeration buffer")
                        .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "MSACM teardown lost its retained allocation cause"));
                    let mut owner = super::owner::OrphanAcmAllocation::new(allocation);
                    let _ = owner.remember_failure(cause);
                    self.acm.orphan_callback_allocations.push(owner);
                    self.acm.enumerations[index].allocation = None;
                    self.acm.enumerations[index].allocation_locked = false;
                    // The synchronous native enumeration has ended. Retain
                    // only the guest backing owner so aliases can retire
                    // before this exact allocation is retried.
                }
            }
        }
        self.release_unowned_enumeration_records(
            &self.acm.enumerations[index].records, host, Some(index))?;
        let frame = self.acm.enumerations.pop().ok_or_else(||
            acm_invariant("MSACM enumeration frame disappeared during cleanup"))?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::AcmEnumeration, callback_id) {
            self.acm.enumerations.push(frame);
            return Err(error);
        }
        Ok(frame)
    }

}

fn report_acm_enumeration_resource_exhaustion(
    host: &mut impl RuntimeHost,
    error: RuntimeError,
) {
    host.report_diagnostic(&crate::Diagnostic::warning(Kind::ResourceExhausted,
        "MSACM enumeration returned MMSYSERR_NOMEM after resource exhaustion")
        .with_cause(error));
}

fn enumeration_driver_id(
    record: &Win16HostAcmEnumerationRecord,
) -> crate::Win16HostAcmHandle {
    match record {
        Win16HostAcmEnumerationRecord::Driver { driver_id, .. }
        | Win16HostAcmEnumerationRecord::Tag { driver_id, .. }
        | Win16HostAcmEnumerationRecord::Item { driver_id, .. } => *driver_id,
    }
}

fn callback_record_extent(
    record: &Win16HostAcmEnumerationRecord,
) -> Result<usize, RuntimeError> {
    match record {
        Win16HostAcmEnumerationRecord::Driver { .. } => Ok(DRIVER_RECORD_BYTES),
        Win16HostAcmEnumerationRecord::Tag { .. } => Ok(TAG_RECORD_BYTES),
        Win16HostAcmEnumerationRecord::Item { details, .. } => ITEM_RECORD_BYTES
            .checked_add(details.data.len()).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted, "MSACM callback record extent overflow")),
    }
}

fn try_clone_record(
    record: &Win16HostAcmEnumerationRecord,
) -> Result<Win16HostAcmEnumerationRecord, RuntimeError> {
    match record {
        Win16HostAcmEnumerationRecord::Driver { driver_id, support } =>
            Ok(Win16HostAcmEnumerationRecord::Driver {
                driver_id: *driver_id, support: *support,
            }),
        Win16HostAcmEnumerationRecord::Tag { driver_id, support, details } =>
            Ok(Win16HostAcmEnumerationRecord::Tag {
                driver_id: *driver_id,
                support: *support,
                details: Win16HostAcmTagDetails {
                    index: details.index, tag: details.tag, data_bytes: details.data_bytes,
                    support: details.support, standard_count: details.standard_count,
                    name: details.name,
                },
            }),
        Win16HostAcmEnumerationRecord::Item { driver_id, support, details } =>
            Ok(Win16HostAcmEnumerationRecord::Item {
                driver_id: *driver_id,
                support: *support,
                details: Win16HostAcmItemDetails {
                    index: details.index, tag: details.tag, support: details.support,
                    name: details.name, data: super::acm_copy(&details.data)?,
                },
            }),
    }
}

fn allocate_guest_callback_buffer(
    state: &mut Win16State,
    memory: &mut Memory,
    length: usize,
) -> Result<(GlobalHandle, SegmentedPointer), RuntimeError> {
    let active_buffers = state.acm.enumerations.iter()
        .filter(|frame| frame.allocation.is_some()).count();
    let target_capacity = state.acm.orphan_callback_allocations.len()
        .checked_add(active_buffers).and_then(|count| count.checked_add(1))
        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
            "MSACM retained callback-buffer capacity overflowed"))?;
    let additional = target_capacity.saturating_sub(state.acm.orphan_callback_allocations.len());
    state.acm.orphan_callback_allocations.try_reserve(additional).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "reserve retained callback allocation owner before GlobalAlloc", error))?;
    let bytes = u32::try_from(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "MSACM callback record exceeds DWORD", error))?;
    let allocation = state.heap.alloc(memory, OwnerId(1), bytes,
        AllocationFlags::fixed().with_zero_init()).map_err(crate::runtime_error)?;
    match state.heap.lock(allocation, &mut state.selectors, memory) {
        Ok(pointer) => Ok((allocation, pointer)),
        Err(error) => {
            let primary = crate::runtime_error(error);
            match state.free_runtime_global_on_teardown(allocation) {
                Ok(GlobalTeardownResult::Freed) => Err(primary),
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    let cleanup = retained.retained_error("MSACM callback buffer")
                        .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "MSACM teardown lost its retained allocation cause"));
                    let mut owner = super::owner::OrphanAcmAllocation::new(allocation);
                    let cleanup = owner.remember_failure(cleanup);
                    state.acm.orphan_callback_allocations.push(owner);
                    Err(combine_acm_failures(primary, cleanup,
                        "MSACM callback allocation lock and immediate free both failed"))
                }
                Err(cleanup) => {
                    let mut owner = super::owner::OrphanAcmAllocation::new(allocation);
                    let cleanup = owner.remember_failure(cleanup);
                    state.acm.orphan_callback_allocations.push(owner);
                    Err(combine_acm_failures(primary, cleanup,
                        "MSACM callback allocation lock and immediate free both failed"))
                }
            }
        }
    }
}
