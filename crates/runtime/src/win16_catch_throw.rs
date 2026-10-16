//! Reusable Win16 Catch/Throw checkpoints, never host-stack unwinding.
//!
//! CATCHBUF is nine WORDs. Its private encoding is seven saved WORDs followed
//! by a nonreused scope token; this is not Windows' undocumented wire layout.
//! The token grants only a checked same-owner transfer. Copied buffers and
//! repeated Throw remain usable. Only FAR activations are observed: a buffer
//! retained after a NEAR-only function returns cannot be reliably recognized
//! as stale. ToolHelp observer recovery and descriptor growth across a saved
//! checkpoint are not supported when they change canonical backing identity.
//! Same-base descriptor enlargement with identical backing is accepted; this
//! compares endpoints, not an unobserved descriptor mutation history.

use dos_kernel::DosKernel;
use guest_core::memory::{Memory, MemoryDomainSnapshot};
use guest_core::{AtomicMemoryRange, GuestMemory, OwnerId, Selector};
use win16_abi::{Access, DescriptorInfo, SegmentedPointer, SelectorRef};
use x86_cpu::{Cpu, LegacyCheckpointRegisters, LegacyCpuCheckpointStamp, LegacyStackPointerTarget};

use super::{CallbackFrameId, Win16State, selector_ownership::SelectorBackingIdentity};
use crate::{DiagnosticKind as Kind, RuntimeError, runtime_error};

const BUFFER_BYTES: usize = 18;
const MAX_RECORDS: usize = 65_536;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Root {
    raw: u16,
    reference: SelectorRef,
    descriptor: DescriptorInfo,
    backing: SelectorBackingIdentity,
}

#[derive(Eq, PartialEq)]
struct Scope {
    callbacks: Vec<CallbackFrameId>,
    legacy: Vec<u64>,
    interrupts: Vec<u64>,
    windows: Vec<u64>,
    pe32: Vec<crate::pe32_call::Pe32CallNonce>,
}

struct Record {
    token: u32,
    task: OwnerId,
    cpu: LegacyCpuCheckpointStamp,
    domain: MemoryDomainSnapshot,
    roots: [Root; 3], // CS, SS, DS only; ES/FS/GS are volatile.
    scope: Scope,
    far_anchor: Option<u64>,
}

pub(super) struct CatchRecords {
    records: Vec<Record>,
    next_token: u32,
}

impl Default for CatchRecords {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            next_token: 1,
        }
    }
}

fn descriptor_preserves(saved: DescriptorInfo, current: DescriptorInfo) -> bool {
    current.limit >= saved.limit
        && DescriptorInfo {
            limit: saved.limit,
            ..current
        } == saved
}

fn cpu_error(error: x86_cpu::CpuCallResumeError) -> RuntimeError {
    RuntimeError::with_source(Kind::GuestFault, "Win16 Catch/Throw CPU transfer", error)
}

fn fault(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::GuestFault, message)
}

fn collect<T>(values: impl ExactSizeIterator<Item = T>) -> Result<Vec<T>, RuntimeError> {
    let mut result = Vec::new();
    result.try_reserve(values.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 checkpoint scope",
            error,
        )
    })?;
    result.extend(values);
    Ok(result)
}

fn prefix<T: PartialEq>(saved: &[T], current: impl Iterator<Item = T>) -> bool {
    let mut current = current;
    saved
        .iter()
        .all(|value| current.next().as_ref() == Some(value))
}

impl Win16State {
    fn checkpoint_scope(&self) -> Result<Scope, RuntimeError> {
        if !self.toolhelp_interrupt_frames.is_empty()
            || self.toolhelp_interrupt_stopped_event.is_some()
        {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Catch/Throw inside a ToolHelp fault observer requires observer recovery support",
            ));
        }
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(fault("Catch/Throw callback ownership is inconsistent"));
        }
        Ok(Scope {
            callbacks: collect(self.callback_frame_ids.iter().copied())?,
            legacy: collect(self.legacy_cpu_frames.iter().map(|frame| frame.id))?,
            interrupts: collect(self.interrupt_returns.iter().map(|frame| frame.id))?,
            windows: collect(self.window_operations.iter().map(|frame| frame.id))?,
            pe32: collect(self.pe32_dispatch.checkpoint_scope())?,
        })
    }

    fn capture_checkpoint_roots(
        &mut self,
        words: [u16; 3],
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<[Root; 3], RuntimeError> {
        let mut root = |raw| -> Result<Root, RuntimeError> {
            let reference = self
                .selectors
                .reference(Selector(raw))
                .map_err(runtime_error)?;
            let descriptor = self.selectors.describe(reference).map_err(runtime_error)?;
            let backing = self
                .selector_backing_lease(reference, dos, memory)?
                .ok_or_else(|| fault("Catch/Throw selector has no live canonical backing"))?;
            Ok(Root {
                raw,
                reference,
                descriptor,
                backing,
            })
        };
        Ok([root(words[0])?, root(words[1])?, root(words[2])?])
    }

    /// Drop records only when their exact enclosing authority has ended. Nested
    /// callbacks preserve outer records; equal-depth replacements do not.
    pub(super) fn prune_catch_scopes(&mut self) {
        let task = self.tasks.current();
        let callbacks = &self.callback_frame_ids;
        let legacy = &self.legacy_cpu_frames;
        let interrupts = &self.interrupt_returns;
        let windows = &self.window_operations;
        let pe32 = &self.pe32_dispatch;
        let far = &self.far_returns;
        let selectors = &self.selectors;
        self.catch_records.records.retain(|record| {
            task == Some(record.task)
                && prefix(&record.scope.callbacks, callbacks.iter().copied())
                && prefix(&record.scope.legacy, legacy.iter().map(|frame| frame.id))
                && prefix(
                    &record.scope.interrupts,
                    interrupts.iter().map(|frame| frame.id),
                )
                && prefix(&record.scope.windows, windows.iter().map(|frame| frame.id))
                && prefix(&record.scope.pe32, pe32.checkpoint_scope())
                && record
                    .far_anchor
                    .is_none_or(|id| far.iter().any(|entry| entry.id == id))
                && record.roots.iter().all(|root| {
                    selectors
                        .describe(root.reference)
                        .is_ok_and(|value| descriptor_preserves(root.descriptor, value))
                })
        });
    }

    fn prune_checkpoint_roots(
        &mut self,
        stamp: &LegacyCpuCheckpointStamp,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        self.prune_catch_scopes();
        self.catch_records
            .records
            .retain(|record| record.cpu == *stamp && memory.domain_matches(&record.domain));
        for index in (0..self.catch_records.records.len()).rev() {
            let roots = self.catch_records.records[index].roots;
            let mut live = true;
            for root in roots {
                if self.selector_backing_lease(root.reference, dos, memory)? != Some(root.backing) {
                    live = false;
                    break;
                }
            }
            if !live {
                self.catch_records.records.remove(index);
            }
        }
        Ok(())
    }

    fn checkpoint_buffer(&self, raw: u32) -> Result<SegmentedPointer, RuntimeError> {
        self.selectors
            .pointer_from_raw(Selector((raw >> 16) as u16), raw as u16)
            .map_err(runtime_error)
    }

    fn validate_checkpoint_target(
        &self,
        target: &LegacyCheckpointRegisters,
        roots: &[Root; 3],
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        if [target.cs, target.ss, target.ds] != roots.map(|root| root.raw) {
            return Err(fault(
                "Catch/Throw saved selector words do not match their captured roots",
            ));
        }
        if u32::from(target.ip) > roots[0].descriptor.limit {
            return Err(fault("Throw code offset exceeds its captured code extent"));
        }
        self.selectors
            .translate(
                SegmentedPointer::new(roots[0].reference, target.ip),
                Access::Execute,
                1,
                memory,
            )
            .map_err(runtime_error)?;
        let stack_end = if target.stack_pointer == LegacyStackPointerTarget::OnePast16BitSegment {
            0x1_0000
        } else {
            u32::from(target.sp)
        };
        if !roots[1].descriptor.rights.writable()
            || stack_end > roots[1].descriptor.limit.saturating_add(1)
        {
            return Err(fault(
                "Catch/Throw saved stack pointer exceeds its writable stack",
            ));
        }
        // Check the stack byte immediately below the saved top, where the next
        // push writes, without demanding access to unrelated stack contents.
        let offset = stack_end.saturating_sub(1) as u16;
        self.selectors
            .translate(
                SegmentedPointer::new(roots[1].reference, offset),
                Access::Write,
                1,
                memory,
            )
            .map_err(runtime_error)?;
        self.selectors
            .translate(
                SegmentedPointer::new(roots[2].reference, 0),
                Access::Read,
                0,
                memory,
            )
            .map_err(runtime_error)?;
        Ok(())
    }

    pub(super) fn catch_guest(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        raw: u32,
    ) -> Result<(), RuntimeError> {
        // Capture the FAR return before touching a possibly overlapping buffer.
        let (cs, ip, return_sp) = self.far_return(&cpu.regs, memory, 4)?;
        let target = LegacyCheckpointRegisters {
            cs,
            ip,
            ss: cpu.regs.ss,
            sp: return_sp as u16,
            bp: cpu.regs.bp(),
            si: cpu.regs.si(),
            di: cpu.regs.di(),
            ds: cpu.regs.ds,
            stack_pointer: if return_sp == 0x1_0000 {
                LegacyStackPointerTarget::OnePast16BitSegment
            } else {
                LegacyStackPointerTarget::RegisterValue
            },
        };
        let buffer = self.checkpoint_buffer(raw)?;
        let address = self
            .selectors
            .translate(buffer, Access::Write, BUFFER_BYTES, memory)
            .map_err(runtime_error)?;
        let task = self
            .tasks
            .current()
            .ok_or_else(|| fault("Catch has no active Win16 task"))?;
        let stamp = cpu.legacy_checkpoint_stamp().map_err(cpu_error)?;
        let roots =
            self.capture_checkpoint_roots([target.cs, target.ss, target.ds], dos, memory)?;
        self.validate_checkpoint_target(&target, &roots, memory)?;
        let scope = self.checkpoint_scope()?;
        // Exclude only the exact observed FAR frame consumed by this return.
        // A jump to Catch without that frame must not drop an arbitrary anchor.
        let consumed = self.far_returns.last().is_some_and(|frame| {
            frame.selector == cs
                && frame.offset == u32::from(ip)
                && frame.stack == target.ss
                && frame.frame_sp == cpu.regs.sp()
        });
        let keep = self.far_returns.len() - usize::from(consumed);
        let far_anchor = keep.checked_sub(1).map(|index| self.far_returns[index].id);
        self.prune_checkpoint_roots(&stamp, dos, memory)?;
        let existing = self.catch_records.records.iter().find(|record| {
            record.task == task
                && record.cpu == stamp
                && record.roots == roots
                && record.scope == scope
                && record.far_anchor == far_anchor
        });
        let (token, next_token) = if let Some(record) = existing {
            (record.token, None)
        } else {
            if self.catch_records.records.len() == MAX_RECORDS {
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 Catch scope limit reached",
                ));
            }
            let token = self.catch_records.next_token;
            let next = token.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 Catch token identities exhausted",
                )
            })?;
            self.catch_records.records.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 Catch scope",
                    error,
                )
            })?;
            (token, Some(next))
        };
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, target, 0)
            .map_err(cpu_error)?;
        let bytes = encode(target, token);
        // Providers without atomic updates reject this before mutation. A native
        // partial-storage failure remains fatal, with its committed byte count;
        // it never publishes a token or CPU return. No CPU mutation occurs
        // between preparation and commit.
        let mut original = [0; BUFFER_BYTES];
        memory
            .atomic_update(
                &[AtomicMemoryRange {
                    offset: address.0,
                    length: BUFFER_BYTES,
                }],
                &mut original,
                &mut |value| value.copy_from_slice(&bytes),
            )
            .map_err(runtime_error)?;
        cpu.commit_legacy_checkpoint_return(prepared)
            .map_err(cpu_error)?;
        if let Some(next) = next_token {
            self.catch_records.next_token = next;
            self.catch_records.records.push(Record {
                token,
                task,
                cpu: stamp,
                domain: memory.domain_snapshot(),
                roots,
                scope,
                far_anchor,
            });
        }
        self.far_returns.truncate(keep);
        self.prune_catch_scopes();
        Ok(())
    }

    pub(super) fn throw_guest(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        raw: u32,
        value: u16,
    ) -> Result<(), RuntimeError> {
        let buffer = self.checkpoint_buffer(raw)?;
        let mut bytes = [0; BUFFER_BYTES];
        self.selectors
            .read(memory, buffer, &mut bytes)
            .map_err(runtime_error)?;
        let token = u32::from_le_bytes(bytes[14..18].try_into().expect("four token bytes"));
        let scope = self.checkpoint_scope()?;
        self.prune_catch_scopes();
        let record = self
            .catch_records
            .records
            .iter()
            .find(|record| record.token == token)
            .ok_or_else(|| fault("Throw names an expired or unknown Catch scope"))?;
        if self.tasks.current() != Some(record.task)
            || record.scope != scope
            || !memory.domain_matches(&record.domain)
        {
            return Err(fault(
                "Throw would cross a Win16 message or execution owner boundary",
            ));
        }
        let keep = match record.far_anchor {
            Some(id) => self
                .far_returns
                .iter()
                .position(|entry| entry.id == id)
                .map(|index| index + 1)
                .ok_or_else(|| fault("Throw FAR activation has ended"))?,
            None => 0,
        };
        let roots = record.roots;
        let stamp = record.cpu.clone();
        let target = decode(&bytes, roots[1].raw, roots[1].descriptor.limit);
        let current =
            self.capture_checkpoint_roots([target.cs, target.ss, target.ds], dos, memory)?;
        if !roots.iter().zip(current).all(|(saved, current)| {
            saved.raw == current.raw
                && saved.reference == current.reference
                && saved.backing == current.backing
                && descriptor_preserves(saved.descriptor, current.descriptor)
        }) {
            return Err(fault("Throw selector or backing identity changed"));
        }
        self.validate_checkpoint_target(&target, &roots, memory)?;
        let prepared = cpu
            .prepare_legacy_checkpoint_transfer(&stamp, target, value)
            .map_err(cpu_error)?;
        cpu.commit_legacy_checkpoint_transfer(prepared)
            .map_err(cpu_error)?;
        // Only guest FAR observations are abandoned. All host callback, legacy,
        // interrupt and native operation owners remain untouched.
        self.far_returns.truncate(keep);
        self.prune_catch_scopes();
        Ok(())
    }
}

fn encode(target: LegacyCheckpointRegisters, token: u32) -> [u8; BUFFER_BYTES] {
    let mut bytes = [0; BUFFER_BYTES];
    for (slot, value) in [
        target.ip, target.cs, target.sp, target.bp, target.si, target.di, target.ds,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[slot * 2..slot * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[14..18].copy_from_slice(&token.to_le_bytes());
    bytes
}

fn decode(bytes: &[u8; BUFFER_BYTES], ss: u16, stack_limit: u32) -> LegacyCheckpointRegisters {
    let word = |index: usize| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    let sp = word(2);
    LegacyCheckpointRegisters {
        ip: word(0),
        cs: word(1),
        sp,
        bp: word(3),
        si: word(4),
        di: word(5),
        ds: word(6),
        ss,
        stack_pointer: if sp == 0 && stack_limit == 0xffff {
            LegacyStackPointerTarget::OnePast16BitSegment
        } else {
            LegacyStackPointerTarget::RegisterValue
        },
    }
}

#[cfg(test)]
#[path = "win16_catch_throw_tests.rs"]
mod tests;
