//! Complete CPU-context ownership for DDE safe-point and terminal callbacks.

use guest_core::memory::Memory;

use super::{DdeGuestExecutionContext, Win16State, execute};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(in crate::win16_runtime) fn capture_dde_guest_context(
        &mut self,
        cpu: &x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        frame: crate::Win16HostDdeCallbackFrame,
    ) -> Result<(), RuntimeError> {
        if self
            .dde_guest_contexts
            .iter()
            .any(|entry| entry.frame == frame)
            || self
                .dde_context_restores
                .iter()
                .any(|entry| entry.frame == frame)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE safe-point callback frame already owns a saved CPU context",
            ));
        }
        self.dde_guest_contexts.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain interrupted CPU context for a DDE callback",
                error,
            )
        })?;
        let cpu_owner = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
        self.dde_guest_contexts.push(DdeGuestExecutionContext {
            frame,
            cpu_owner,
        });
        Ok(())
    }

    pub(in crate::win16_runtime) fn preflight_dde_guest_context(
        &self,
        cpu: &x86_cpu::Cpu,
        frame: crate::Win16HostDdeCallbackFrame,
    ) -> Result<(), RuntimeError> {
        let mut saved = self
            .dde_guest_contexts
            .iter()
            .filter(|entry| entry.frame == frame);
        let context = saved.next().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE guest callback has no retained CPU context to preflight",
            )
        })?;
        if saved.next().is_some()
            || self
                .dde_context_restores
                .iter()
                .any(|entry| entry.frame == frame)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE guest callback CPU context is present in multiple continuation states",
            ));
        }
        self.preflight_legacy_cpu_frame(context.cpu_owner, cpu)
    }

    pub(in crate::win16_runtime) fn queue_dde_guest_context_restore(
        &mut self,
        frame: crate::Win16HostDdeCallbackFrame,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self
            .dde_guest_contexts
            .iter()
            .position(|entry| entry.frame == frame)
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "acknowledged DDE callback has no saved guest CPU context",
            ));
        };
        if self
            .dde_context_restores
            .iter()
            .any(|entry| entry.frame == frame)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback CPU context was queued more than once",
            ));
        }
        self.dde_context_restores.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "queue restored CPU context after a DDE callback",
                error,
            )
        })?;
        let saved = self.dde_guest_contexts.remove(index);
        self.dde_context_restores.push(saved);
        Ok(())
    }

    pub(super) fn restore_next_dde_context(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(saved) = self.dde_context_restores.last() else {
            return Ok(false);
        };
        let frame = saved.frame;
        let owner = saved.cpu_owner;
        self.restore_legacy_cpu_parked_frame(owner, cpu, dos, memory)?;
        self.release_legacy_cpu_frame(owner, dos, memory)?;
        if self.dde_context_restores.last().is_none_or(|entry| entry.frame != frame) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE CPU restore frame changed before exact owner pop"));
        }
        self.dde_context_restores.pop();
        Ok(true)
    }

    fn retained_dde_guest_context_owner(
        &self,
        frame: crate::Win16HostDdeCallbackFrame,
    ) -> Result<u64, RuntimeError> {
        let mut matches = self.dde_guest_contexts.iter()
            .chain(self.dde_context_restores.iter())
            .filter(|saved| saved.frame == frame);
        let saved = matches.next().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "terminal DDE callback has no retained guest CPU owner",
        ))?;
        if matches.next().is_some() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal DDE callback has multiple retained guest CPU owners"));
        }
        Ok(saved.cpu_owner)
    }

    /// Normal DDE source acknowledgement can precede a failed parked restore
    /// or partial owner release. Its family frame has already retired, so the
    /// terminal scheduler consumes this separate queued owner before its parent.
    pub(super) fn retire_acknowledged_dde_context_after_task_execution_ended(
        &mut self,
        ended: &execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(saved) = self.dde_context_restores.last() else {
            return Ok(false);
        };
        let frame = saved.frame;
        let owner = self.retained_dde_guest_context_owner(frame)?;
        if !self.legacy_cpu_frame_is_top(owner) {
            return Ok(false);
        }
        self.restore_legacy_cpu_frame_after_task_execution_ended(ended, owner, cpu, memory)?;
        self.release_dde_guest_context_after_task_execution_ended(ended, frame, dos, memory)?;
        Ok(true)
    }

    /// Terminal cancellation restores the complete architecture state while
    /// keeping selector roots alive until the native callback is acknowledged.
    pub(in crate::win16_runtime) fn restore_dde_guest_context_after_task_execution_ended(
        &mut self,
        ended: &execute::Win16TaskExecutionEnded,
        frame: crate::Win16HostDdeCallbackFrame,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let owner = self.retained_dde_guest_context_owner(frame)?;
        self.restore_legacy_cpu_frame_after_task_execution_ended(ended, owner, cpu, memory)
    }

    /// A failed release keeps both the exact CPU frame and its DDE identity
    /// available for retry; the acknowledgement is owned by the DDE caller.
    pub(in crate::win16_runtime) fn release_dde_guest_context_after_task_execution_ended(
        &mut self,
        ended: &execute::Win16TaskExecutionEnded,
        frame: crate::Win16HostDdeCallbackFrame,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let owner = self.retained_dde_guest_context_owner(frame)?;
        self.release_legacy_cpu_frame_after_task_execution_ended(ended, owner, dos, memory)?;
        self.dde_guest_contexts.retain(|saved| saved.frame != frame);
        self.dde_context_restores.retain(|saved| saved.frame != frame);
        Ok(())
    }

    /// Clear full interrupted CPU contexts only after the private close path
    /// has confirmed host abort and retired all DDE guest allocations.
    pub(in crate::win16_runtime) fn close_dde_runtime(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.dde_runtime_quiesced {
            return Ok(());
        }
        self.close_dde(memory, host)?;
        self.dde_guest_contexts.clear();
        self.dde_context_restores.clear();
        self.dde_runtime_quiesced = true;
        Ok(())
    }

}
