//! Transfer accepted DDE callbacks at the real CPU and DOS service boundary.

use super::*;
use dos_kernel::DosKernel;
use x86_cpu::Cpu;

impl Win16State {
    pub(in crate::win16_runtime) fn service_pending_window_dde_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_dispatch_allowed: bool,
    ) -> Result<bool, RuntimeError> {
        if !guest_dispatch_allowed {
            return Ok(false);
        }
        let Some((frame_id, origin, source)) = self.window_operations.last()
            .and_then(|frame| frame.pending_dde_callback.as_ref()
                .map(|(origin, source)| (frame.id, *origin, Arc::clone(source))))
        else {
            return Ok(false);
        };
        // Keep the native carrier until this read-only reconciliation succeeds
        // on this entry attempt. A failed query cannot authorize later entry.
        self.refresh_pending_window_parents(host)?;
        // Failure leaves the same Arc on the operation frame. The DDE entry
        // provider retains its own partial frame and forbids duplicate entry.
        let next = self.begin_dde_callback(Arc::clone(&source), origin,
            cpu, dos, memory, host)?;
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "accepted DDE callback lost its exact window operation owner"))?;
        if !frame.pending_dde_callback.as_ref().is_some_and(|(cached_origin, cached)|
            *cached_origin == origin && Arc::ptr_eq(cached, &source))
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "accepted DDE callback carrier changed before ownership transfer"));
        }
        // Success means the real entered DDE frame owns this carrier, or its
        // fallback reply has completed exact native ACK and retirement.
        frame.pending_dde_callback = None;
        if let Some((origin, step)) = next {
            self.route_dde_callback_step(cpu, dos, memory, host, origin, step)?;
        }
        Ok(true)
    }
}
