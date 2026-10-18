//! Registered DOS, BIOS and XMS firmware services.

use crate::{Runtime, RuntimeError, DiagnosticKind as Kind, RuntimeHost, runtime_error};
use crate::interrupts::{store_service_return_flags, validate_service_frame};
use crate::multiplex::{self, MultiplexOutcome};
use crate::trace::{GuestMemoryWriteObserver, GuestWriteBoundary};
use devices::DeviceAction;
use dos_kernel::DosAction;
use guest_core::{real_address, GuestMemory, OwnerId};
use xms::{MoveRequest, PreparedXmsCall, XmsError};

impl Runtime {
    pub(crate) fn call_interrupt_service(&mut self, number: u8, host: &mut impl RuntimeHost) -> Result<DosAction, RuntimeError> {
        validate_service_frame(&self.memory.bus(), &self.cpu.regs)?;
        let dos_service_before = (number == 0x21).then(|| (self.instructions, self.cpu.regs.clone()));
        // An installed INT 33h vector may point at an IRET even when no mouse
        // driver is connected. Preserve that empty-chain behavior for all
        // requests; the device model alone does not constitute a host driver.
        if number == 0x33 && !self.devices.mouse.present() {
            return Ok(DosAction::Continue);
        }
        let request = (self.cpu.regs.ax(), self.cpu.regs.bx(), self.cpu.regs.cx(), self.cpu.regs.dx());
        let action = if number == 0x2a {
            match crate::network::int2a(&mut self.cpu.regs) {
                DosAction::Unhandled => return Ok(DosAction::Continue),
                action => action,
            }
        } else if number == 0x2f {
            let outcome = if self.dos.message_address_service(&mut self.cpu.regs) {
                MultiplexOutcome::Handled
            } else { multiplex::dispatch(&mut self.cpu.regs) };
            match outcome {
                MultiplexOutcome::Handled => DosAction::Continue,
                // No installed provider claimed this multiplex request. Leave
                // its registers and saved FLAGS intact; the guest's IRET is
                // the end of the chain, not a BIOS service call.
                MultiplexOutcome::Unclaimed => return Ok(DosAction::Continue),
                MultiplexOutcome::MissingDosService => {
                    return Err(service_context(RuntimeError::new(
                        Kind::CompatibilityGap, "DOS internal multiplex service is not implemented",
                    ), number, request));
                }
            }
        } else {
            let writer = self.cpu.regs.clone();
            let mut memory = GuestMemoryWriteObserver::new(
                self.memory.bus(), self.memory_write_watch.as_mut(), self.instructions,
                &writer, GuestWriteBoundary::DosInterrupt,
            );
            self.dos.interrupt(number, &mut self.cpu.regs, &mut memory, host)
                .map_err(|error| service_context(runtime_error(error), number, request))?
        };
        let action = match action {
            DosAction::Execute(request) => {
                let (instruction, before) = dos_service_before
                    .as_ref().ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "DOS EXEC action originated outside INT 21h"))?;
                match self.start_child_process(request, host, *instruction, before.clone())? {
                    None => return Ok(DosAction::Continue),
                    Some(code) => {
                        self.dos.complete_exec_failure(&mut self.cpu.regs, code);
                        DosAction::Continue
                    }
                }
            }
            other => other,
        };
        if let DosAction::Exit(_) = &action {
            if let Some((instruction_count, before)) = dos_service_before.as_ref() {
                let after = self.cpu.regs.clone();
                host.observe_dos_service(*instruction_count, before, &after);
            }
            return Ok(action);
        }
        if matches!(&action, DosAction::Unhandled) {
            if number == 0x16 && self.devices.keyboard.is_empty() {
                if let Some(key) = host.try_read_bios_key()? {
                    if !self.devices.push_key(key) {
                        return Err(RuntimeError::new(Kind::InternalInvariant, "empty BIOS keyboard queue rejected input"));
                    }
                }
            }
            loop {
                let writer = self.cpu.regs.clone();
                let mut memory = GuestMemoryWriteObserver::new(
                    self.memory.bus(), self.memory_write_watch.as_mut(), self.instructions,
                    &writer, GuestWriteBoundary::BiosDeviceService,
                );
                let response = self.devices.dispatch_interrupt(number, &mut self.cpu.regs, &mut memory, host.epoch_seconds())
                    .map_err(|error| service_context(runtime_error(error), number, request))?;
                let mut retry = false;
                for action in response.actions {
                    match action {
                        DeviceAction::RenderText(screen) => {
                            host.render_text(&screen)?;
                            self.rendered_video_version = screen.version;
                        }
                        DeviceAction::AwaitKeyboard => {
                            // Guest programs often draw directly into text
                            // memory immediately before a blocking read.
                            self.flush_video(host)?;
                            let key = host.read_bios_key()?;
                            if !self.devices.push_key(key) { return Err(RuntimeError::new(Kind::InternalInvariant, "BIOS keyboard queue rejected requested input")); }
                            retry = true;
                        }
                        DeviceAction::SetHostMousePosition { x, y } => host.set_mouse_position(x, y)?,
                    }
                }
                if !retry { break; }
            }
        }
        // The registered ROM instruction is IRET. Copy status results to its
        // saved FLAGS word while preserving the caller's IF/TF/control bits.
        {
            let writer = self.cpu.regs.clone();
            let mut memory = GuestMemoryWriteObserver::new(
                self.memory.bus(), self.memory_write_watch.as_mut(), self.instructions,
                &writer, GuestWriteBoundary::DosInterrupt,
            );
            store_service_return_flags(&mut memory, &self.cpu.regs)?;
        }
        if let Some((instruction_count, before)) = dos_service_before.as_ref() {
            let after = self.cpu.regs.clone();
            host.observe_dos_service(*instruction_count, before, &after);
        }
        Ok(DosAction::Continue)
    }

    pub(crate) fn call_xms(&mut self) -> Result<(), RuntimeError> {
        let prepared = if self.cpu.regs.ah() == 0x0b {
            let mut descriptor = [0; MoveRequest::BYTE_LEN];
            let address = real_address(self.cpu.regs.ds, self.cpu.regs.si());
            let request = self.memory.bus().read(address, &mut descriptor)
                .map_err(XmsError::Memory)
                .and_then(|()| MoveRequest::decode(&descriptor));
            PreparedXmsCall::Move(request)
        } else {
            PreparedXmsCall::OtherFunction(self.cpu.regs.ah())
        };
        {
            let writer = self.cpu.regs.clone();
            let mut memory = GuestMemoryWriteObserver::new(
                &mut self.memory, self.memory_write_watch.as_mut(), self.instructions,
                &writer, GuestWriteBoundary::XmsService,
            );
            self.xms.handle_prepared_call(
                OwnerId(u32::from(self.dos.psp_segment())), &mut self.cpu.regs, &mut memory, prepared,
            ).map_err(runtime_error)?;
        }
        self.memory.set_a20_enabled(self.xms.a20_state().enabled)?;
        Ok(())
    }

}

fn service_context(error: RuntimeError, number: u8, request: (u16, u16, u16, u16)) -> RuntimeError {
    error.with_context(format!(
        "INT {number:02X}h AX={:04X} BX={:04X} CX={:04X} DX={:04X}",
        request.0, request.1, request.2, request.3,
    ))
}
