//! Instruction scheduling and transitions into guest interrupt handlers.

use crate::clock::DeviceClock;
use crate::input::MouseInputBridge;
use crate::interrupts::{enter_interrupt, service_vector};
use crate::trace::{GuestMemoryWriteObserver, GuestWriteBoundary};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, XMS_ENTRY, runtime_error};
use devices::BiosDevices;
use devices::ports::MachinePorts;
use dos_kernel::DosAction;
use guest_core::arena::PhysicalArenaMap;
use guest_core::memory::Memory;
use guest_core::{GuestMemory, OwnerId, PhysAddr, real_address};
use x86_cpu::{Cpu, StepOutcome};
use xms::XmsService;

const MAX_MOUSE_EVENTS_PER_PUMP: usize = 256;

pub struct Runtime {
    pub(crate) memory: Memory,
    pub(crate) cpu: Cpu,
    pub(crate) dos: dos_kernel::DosKernel,
    pub(crate) devices: BiosDevices,
    pub(crate) ports: MachinePorts,
    pub(crate) port_clock: DeviceClock,
    pub(crate) xms: XmsService,
    pub(crate) arenas: PhysicalArenaMap,
    pub(crate) instructions: u64,
    pub(crate) rendered_video_version: u64,
    pub(crate) rendered_graphics_version: Option<u64>,
    pub(crate) graphics_frame_decoder: devices::vga::VgaFrameDecoder,
    pub(crate) instruction_trace: Option<crate::trace::InstructionTrace>,
    pub(crate) memory_write_watch: Option<crate::trace::GuestMemoryWriteWatch>,
    pub(crate) input: MouseInputBridge,
    pub(crate) rendered_mouse_cursor: Option<(u16, u16, u16, u16)>,
    pub(crate) process_frames: Vec<crate::process::ProcessFrame>,
    pub(crate) win16: Option<crate::win16_runtime::Win16State>,
}

/// Copied diagnostic data; it grants no access to live guest state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeProgress {
    pub instructions: u64,
    pub code_segment: u16,
    pub instruction_pointer: u32,
    pub reserved_memory_regions: usize,
}

impl Runtime {
    /// Enable native generic thunks after the host has installed its stable
    /// 32-bit mapping and reentrant worker, before any guest instruction runs.
    pub fn enable_native_thunks(&mut self) -> Result<(), RuntimeError> {
        if self.instructions != 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "native thunk capability must be selected before guest execution",
            ));
        }
        let state = self.win16.as_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "native thunk capability requires a Win16 task",
            )
        })?;
        state.set_native_thunks_available(true);
        Ok(())
    }
    /// Keep the last 64 instruction-boundary snapshots in guest-owned terms.
    pub fn enable_instruction_trace(&mut self) -> Result<(), RuntimeError> {
        self.instruction_trace = Some(crate::trace::InstructionTrace::new()?);
        Ok(())
    }

    pub fn format_instruction_trace(&self) -> Option<String> {
        self.instruction_trace
            .as_ref()
            .map(crate::trace::InstructionTrace::format)
    }

    /// Observe changes to a bounded physical guest-memory range. The watch is
    /// disabled unless explicitly enabled by the caller.
    pub fn watch_guest_memory(&mut self, address: u32, length: u32) -> Result<(), RuntimeError> {
        let end = address.checked_add(length).ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "guest memory watch range overflows the physical address space",
            )
        })?;
        if end > self.memory.len() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                format!(
                    "guest memory watch 0x{address:08X}+0x{length:X} exceeds configured guest memory (0x{:08X} bytes)",
                    self.memory.len(),
                ),
            ));
        }
        let watch = crate::trace::GuestMemoryWriteWatch::new(address, length)?;
        if self.instruction_trace.is_none() {
            self.enable_instruction_trace()?;
        }
        self.memory_write_watch = Some(watch);
        Ok(())
    }

    /// Resolve a Win16 range once at watch installation. This observes the
    /// backing allocation; subsequent selector remapping does not retarget it.
    pub fn watch_win16_memory(&mut self, selector: u16, offset: u16, length: u32) -> Result<(), RuntimeError> {
        let state = self.win16.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InvalidInput, "selector memory watches require a Win16 program"))?;
        let reference = state.selectors.reference(guest_core::Selector(selector)).map_err(runtime_error)?;
        let pointer = win16_abi::SegmentedPointer::new(reference, offset);
        let address = state.selectors.translate(pointer, win16_abi::Access::Read, length as usize, &self.memory)
            .map_err(runtime_error)?;
        self.watch_guest_memory(address.0, length)
    }

    pub fn format_memory_write_watch(&self) -> Option<String> {
        self.memory_write_watch
            .as_ref()
            .map(crate::trace::GuestMemoryWriteWatch::format)
    }

    /// Copy the current guest-physical memory image for explicit failure
    /// diagnostics. This returns emulated process-owned bytes only.
    pub fn snapshot_guest_memory(&self) -> Result<Vec<u8>, RuntimeError> {
        let length = usize::try_from(self.memory.size_bytes()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "size guest memory snapshot", error)
        })?;
        let mut snapshot = Vec::new();
        snapshot.try_reserve_exact(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate guest memory snapshot",
                error,
            )
        })?;
        snapshot.resize(length, 0);
        self.memory
            .read_physical(PhysAddr(0), &mut snapshot)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "read guest memory snapshot",
                    error,
                )
            })?;
        Ok(snapshot)
    }

    pub fn progress(&self) -> RuntimeProgress {
        RuntimeProgress {
            instructions: self.instructions,
            code_segment: self.cpu.regs.cs,
            instruction_pointer: self.cpu.regs.eip,
            reserved_memory_regions: self.arenas.len(),
        }
    }

    pub fn run(
        &mut self,
        host: &mut impl RuntimeHost,
        instruction_limit: u64,
    ) -> Result<u8, RuntimeError> {
        self.check_memory_storage()?;
        let win16 = self.win16.is_some();
        let result = self.run_machine(host, instruction_limit);
        if win16 {
            // Win16 owns a multi-stage teardown after run_machine returns and
            // checks the storage latch after those cleanup steps. Do not replace
            // its typed operation/cleanup result with a second copy here.
            return result;
        }
        // Some guest service protocols convert a memory error to CF/AX. A
        // partial host transfer is not such a protocol result, including when
        // the same service requests process exit before another CPU fetch.
        match self.check_memory_storage() {
            Ok(()) => result,
            Err(storage) => match result {
                Ok(_) => Err(storage),
                Err(operation) => Err(operation.with_cleanup(
                    "runtime operation and guest-memory storage both failed",
                    storage,
                )),
            },
        }
    }

    pub(crate) fn check_memory_storage(&self) -> Result<(), RuntimeError> {
        check_memory_storage(&self.memory)
    }

    fn run_machine(
        &mut self,
        host: &mut impl RuntimeHost,
        instruction_limit: u64,
    ) -> Result<u8, RuntimeError> {
        if self.win16.is_some() {
            return self.run_win16(host, instruction_limit);
        }
        self.devices.mouse.set_present(host.mouse_available());
        crate::input::install_mouse_return_stub(&mut self.memory)?;
        self.refresh_real_mode_run_state(host)?;
        self.run_real_mode_loop(host, instruction_limit, None)?
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "top-level real-mode execution returned to a child-process depth",
                )
            })
    }

    /// Execute a synchronously launched DOS child without re-entering the
    /// Win16 loop. The protected parent CPU and DosKernel remain suspended in
    /// the process frame until that exact child depth returns.
    pub(crate) fn run_dos_child_until_process_depth(
        &mut self,
        host: &mut impl RuntimeHost,
        return_depth: usize,
        instruction_limit: u64,
    ) -> Result<(), RuntimeError> {
        if self.win16.is_none() || self.process_frames.len() <= return_depth {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DOS child runner has no matching suspended parent frame",
            ));
        }
        if self.process_frames.len() != return_depth + 1
            || !self
                .process_frames
                .last()
                .is_some_and(crate::process::ProcessFrame::is_win16_dos_child)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DOS child runner does not match the newly suspended FAR-call frame",
            ));
        }
        self.refresh_real_mode_run_state(host)?;
        match self.run_real_mode_loop(host, instruction_limit, Some(return_depth))? {
            None => Ok(()),
            Some(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DOS child runner escaped to top-level process exit",
            )),
        }
    }

    fn refresh_real_mode_run_state(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        {
            let mut memory = GuestMemoryWriteObserver::new(
                &mut self.memory,
                self.memory_write_watch.as_mut(),
                self.instructions,
                &self.cpu.regs,
                GuestWriteBoundary::DeviceClock,
            );
            self.devices
                .update_clock(&mut memory, host.epoch_seconds())
                .map_err(runtime_error)?;
        }
        {
            let mut memory = GuestMemoryWriteObserver::new(
                self.memory.bus(),
                self.memory_write_watch.as_mut(),
                self.instructions,
                &self.cpu.regs,
                GuestWriteBoundary::DosSystemTables,
            );
            self.dos
                .refresh_system_tables(&mut memory, host)
                .map_err(runtime_error)?;
        }
        Ok(())
    }

    fn run_real_mode_loop(
        &mut self,
        host: &mut impl RuntimeHost,
        instruction_limit: u64,
        return_depth: Option<usize>,
    ) -> Result<Option<u8>, RuntimeError> {
        let mut halted = false;
        let child_execution = return_depth.is_some();
        loop {
            self.check_memory_storage()?;
            if !child_execution {
                self.input
                    .restore_returned_cpu_callback(&mut self.cpu)?;
            }
            self.port_clock.advance(&mut self.ports);
            if self.cpu.take_pending_x87_irq13() {
                self.ports.request_irq(13).map_err(runtime_error)?;
            }
            if self.cpu.can_accept_maskable_interrupt() {
                if let Some(vector) = self.ports.acknowledge_interrupt() {
                    let writer = self.cpu.regs.clone();
                    let mut memory = GuestMemoryWriteObserver::new(
                        self.memory.bus(),
                        self.memory_write_watch.as_mut(),
                        self.instructions,
                        &writer,
                        GuestWriteBoundary::InterruptEntry,
                    );
                    enter_interrupt(&mut self.cpu, &mut memory, vector)?;
                    halted = false;
                }
            }
            if halted {
                self.pump_host_events(host)?;
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            if self.instructions >= instruction_limit {
                return Err(RuntimeError::new(
                    Kind::ExecutionLimit,
                    "instruction budget exhausted",
                ));
            }
            if !child_execution
                && self.cpu.allows_real_mode_service_intercepts()
                && !self.at_runtime_service_entry()
                && self.cpu.can_accept_maskable_interrupt()
            {
                let writer = self.cpu.regs.clone();
                let mut memory = GuestMemoryWriteObserver::new(
                    self.memory.bus(),
                    self.memory_write_watch.as_mut(),
                    self.instructions,
                    &writer,
                    GuestWriteBoundary::MouseCallback,
                );
                self.input
                    .start_cpu_callback_if_enabled(&mut self.cpu, &mut memory)?;
            }
            if let Some(trace) = &mut self.instruction_trace {
                trace.record(self.instructions, &self.cpu.regs, &mut self.memory);
            }
            self.check_memory_storage()?;
            if self.cpu.allows_real_mode_service_intercepts() {
                if real_address(self.cpu.regs.cs, self.cpu.regs.ip())
                    == real_address(XMS_ENTRY.segment, XMS_ENTRY.offset)
                {
                    self.call_xms()?;
                } else if self.cpu.regs.cs == dos_kernel::SYSTEM_SEGMENT {
                    let writer = self.cpu.regs.clone();
                    let mut memory = GuestMemoryWriteObserver::new(
                        self.memory.bus(),
                        self.memory_write_watch.as_mut(),
                        self.instructions,
                        &writer,
                        GuestWriteBoundary::DosCharacterService,
                    );
                    self.dos
                        .character_device_service(
                            self.cpu.regs.ip(),
                            &self.cpu.regs,
                            &mut memory,
                            host,
                        )
                        .map_err(runtime_error)?;
                } else if let Some(vector) = service_vector(self.cpu.regs.cs, self.cpu.regs.ip()) {
                    if let DosAction::Exit(code) = self.call_interrupt_service(vector, host)? {
                        self.check_memory_storage()?;
                        if self.finish_child_process(host, code)? {
                            if return_depth.is_some_and(|depth| self.process_frames.len() <= depth) {
                                return Ok(None);
                            }
                            continue;
                        }
                        if return_depth.is_some() {
                            return Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "Win16 DOS child exited without its suspended parent frame",
                            ));
                        }
                        self.xms
                            .cleanup_owner(OwnerId(u32::from(self.dos.psp_segment())));
                        self.flush_video(host)?;
                        return Ok(Some(code));
                    }
                }
            }
            self.check_memory_storage()?;
            let step_writer = self.cpu.regs.clone();
            let step_number = self.instructions;
            let outcome = {
                let mut memory = GuestMemoryWriteObserver::new(
                    self.memory.bus(),
                    self.memory_write_watch.as_mut(),
                    self.instructions,
                    &step_writer,
                    GuestWriteBoundary::CpuStep,
                );
                self.cpu.step_with_io(&mut memory, &mut self.ports)
            };
            self.capture_memory_watch_cpu_history();
            self.check_memory_storage()?;
            let outcome = outcome.map_err(runtime_error)?;
            self.instructions += 1;
            match outcome {
                StepOutcome::Continue => {}
                StepOutcome::Halt => halted = true,
                StepOutcome::Interrupt(number) => {
                    let mut memory = GuestMemoryWriteObserver::new(
                        self.memory.bus(),
                        self.memory_write_watch.as_mut(),
                        step_number,
                        &step_writer,
                        GuestWriteBoundary::InterruptEntry,
                    );
                    enter_interrupt(&mut self.cpu, &mut memory, number)?;
                }
            }
            if self.instructions % 4096 == 0 {
                self.pump_host_events(host)?;
            }
        }
    }

    pub(crate) fn capture_memory_watch_cpu_history(&mut self) {
        let capture = match self.memory_write_watch.as_mut() {
            Some(watch) => watch.take_cpu_history_request(),
            None => false,
        };
        if !capture {
            return;
        }
        let history = self
            .instruction_trace
            .as_ref()
            .map(crate::trace::InstructionTrace::format)
            .unwrap_or_default();
        if let Some(watch) = self.memory_write_watch.as_mut() {
            watch.set_cpu_history(history);
        }
    }

    fn pump_host_events(&mut self, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        self.check_memory_storage()?;
        host.pump_events()?;
        for _ in 0..MAX_MOUSE_EVENTS_PER_PUMP {
            let Some(input) = host.take_mouse_input()? else {
                break;
            };
            self.input.queue_input(&mut self.devices, input)?;
        }
        {
            let writer = self.cpu.regs.clone();
            let mut memory = GuestMemoryWriteObserver::new(
                &mut self.memory,
                self.memory_write_watch.as_mut(),
                self.instructions,
                &writer,
                GuestWriteBoundary::DeviceClock,
            );
            self.devices
                .update_clock(&mut memory, host.epoch_seconds())
                .map_err(runtime_error)?;
        }
        self.flush_video(host)
    }

    pub(crate) fn flush_video(&mut self, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        if !self.devices.video.is_text() {
            self.rendered_mouse_cursor = None;
            let vga = self.devices.video.vga();
            let version = vga.generation();
            if self.rendered_graphics_version != Some(version) {
                let frame = self
                    .graphics_frame_decoder
                    .decode(&vga)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "graphics mode has no framebuffer decoder",
                        )
                    })?;
                let generation = frame.generation;
                let render_result = host.render_graphics(&frame);
                self.graphics_frame_decoder.recycle(frame);
                render_result?;
                self.rendered_graphics_version = Some(generation);
            }
            return Ok(());
        }
        self.rendered_graphics_version = None;
        self.devices
            .refresh_video_from_guest(&self.memory)
            .map_err(runtime_error)?;
        let snapshot = self.devices.video_snapshot();
        let mouse_cursor = self.devices.mouse.text_cursor();
        if snapshot.version != self.rendered_video_version
            || mouse_cursor != self.rendered_mouse_cursor
        {
            let version = snapshot.version;
            let mut visible_snapshot = snapshot;
            overlay_text_mouse_cursor(&mut visible_snapshot, mouse_cursor);
            host.render_text(&visible_snapshot)?;
            self.rendered_video_version = version;
            self.rendered_mouse_cursor = mouse_cursor;
        }
        Ok(())
    }

    fn at_runtime_service_entry(&self) -> bool {
        self.cpu.allows_real_mode_service_intercepts()
            && (real_address(self.cpu.regs.cs, self.cpu.regs.ip())
                == real_address(XMS_ENTRY.segment, XMS_ENTRY.offset)
                || self.cpu.regs.cs == dos_kernel::SYSTEM_SEGMENT
                || service_vector(self.cpu.regs.cs, self.cpu.regs.ip()).is_some())
    }
}

/// Diagnostic reads and guest probe APIs may tolerate ordinary bad pointers.
/// A failed host transfer must still stop before another native side effect.
pub(crate) fn check_memory_storage(memory: &Memory) -> Result<(), RuntimeError> {
    match memory.storage_failure() {
        Some(error) => Err(runtime_error(error)),
        None => Ok(()),
    }
}

fn overlay_text_mouse_cursor(
    snapshot: &mut devices::video::ConsoleSnapshot,
    cursor: Option<(u16, u16, u16, u16)>,
) {
    let Some((x, y, screen_mask, cursor_mask)) = cursor else {
        return;
    };
    let columns = usize::from(snapshot.columns);
    let rows = usize::from(snapshot.rows);
    if columns == 0 || rows == 0 {
        return;
    }
    let column = usize::from(x).saturating_mul(columns) / 640;
    let row = usize::from(y).saturating_mul(rows) / 200;
    if column >= columns || row >= rows {
        return;
    }
    let Some(cell) = snapshot
        .cells
        .get_mut(row.saturating_mul(columns).saturating_add(column))
    else {
        return;
    };
    let original = u16::from_le_bytes([cell.character, cell.attribute]);
    let visible = (original & screen_mask) ^ cursor_mask;
    let [character, attribute] = visible.to_le_bytes();
    cell.character = character;
    cell.attribute = attribute;
}

#[cfg(test)]
mod mouse_overlay_tests {
    use super::overlay_text_mouse_cursor;
    use devices::video::{ConsoleSnapshot, TextCell};

    #[test]
    fn mouse_text_cursor_maps_640_by_200_coordinates_to_one_snapshot_cell() {
        let mut snapshot = ConsoleSnapshot {
            mode: 3,
            columns: 80,
            rows: 25,
            cells: vec![
                TextCell {
                    character: b'A',
                    attribute: 0x07
                };
                80 * 25
            ],
            cursor_column: 0,
            cursor_row: 0,
            cursor_shape: 0x0607,
            version: 9,
        };

        overlay_text_mouse_cursor(&mut snapshot, Some((8, 8, 0xffff, 0xffff)));

        assert_eq!(
            snapshot.cells[0],
            TextCell {
                character: b'A',
                attribute: 0x07
            }
        );
        assert_eq!(
            snapshot.cells[81],
            TextCell {
                character: !b'A',
                attribute: !0x07
            }
        );
    }
}
