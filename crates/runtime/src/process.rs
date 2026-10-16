//! DOS EXEC process transitions in the shared emulated address space.

#[path = "process_cpu_context.rs"]
mod cpu_context;
#[path = "process_failure.rs"]
mod process_failure;

use crate::environment::EnvironmentBlock;
use crate::interrupts::store_service_return_flags;
use crate::{Diagnostic, DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, runtime_error};
use dos_kernel::{DosError, DosErrorCode, DosExecRequest, DosFileAccess, DosHostError, DosKernel};
use formats::{FormatError, ImageKind, load_executable, parse_mz};
use guest_core::memory::Memory;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers, real_address};
use x86_cpu::Cpu;
use process_failure::combine_process_failure;

const PSP_BYTES: usize = 256;
const PSP_PARENT_SEGMENT_OFFSET: u16 = 0x16;
const PSP_INLINE_JFT_OFFSET: u16 = 0x18;
const PSP_ENVIRONMENT_OFFSET: u16 = 0x2c;
const PSP_JFT_COUNT_OFFSET: u16 = 0x32;
const PSP_JFT_POINTER_OFFSET: u16 = 0x34;
const PSP_PREVIOUS_PSP_OFFSET: usize = 0x38;
const PSP_INLINE_JFT_BYTES: usize = 20;
const PROCESS_INTERRUPT_VECTORS: [(u8, u16); 3] = [(0x22, 0x0a), (0x23, 0x0e), (0x24, 0x12)];
const COM_PROCESS_PARAGRAPHS: u16 = 0x1000;
const MAX_GUEST_IMAGE_BYTES: usize = 0xa0000;

pub(crate) struct ProcessFrame {
    pub(crate) cpu: Cpu,
    pub(crate) dos: DosKernel,
    /// Immutable MCB/PSP owner created for this EXEC, independent of later
    /// AH=50h changes to the child's current PSP.
    child_allocation_psp: u16,
    pub(crate) exec_instruction: u64,
    pub(crate) exec_request: Registers,
    return_to: ProcessReturn,
    child_phase: ChildProcessPhase,
}

impl ProcessFrame {
    pub(crate) fn is_win16_dos_child(&self) -> bool {
        matches!(
            self.child_phase,
            ChildProcessPhase::Running
                | ChildProcessPhase::VectorsRestored
                | ChildProcessPhase::ResourcesClosed
        ) && matches!(self.return_to, ProcessReturn::Win16FarCall { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildProcessPhase {
    Starting,
    Running,
    VectorsRestored,
    ResourcesClosed,
}

#[derive(Clone, Copy)]
enum ProcessReturn {
    DosInterrupt,
    Win16FarCall { return_to: (u16, u16, u32) },
}

enum ChildStartupFailure {
    Dos(DosError),
    Guest {
        code: DosErrorCode,
        cause: RuntimeError,
    },
    Runtime(RuntimeError),
}

impl ChildStartupFailure {
    fn into_guest_result(self, host: &mut impl RuntimeHost)
        -> Result<Option<DosErrorCode>, RuntimeError> {
        match self {
            Self::Dos(error) => dos_failure(error),
            Self::Guest { code, cause } => {
                if cause.kind() == Kind::CompatibilityGap {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap, "DOS EXEC image format is unsupported; returning DOS invalid-format",
                    ).with_cause(cause));
                }
                Ok(Some(code))
            }
            Self::Runtime(error) => Err(error),
        }
    }

    fn into_runtime_error(self) -> RuntimeError {
        match self {
            Self::Dos(error) => runtime_error(error),
            Self::Guest { cause, .. } | Self::Runtime(cause) => cause,
        }
    }
}

impl Runtime {
    /// A normal DOS EXEC error is returned through AX/CF by the caller. A
    /// damaged emulator or guest memory arena remains a runtime error.
    pub(crate) fn start_child_process(
        &mut self,
        request: DosExecRequest,
        host: &mut impl RuntimeHost,
        exec_instruction: u64,
        exec_registers: Registers,
    ) -> Result<Option<DosErrorCode>, RuntimeError> {
        self.start_child_process_with_return(
            request,
            host,
            exec_instruction,
            exec_registers,
            ProcessReturn::DosInterrupt,
        )
    }

    /// Start the DOS EXEC decoded by the KERNEL DOS3Call register ABI. The
    /// request has already been copied through the protected caller view; the
    /// child itself runs with real-mode DOS segment semantics.
    pub(crate) fn start_win16_child_process(
        &mut self,
        request: DosExecRequest,
        host: &mut impl RuntimeHost,
        exec_instruction: u64,
        exec_registers: Registers,
        return_to: (u16, u16, u32),
    ) -> Result<Option<DosErrorCode>, RuntimeError> {
        self.start_child_process_with_return(
            request,
            host,
            exec_instruction,
            exec_registers,
            ProcessReturn::Win16FarCall { return_to },
        )
    }

    fn start_child_process_with_return(
        &mut self,
        request: DosExecRequest,
        host: &mut impl RuntimeHost,
        exec_instruction: u64,
        exec_registers: Registers,
        return_to: ProcessReturn,
    ) -> Result<Option<DosErrorCode>, RuntimeError> {
        self.process_frames.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve DOS process frame", error)
        })?;

        let image = match read_guest_program(&mut self.dos, host, &request.program_path) {
            Ok(image) => image,
            Err(ProgramReadFailure::Dos(code)) => return Ok(Some(code)),
            Err(ProgramReadFailure::Runtime(error)) => return Err(error),
        };
        let source_environment = if request.environment_segment != 0 {
            request.environment_segment
        } else {
            self.memory
                .read_u16(real_address(self.dos.psp_segment(), 0x2c))
                .map_err(runtime_error)?
        };
        let environment = match EnvironmentBlock::copy_for_child(
            &self.memory.bus(),
            source_environment,
            &request.program_path,
        ) {
            Ok(environment) => environment,
            Err(code) => return Ok(Some(code)),
        };

        let largest = match self.dos.largest_free_block(&mut self.memory.bus()) {
            Ok(size) => size,
            Err(error) => return dos_failure(error),
        };
        let Some(reserved_environment) = environment.paragraphs.checked_add(1) else {
            return Ok(Some(DosErrorCode::InsufficientMemory));
        };
        let Some(maximum_program) = largest.checked_sub(reserved_environment) else {
            return Ok(Some(DosErrorCode::InsufficientMemory));
        };
        let program_paragraphs = match required_program_paragraphs(&image, maximum_program) {
            Ok(size) => size,
            Err(code) => return Ok(Some(code)),
        };

        let child_psp = match self
            .dos
            .allocate_child_process_block(&mut self.memory.bus(), program_paragraphs)
        {
            Ok(segment) => segment,
            Err(error) => return dos_failure(error),
        };
        let mut child_dos = DosKernel::child_allocation_owner(&self.dos, child_psp);
        let environment_segment = match self.dos.allocate_owned_block(
            &mut self.memory.bus(),
            child_psp,
            environment.paragraphs,
        ) {
            Ok(segment) => segment,
            Err(error) => {
                return self.rollback_child_startup(
                    child_dos,
                    host,
                    exec_instruction,
                    exec_registers,
                    return_to,
                    ChildStartupFailure::Dos(error),
                );
            }
        };

        let prepared = (|| -> Result<_, RuntimeError> {
            self.memory
                .write(real_address(environment_segment, 0), &environment.bytes)
                .map_err(runtime_error)?;
            install_child_psp(
                &mut self.memory,
                child_psp,
                self.dos.psp_segment(),
                program_paragraphs,
                environment_segment,
                &request,
            )?;
            let end = (u32::from(child_psp) + u32::from(program_paragraphs)) * 16;
            let loaded = load_executable(
                &image,
                child_psp,
                &mut ChildConventional {
                    memory: &mut self.memory,
                    end,
                },
            );
            Ok(loaded)
        })();
        let loaded = match prepared {
            Ok(Ok(loaded)) => loaded,
            Ok(Err(error)) => {
                let failure = executable_load_failure(error);
                return self.rollback_child_startup(
                    child_dos,
                    host,
                    exec_instruction,
                    exec_registers,
                    return_to,
                    failure,
                );
            }
            Err(error) => {
                return self.rollback_child_startup(
                    child_dos,
                    host,
                    exec_instruction,
                    exec_registers,
                    return_to,
                    ChildStartupFailure::Runtime(error),
                );
            }
        };
        if loaded.kind == ImageKind::Com {
            if let Err(error) = self.memory.write_u16(real_address(child_psp, 0xfffe), 0) {
                return self.rollback_child_startup(
                    child_dos,
                    host,
                    exec_instruction,
                    exec_registers,
                    return_to,
                    ChildStartupFailure::Runtime(runtime_error(error)),
                );
            }
        }
        if let Err(error) = child_dos.begin_child_process(&mut self.dos, host) {
            let failure = match error {
                DosError::HostOperation(host_error) => ChildStartupFailure::Guest {
                    code: host_error.code,
                    cause: runtime_error(DosError::HostOperation(host_error)),
                },
                error => ChildStartupFailure::Runtime(runtime_error(error)),
            };
            return self.rollback_child_startup(
                child_dos,
                host,
                exec_instruction,
                exec_registers,
                return_to,
                failure,
            );
        }
        let child_model = self.cpu.model();
        let mut child_cpu = Cpu::new_with_model(loaded.registers, child_model);
        child_cpu.set_execution_engine(self.cpu.execution_engine());
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        child_cpu.set_jit_artifact_store(self.cpu.jit_artifact_store());
        let parent_cpu = std::mem::replace(
            &mut self.cpu,
            child_cpu,
        );
        let parent_dos = std::mem::replace(&mut self.dos, child_dos);
        self.process_frames.push(ProcessFrame {
            cpu: parent_cpu,
            dos: parent_dos,
            child_allocation_psp: child_psp,
            exec_instruction,
            exec_request: exec_registers,
            return_to,
            child_phase: ChildProcessPhase::Running,
        });
        Ok(None)
    }

    fn rollback_child_startup(
        &mut self,
        mut child: DosKernel,
        host: &mut impl RuntimeHost,
        exec_instruction: u64,
        exec_request: Registers,
        return_to: ProcessReturn,
        failure: ChildStartupFailure,
    ) -> Result<Option<DosErrorCode>, RuntimeError> {
        let child_allocation_psp = child.psp_segment();
        match child.abort_child_process(
            &mut self.dos,
            &mut self.memory.bus(),
            host,
            child_allocation_psp,
        ) {
            Ok(()) => failure.into_guest_result(host),
            Err(cleanup) => {
                let operation = failure.into_runtime_error();
                // Preserve the complete modeled context through the CPU's
                // snapshot API; the execution engine is not a cloneable owner.
                let (parent_cpu, restore_error) = match cpu_context::restored_copy(&self.cpu) {
                    Ok(parent_cpu) => (parent_cpu, None),
                    Err(restore_error) => {
                        // The original CPU is still the source of the snapshot.
                        // Retain that owner in the retry frame if reconstruction
                        // rejects the context profile.
                        let placeholder = Cpu::new_with_model(
                            self.cpu.regs.clone(),
                            self.cpu.model(),
                        );
                        (
                            std::mem::replace(&mut self.cpu, placeholder),
                            Some(restore_error),
                        )
                    }
                };
                let parent_dos = std::mem::replace(&mut self.dos, child);
                self.process_frames.push(ProcessFrame {
                    cpu: parent_cpu,
                    dos: parent_dos,
                    child_allocation_psp,
                    exec_instruction,
                    exec_request,
                    return_to,
                    child_phase: ChildProcessPhase::Starting,
                });
                let mut combined = combine_process_failure(operation, runtime_error(cleanup));
                if let Some(restore_error) = restore_error {
                    combined = combined.with_cleanup(
                        "restore the parent CPU context after child startup cleanup failed",
                        restore_error,
                    );
                }
                Err(combined)
            }
        }
    }

    /// Return to the suspended parent at its INT 21h service IRET.
    pub(crate) fn finish_child_process(
        &mut self,
        host: &mut impl RuntimeHost,
        code: u8,
    ) -> Result<bool, RuntimeError> {
        if self.process_frames.is_empty() {
            return Ok(false);
        }
        if !self.process_frames.last().is_some_and(|frame| {
            matches!(
                frame.child_phase,
                ChildProcessPhase::Running
                    | ChildProcessPhase::VectorsRestored
                    | ChildProcessPhase::ResourcesClosed
            )
        }) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DOS child returned before its process image started",
            ));
        }
        let frame_index = self.process_frames.len() - 1;
        let child_psp = self.process_frames[frame_index].child_allocation_psp;
        let mut parent_cpu =
            cpu_context::restored_copy(&self.process_frames[frame_index].cpu)?;
        if self.process_frames[frame_index].child_phase == ChildProcessPhase::Running {
            restore_child_interrupt_vectors(&mut self.memory.bus(), child_psp)?;
            let frame = self.process_frames.get_mut(frame_index).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DOS child process frame disappeared after vector restoration",
                )
            })?;
            frame.child_phase = ChildProcessPhase::VectorsRestored;
        }
        if self.process_frames[frame_index].child_phase != ChildProcessPhase::ResourcesClosed {
            let frame = self.process_frames.get_mut(frame_index).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DOS child process frame disappeared before cleanup",
                )
            })?;
            self.dos
                .finish_child_process(
                    &mut frame.dos,
                    &mut self.memory.bus(),
                    host,
                    code,
                    child_psp,
                )
                .map_err(runtime_error)?;
            frame.child_phase = ChildProcessPhase::ResourcesClosed;
        }
        self.xms
            .cleanup_owner(guest_core::OwnerId(u32::from(child_psp)));
        let frame = self.process_frames.get_mut(frame_index).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DOS child process frame disappeared before parent restoration",
            )
        })?;
        frame
            .dos
            .refresh_system_tables(&mut self.memory.bus(), host)
            .map_err(runtime_error)?;

        DosKernel::complete_exec_success(&mut parent_cpu.regs);
        match frame.return_to {
            ProcessReturn::DosInterrupt => {
                store_service_return_flags(&mut self.memory.bus(), &parent_cpu.regs)?;
            }
            ProcessReturn::Win16FarCall { return_to } => {
                let state = self.win16.as_mut().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DOS3Call parent state disappeared while its DOS child ran",
                    )
                })?;
                state.complete_kernel_register_return(&mut parent_cpu.regs, return_to)?;
            }
        }
        host.observe_dos_service(
            frame.exec_instruction,
            &frame.exec_request,
            &parent_cpu.regs,
        );
        let frame = self.process_frames.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DOS child process frame disappeared after cleanup",
            )
        })?;
        self.cpu = parent_cpu;
        self.dos = frame.dos;
        Ok(true)
    }

    /// Abort suspended DOS children during fatal Win16 task teardown. Each
    /// frame stays in place until the DOS host handles and PSP allocations
    /// have actually been released, so a cleanup error retains its retry data.
    pub(crate) fn abort_child_processes(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        while let Some(frame_index) = self.process_frames.len().checked_sub(1) {
            let child_psp = self.process_frames[frame_index].child_allocation_psp;
            if self.process_frames[frame_index].child_phase == ChildProcessPhase::Running {
                restore_child_interrupt_vectors(&mut self.memory.bus(), child_psp)?;
                let frame = self.process_frames.get_mut(frame_index).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "DOS child process frame disappeared after vector restoration",
                    )
                })?;
                frame.child_phase = ChildProcessPhase::VectorsRestored;
            }
            if self.process_frames[frame_index].child_phase != ChildProcessPhase::ResourcesClosed {
                let frame = self.process_frames.get_mut(frame_index).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "DOS child process frame disappeared during fatal cleanup",
                    )
                })?;
                self.dos
                    .abort_child_process(&mut frame.dos, &mut self.memory.bus(), host, child_psp)
                    .map_err(runtime_error)?;
                frame.child_phase = ChildProcessPhase::ResourcesClosed;
            }
            self.xms
                .cleanup_owner(guest_core::OwnerId(u32::from(child_psp)));
            let frame = self.process_frames.pop().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DOS child frame disappeared after fatal cleanup",
                )
            })?;
            self.cpu = frame.cpu;
            self.dos = frame.dos;
        }
        Ok(())
    }
}

fn dos_failure(error: DosError) -> Result<Option<DosErrorCode>, RuntimeError> {
    match error {
        DosError::HostOperation(error) => Ok(Some(error.code)),
        error => Err(runtime_error(error)),
    }
}

enum ProgramReadFailure {
    Dos(DosErrorCode),
    Runtime(RuntimeError),
}

enum ProgramReadCause {
    Guest(DosErrorCode),
    Host(DosHostError),
    Contract(RuntimeError),
    Resource(RuntimeError),
}

impl ProgramReadCause {
    fn into_read_failure(self) -> ProgramReadFailure {
        match self {
            Self::Guest(code) => ProgramReadFailure::Dos(code),
            Self::Host(error) => ProgramReadFailure::Dos(error.code),
            Self::Contract(error) | Self::Resource(error) => ProgramReadFailure::Runtime(error),
        }
    }

    fn into_runtime_error(self) -> RuntimeError {
        match self {
            Self::Guest(code) => RuntimeError::with_source(
                Kind::InvalidInput,
                "DOS EXEC program image was rejected before child startup",
                ProgramReadGuestFailure(code),
            ),
            Self::Host(error) => runtime_error(DosError::HostOperation(error)),
            Self::Contract(error) | Self::Resource(error) => error,
        }
    }
}

#[derive(Debug)]
struct ProgramReadGuestFailure(DosErrorCode);

impl std::fmt::Display for ProgramReadGuestFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "DOS error {}", self.0)
    }
}

impl std::error::Error for ProgramReadGuestFailure {}

#[derive(Debug)]
struct UnretainedDosFileFailure {
    file: dos_kernel::DosHostFile,
    close: DosHostError,
    record: DosHostError,
}

impl std::fmt::Display for UnretainedDosFileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "DOS file identity {} could not be retained after close failed: {}; bookkeeping failed: {}",
            self.file.0, self.close, self.record
        )
    }
}

impl std::error::Error for UnretainedDosFileFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.close)
    }
}

fn read_guest_program(
    dos: &mut DosKernel,
    host: &mut impl RuntimeHost,
    path: &[u8],
) -> Result<Vec<u8>, ProgramReadFailure> {
    dos.reserve_file_cleanup_slot()
        .map_err(|error| ProgramReadFailure::Dos(error.code))?;
    let file = host
        .file_open(path, DosFileAccess::ReadOnly)
        .map_err(|error| ProgramReadFailure::Dos(error.code))?;
    let mut image = Vec::new();
    let result = (|| -> Result<Vec<u8>, ProgramReadCause> {
        let mut buffer = [0u8; 8192];
        loop {
            let count = host
                .file_read(file, &mut buffer)
                .map_err(ProgramReadCause::Host)?;
            if count == 0 {
                break;
            }
            if count > buffer.len() {
                return Err(ProgramReadCause::Contract(RuntimeError::new(
                    Kind::InternalInvariant,
                    "host DOS file read exceeded the supplied output buffer",
                )));
            }
            if image.len().saturating_add(count) > MAX_GUEST_IMAGE_BYTES {
                return Err(ProgramReadCause::Guest(DosErrorCode::InvalidFormat));
            }
            image.try_reserve(count).map_err(|error| {
                ProgramReadCause::Resource(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve DOS EXEC image bytes",
                    error,
                ))
            })?;
            image.extend_from_slice(&buffer[..count]);
        }
        if image.is_empty() {
            return Err(ProgramReadCause::Guest(DosErrorCode::InvalidFormat));
        }
        Ok(image)
    })();
    let close = host.file_close(file);
    match (result, close) {
        (Err(cause), Ok(())) => Err(cause.into_read_failure()),
        (Ok(image), Ok(())) => Ok(image),
        (read_result, Err(close_error)) => {
            if let Err(record_error) = dos.retain_unclosed_file(file) {
                let cleanup = RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "DOS EXEC file close failed and the reserved retry slot was unavailable",
                    UnretainedDosFileFailure {
                        file,
                        close: close_error,
                        record: record_error,
                    },
                );
                let error = match read_result {
                    Err(operation) => {
                        combine_process_failure(operation.into_runtime_error(), cleanup)
                    }
                    Ok(_) => cleanup,
                };
                return Err(ProgramReadFailure::Runtime(error));
            }
            let cleanup = runtime_error(DosError::HostOperation(close_error));
            let error = match read_result {
                Err(operation) => combine_process_failure(operation.into_runtime_error(), cleanup),
                Ok(_) => cleanup,
            };
            Err(ProgramReadFailure::Runtime(error))
        }
    }
}

fn required_program_paragraphs(image: &[u8], available: u16) -> Result<u16, DosErrorCode> {
    if image.starts_with(b"MZ") {
        let mz = parse_mz(image).map_err(|_| DosErrorCode::InvalidFormat)?;
        let image_paragraphs = mz.image.len().div_ceil(16);
        let base = 0x10usize
            .checked_add(image_paragraphs)
            .ok_or(DosErrorCode::InvalidFormat)?;
        let minimum = base
            .checked_add(usize::from(mz.header.min_extra_paragraphs))
            .ok_or(DosErrorCode::InvalidFormat)?;
        if minimum > usize::from(available) {
            return Err(DosErrorCode::InsufficientMemory);
        }
        let extra_available = usize::from(available) - base;
        let extra = usize::from(mz.header.max_extra_paragraphs).min(extra_available);
        u16::try_from(base + extra).map_err(|_| DosErrorCode::InvalidFormat)
    } else {
        if image.len() > 0xff00 {
            return Err(DosErrorCode::InvalidFormat);
        }
        if available < COM_PROCESS_PARAGRAPHS {
            return Err(DosErrorCode::InsufficientMemory);
        }
        Ok(available)
    }
}

fn executable_load_failure(error: FormatError) -> ChildStartupFailure {
    // This DOS loader's unsupported-image variants return InvalidFormat; other gaps remain runtime errors.
    let return_invalid_format = matches!(
        &error,
        FormatError::Truncated { .. }
            | FormatError::InvalidSignature { .. }
            | FormatError::InvalidCom(_)
            | FormatError::InvalidMzHeader(_)
            | FormatError::InvalidNe(_)
            | FormatError::ArithmeticOverflow
            | FormatError::UnsupportedExecutable(_)
            | FormatError::UnsupportedNeLoading
    );
    let cause = runtime_error(error).with_context("DOS EXEC image could not be loaded");
    if return_invalid_format {
        ChildStartupFailure::Guest {
            code: DosErrorCode::InvalidFormat,
            cause,
        }
    } else {
        ChildStartupFailure::Runtime(cause)
    }
}

fn install_child_psp(
    memory: &mut Memory,
    child: u16,
    parent: u16,
    paragraphs: u16,
    environment: u16,
    request: &DosExecRequest,
) -> Result<(), RuntimeError> {
    let end_segment = child.checked_add(paragraphs).ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "child process block crosses the segment address space",
        )
    })?;
    let mut psp = [0u8; PSP_BYTES];
    psp[0..2].copy_from_slice(&[0xcd, 0x20]);
    psp[2..4].copy_from_slice(&end_segment.to_le_bytes());
    for (vector, offset) in PROCESS_INTERRUPT_VECTORS {
        let offset = usize::from(offset);
        memory
            .read(
                PhysAddr(u32::from(vector) * 4),
                &mut psp[offset..offset + 4],
            )
            .map_err(runtime_error)?;
    }
    psp[usize::from(PSP_PARENT_SEGMENT_OFFSET)..usize::from(PSP_PARENT_SEGMENT_OFFSET) + 2]
        .copy_from_slice(&parent.to_le_bytes());

    // Start all slots closed. After `DosKernel::child_process` filters
    // no-inherit handles, `refresh_system_tables` writes this child's actual
    // JFT from its inherited DOS handle state before the first guest step.
    psp[usize::from(PSP_INLINE_JFT_OFFSET)
        ..usize::from(PSP_INLINE_JFT_OFFSET) + PSP_INLINE_JFT_BYTES]
        .fill(0xff);
    psp[usize::from(PSP_ENVIRONMENT_OFFSET)..usize::from(PSP_ENVIRONMENT_OFFSET) + 2]
        .copy_from_slice(&environment.to_le_bytes());
    psp[usize::from(PSP_JFT_COUNT_OFFSET)..usize::from(PSP_JFT_COUNT_OFFSET) + 2]
        .copy_from_slice(&(PSP_INLINE_JFT_BYTES as u16).to_le_bytes());
    psp[usize::from(PSP_JFT_POINTER_OFFSET)..usize::from(PSP_JFT_POINTER_OFFSET) + 2]
        .copy_from_slice(&PSP_INLINE_JFT_OFFSET.to_le_bytes());
    psp[0x36..0x38].copy_from_slice(&child.to_le_bytes());
    psp[PSP_PREVIOUS_PSP_OFFSET..PSP_PREVIOUS_PSP_OFFSET + 2].copy_from_slice(&0_u16.to_le_bytes());
    psp[PSP_PREVIOUS_PSP_OFFSET + 2..PSP_PREVIOUS_PSP_OFFSET + 4]
        .copy_from_slice(&parent.to_le_bytes());
    psp[0x50..0x53].copy_from_slice(&[0xcd, 0x21, 0xcb]);
    psp[0x5c..0x6c].copy_from_slice(&request.first_fcb);
    psp[0x6c..0x7c].copy_from_slice(&request.second_fcb);
    psp[0x80..0x100].copy_from_slice(&request.command_tail);
    memory
        .write(real_address(child, 0), &psp)
        .map_err(runtime_error)
}

fn restore_child_interrupt_vectors(
    memory: &mut impl GuestMemory,
    child_psp: u16,
) -> Result<(), RuntimeError> {
    for (vector, psp_offset) in PROCESS_INTERRUPT_VECTORS {
        let mut saved_vector = [0; 4];
        memory
            .read(real_address(child_psp, psp_offset), &mut saved_vector)
            .map_err(runtime_error)?;
        memory
            .write(PhysAddr(u32::from(vector) * 4), &saved_vector)
            .map_err(runtime_error)?;
    }
    Ok(())
}

struct ChildConventional<'a> {
    memory: &'a mut Memory,
    end: u32,
}

impl GuestMemory for ChildConventional<'_> {
    fn len(&self) -> u32 {
        self.end.min(self.memory.len())
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, bytes.len())?;
        self.memory.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, bytes.len())?;
        self.memory.write(address, bytes)
    }
}
