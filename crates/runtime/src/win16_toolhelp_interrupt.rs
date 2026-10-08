//! Checked assembly callback frames for Windows 3.1 ToolHelp interrupts.

use dos_kernel::DosKernel;
use guest_core::{GuestMemory, Registers, Selector, memory::Memory};
use win16_abi::{Access, SegmentedPointer};
use x86_cpu::{
    CallEffectPolicy, CallResumeBoundary, ControlTransfer, CpuDeferredEvent,
    CpuDeferredEventResolution, CpuEventObserverContinuation, CpuExecutionMode,
    CpuGuest16BitReturnFrame, CpuGuestLdtDataSegmentLease, LegacyRegisterTransfer,
    LegacyStackPointerTarget,
};

use super::{
    CallbackFrameId, CallbackKind, Win16State,
    legacy_cpu_binding::{Win16LegacyCpuBindingError, Win16LegacyCpuBindingOwner},
};
use crate::{DiagnosticKind as Kind, RuntimeError, win16_loader::Win16Segments};

#[path = "win16_toolhelp_interrupt_entry.rs"]
mod entry;
#[path = "win16_toolhelp_interrupt_finish.rs"]
mod finish;
#[path = "win16_toolhelp_interrupt_owner.rs"]
mod owner;
#[path = "win16_toolhelp_interrupt_stack.rs"]
mod stack;

const CALLBACK_FRAME_BYTES: u16 = 16;
const CALLBACK_FAULT_STACK_EXTENSION_BYTES: u16 = 4;
const TOOLHELP_CALLBACK_WORKING_STACK_BYTES: u16 = 128;
const TOOLHELP_DIRECT_STACK_BYTES: u16 =
    CALLBACK_FRAME_BYTES + TOOLHELP_CALLBACK_WORKING_STACK_BYTES;
const TOOLHELP_PRIVATE_STACK_BYTES: u16 = CALLBACK_FRAME_BYTES
    + CALLBACK_FAULT_STACK_EXTENSION_BYTES
    + TOOLHELP_CALLBACK_WORKING_STACK_BYTES;

pub(super) fn toolhelp_preflight_declines(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::CompatibilityGap)
}

pub(super) fn toolhelp_binding_error(error: Win16LegacyCpuBindingError) -> RuntimeError {
    match error {
        Win16LegacyCpuBindingError::Selector { source, .. } => {
            crate::runtime_error(source).with_context("validate ToolHelp CPU selector root")
        }
        Win16LegacyCpuBindingError::Runtime(error) => error,
        error @ (Win16LegacyCpuBindingError::MissingBacking { .. }
        | Win16LegacyCpuBindingError::InvalidSegmentAccess { .. }) => RuntimeError::with_source(
            Kind::GuestFault,
            "the interrupted CPU context does not expose a retainable Win16 segment",
            error,
        ),
        error => RuntimeError::with_source(
            Kind::InternalInvariant,
            "ToolHelp CPU selector-root ownership became inconsistent",
            error,
        ),
    }
}

pub(super) fn toolhelp_cpu_capture_error(error: x86_cpu::CpuCallResumeError) -> RuntimeError {
    use x86_cpu::CpuCallResumeError as E;
    let kind = match error {
        E::BoundarySequenceExhausted => Kind::ResourceExhausted,
        E::UnsafeCpuBoundary
        | E::ArchitecturalContextUnavailable
        | E::InvalidExecutionMode
        | E::IncoherentSegmentSelectors
        | E::InvalidCodeState
        | E::InvalidStackState
        | E::UnsupportedGuestTransfer
        | E::InvalidLegacyExecutionMode
        | E::LegacyContextAlreadyInitialized
        | E::InvalidLegacyTransferTarget => Kind::CompatibilityGap,
        E::WrongCpu
        | E::StaleContinuation
        | E::TicketConsumed
        | E::ExecutionRootChanged
        | E::GuestExecutionOccurred
        | E::GuestCallReturnNotCompleted
        | E::PreparedStateChanged => Kind::InternalInvariant,
    };
    RuntimeError::with_source(kind, "capture ToolHelp CPU event continuation", error)
}

/// Guest-owned stack allocated from the current Win16 task's GlobalHeap.
pub(super) struct Win16ToolhelpPrivateStack {
    pub(super) global_handle: u16,
    pub(super) selector: win16_abi::SelectorRef,
    pub(super) descriptor_lease: Option<CpuGuestLdtDataSegmentLease>,
}

pub(super) struct Win16ToolhelpRetainedStack {
    pub(super) task: u16,
    pub(super) allocation: Win16ToolhelpPrivateStack,
}

struct Win16ToolhelpCallbackStack {
    callback_code_selector: u16,
    selector: u16,
    callback_sp: u16,
    callback_return_sp: u16,
    fault_stack_frame: bool,
    private: Option<Win16ToolhelpPrivateStack>,
}

enum Win16ToolhelpInterruptResume {
    Cpu(CpuDeferredEvent),
    SoftwareInterrupt { vector: u8 },
}

enum Win16ToolhelpInterruptCallOwner {
    Legacy(u64),
    Architectural(Win16ToolhelpArchitecturalOwner),
}

struct Win16ToolhelpArchitecturalOwner {
    continuation: Option<CpuEventObserverContinuation>,
    selector_roots: Option<Win16LegacyCpuBindingOwner>,
}

pub(super) struct Win16ToolhelpInterruptFrame {
    callback_id: CallbackFrameId,
    pub(in crate::win16_runtime) callback: SegmentedPointer,
    registration_handle: u16,
    event_vector: u16,
    origin: Registers,
    callback_stack_selector: u16,
    callback_stack_pointer: u16,
    callback_return_sp: u16,
    fault_stack_frame: bool,
    pub(in crate::win16_runtime) private_stack: Option<Win16ToolhelpPrivateStack>,
    cpu_owner: Option<Win16ToolhelpInterruptCallOwner>,
    cpu_restored: bool,
    event_handled: bool,
    resume: Option<Win16ToolhelpInterruptResume>,
}

pub(super) struct Win16ToolhelpRetainedSelectorOwner {
    task: u16,
    owner: Win16LegacyCpuBindingOwner,
}

/// Registration identity pins the callback's exact selector generation while
/// the ToolHelp handler remains registered. The API-visible pointer itself is
/// kept separately for guest-compatible FARPROC bits.
#[derive(Clone, Copy)]
pub(super) struct Win16ToolhelpInterruptRegistration {
    pub(super) guest_handle: u16,
    pub(super) callback_selector: win16_abi::SelectorRef,
}

pub(super) struct Win16ToolhelpStoppedEvent {
    pub(super) task: Option<u16>,
    _origin: Registers,
    _resume: Option<Win16ToolhelpInterruptResume>,
}

#[derive(Clone, Copy)]
struct Win16ToolhelpInterruptReturnFrame {
    event_vector: u16,
    registration_handle: u16,
    instruction_pointer: u16,
    code_segment: u16,
    flags: u16,
    faulting_stack: Option<(u16, u16)>,
}

fn toolhelp_return_image_rejection(error: &x86_cpu::CpuError) -> bool {
    matches!(
        error,
        x86_cpu::CpuError::GeneralProtectionFault { .. }
            | x86_cpu::CpuError::SegmentNotPresentFault { .. }
            | x86_cpu::CpuError::StackSegmentFault { .. }
            | x86_cpu::CpuError::PageFault { .. }
            | x86_cpu::CpuError::CompatibilityGap { .. }
    )
}

impl Win16ToolhelpInterruptFrame {
    pub(super) fn code_references(&self) -> [u32; 2] {
        [
            self.callback.far_value(),
            (u32::from(self.origin.cs) << 16) | u32::from(self.origin.ip()),
        ]
    }
}

impl Win16State {
    /// Drop only event tokens retained by already-finished callback frames,
    /// and only after task execution has ended. Live selector/stack owners
    /// remain for the ordinary callback teardown path.
    pub(in crate::win16_runtime) fn discard_stopped_toolhelp_interrupt_events_after_execution_ended(
        &mut self,
        _ended: &super::execute::Win16TaskExecutionEnded,
    ) {
        let mut index = 0;
        while index < self.toolhelp_interrupt_frames.len() {
            let frame = &self.toolhelp_interrupt_frames[index];
            let stopped_event = frame.cpu_restored
                && frame.cpu_owner.is_none()
                && frame.private_stack.is_none()
                && !frame.event_handled
                && matches!(
                    frame.resume.as_ref(),
                    Some(Win16ToolhelpInterruptResume::Cpu(_))
                )
                && !self.callback_frame_ids.contains(&frame.callback_id);
            if stopped_event {
                self.toolhelp_interrupt_frames.remove(index);
            } else {
                index += 1;
            }
        }
        self.toolhelp_interrupt_stopped_event = None;
    }
}

fn toolhelp_vector_supported(vector: u8) -> bool {
    matches!(vector, 0 | 1 | 3 | 6 | 12 | 13 | 14)
}

fn same_selector_generation(left: win16_abi::SelectorRef, right: win16_abi::SelectorRef) -> bool {
    left.raw().0 & 0xfff8 == right.raw().0 & 0xfff8 && left.generation() == right.generation()
}

fn write_word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn read_word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn returned_uses_released_toolhelp_stack(
    frame: &Win16ToolhelpInterruptFrame,
    returned: Win16ToolhelpInterruptReturnFrame,
) -> bool {
    let Some((stack_selector, _)) = returned.faulting_stack else {
        return false;
    };
    frame
        .private_stack
        .as_ref()
        .is_some_and(|stack| stack.selector.raw().0 & !3 == stack_selector & !3)
}

/// TOOLHELP.H requires assembly handlers to preserve registers so the event
/// can be restarted or chained with the original machine state.
fn preserved_interrupt_registers(before: &Registers, after: &Registers) -> bool {
    before.eax == after.eax
        && before.ebx == after.ebx
        && before.ecx == after.ecx
        && before.edx == after.edx
        && before.ebp == after.ebp
        && before.esi == after.esi
        && before.edi == after.edi
        // 16-bit PUSH/POP and RETF change only the low stack-pointer word.
        && before.esp & 0xffff_0000 == after.esp & 0xffff_0000
        && before.ds == after.ds
        && before.es == after.es
        && before.fs == after.fs
        && before.gs == after.gs
}
