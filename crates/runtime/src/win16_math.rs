//! Register ABI services for Win16 floating-point support.

use x86_cpu::Cpu;
use guest_core::{GuestMemory, Selector};
use guest_core::memory::Memory;
use win16_abi::{Access, Win16RegisterContext, Win16ReturnKind};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::Win16State;

// Microsoft C 6.0 FLOAT.H defines CW_DEFAULT as 0x1332. The Windows 3.1 WIN87EM
// reset helper requests that value but masks it to 0x1330 before FLDCW. Keep
// the existing CRT profile here. The __fpMath table says op 1
// is like FINIT but does not specify the exact control word, so preserve this
// Win16 CRT-facing profile instead of borrowing host FPU state or silently
// switching to the bare x87 FNINIT value.
const WIN87EM_INITIAL_CONTROL_WORD: u16 = 0x1332;

impl Win16State {
    pub(super) fn fp_math(
        &mut self,
        context: Win16RegisterContext,
        cpu: &mut Cpu,
        memory: &Memory,
    ) -> Result<Option<u8>, RuntimeError> {
        let (return_selector, return_offset, return_sp) =
            self.far_return(&cpu.regs, memory, 0)?;
        let operation = context.ebx as u16;
        match operation {
            // Windows 3.1 documents 0=initialize, 1=reset (like FINIT), and
            // 2=stop. The target DLL's op-2 handler calls the same reset helper
            // as op 1 before releasing installed state. This CPU has no x87-
            // disable hook, so the install count is lifecycle bookkeeping,
            // not a gate on later guest x87 instructions.
            0 | 1 | 2 => {
                let succeeded = match operation {
                    0 => match self.win87em_install_count.checked_add(1) {
                        Some(count) => {
                            self.win87em_install_count = count;
                            true
                        }
                        None => false,
                    },
                    2 => {
                        self.win87em_install_count = self.win87em_install_count.saturating_sub(1);
                        true
                    }
                    _ => true,
                };
                if succeeded {
                    cpu.reset_x87();
                    cpu.set_x87_control_word(WIN87EM_INITIAL_CONTROL_WORD);
                    cpu.clear_x87_exceptions();
                }
                cpu.regs.set_ax(0);
                if operation == 0 {
                    // The SDK specifies CF as the initialize error result.
                    if succeeded {
                        cpu.regs.eflags &= !1;
                    } else {
                        cpu.regs.eflags |= 1;
                    }
                }
            }
            4 => {
                // The comparison implementation observes an op-4 control-word extension, but it
                // masks AX with 0x00C3 before applying an internal word and
                // keeps a separate requested word. Preserve this runtime's
                // prior direct-write approximation; the manual marks op 4
                // unused, and C6 binaries do not map _control87 to this op.
                cpu.set_x87_control_word(context.eax as u16);
            }
            3 => {
                // The target Windows 3.1 WIN87EM.DLL consumes DX:AX here (its
                // op-3 handler moves DX to DS and AX to DX before INT 21h),
                // while Programmer's Reference Vol. 1 p.311 says DS:AX. Keep
                // target behavior. Callback delivery is not wired; store only
                // a validated executable address. Zero:zero remains the
                // runtime's clear convention.
                let selector = context.edx as u16;
                let offset = context.eax as u16;
                self.win87em_exception_handler = if selector == 0 && offset == 0 {
                    None
                } else {
                    let pointer = self.selectors.pointer_from_raw(Selector(selector), offset)
                        .map_err(crate::runtime_error)?;
                    self.selectors.address_within(pointer, Access::Execute, 1, memory.len())
                        .map_err(crate::runtime_error)?;
                    Some(pointer)
                };
            }
            5 => {
                // The comparison implementation's op 5 returns its separate last-requested control
                // word. Preserve this runtime's existing modeled-CW result;
                // Microsoft marks op 5 unused, and C6's _control87/_status87
                // declarations do not establish a callsite mapping.
                cpu.regs.set_ax(cpu.x87_control_word());
            }
            9 => {
                // The comparison implementation's op 9 clears its emulator exception state and
                // returns AX=0. Keep the existing modeled x87 flag clear;
                // Microsoft marks op 9 unused, with no C6 suboperation map.
                cpu.clear_x87_exceptions();
                cpu.regs.set_ax(0);
            }
            10 => {
                // The documented count covers values on the coprocessor plus
                // emulator extras. This CPU models one eight-register stack;
                // count its occupied tags without consulting host FPU state.
                let stack_depth = cpu.x87_stack_depth();
                cpu.regs.set_ax(stack_depth);
            }
            11 => {
                // The guest sees this runtime's software x87 implementation
                // as available. This is virtual capability, not a host FPU
                // probe. Keep DX=0 for the previously observed register
                // result; the Microsoft table only specifies AX.
                cpu.regs.set_ax(1);
                cpu.regs.set_dx(0);
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!("WIN87EM __fpMath operation {operation} has no emulated behavior yet"),
                ));
            }
        }
        self.complete_return(&mut cpu.regs, return_selector, return_offset, return_sp,
            0, Win16ReturnKind::Void)
    }
}
