//! Terminal cleanup accepts only an exact, already-completed callback owner.
use super::*;
use super::super::{CallbackKind, execute::Win16TaskExecutionEnded,
    test_support::tiny_ne_executable};
use crate::Runtime;

#[test]
fn terminal_ownerless_far_callback_requires_complete_return_and_exact_top() {
    for restored in [false, true] {
        for returned in [false, true] {
            let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\CALLBACK.NE").unwrap();
            let state = runtime.win16.as_mut().unwrap();
            let id = state.reserve_callback_frame_id().unwrap();
            state.push_callback_kind(CallbackKind::Font, id).unwrap();
            let mut frame = Win16FarCallbackFrame {
                saved: runtime.cpu.regs.clone(),
                procedure: u32::from(runtime.cpu.regs.cs) << 16,
                return_kind: Win16FarCallbackReturn::Word,
                cpu_owner: None,
                cpu_restored: restored,
                returned_value: returned.then_some(7),
                terminal_aborted: false,
            };
            // A terminal transition must leave the current CPU alone even if
            // its saved caller differs. This test injects state combinations;
            // the font lifecycle test separately proves the real checked RETF.
            runtime.cpu.regs.set_ax(0x4567);
            let current = runtime.cpu.regs.clone();
            let ended = Win16TaskExecutionEnded::for_test();
            let wrong_id = state.reserve_callback_frame_id().unwrap();
            for (kind, callback_id) in [(CallbackKind::LineDda, id), (CallbackKind::Font, wrong_id)] {
                assert!(state.abort_guest_far_callback_after_task_execution_ended(
                    &ended, kind, callback_id, &mut runtime.cpu, &mut runtime.dos,
                    &mut runtime.memory, &mut frame).is_err());
                assert!(!frame.terminal_aborted);
            }
            // A retained owner identity must still go through the exact CPU
            // owner path, even when both cached completion flags are present.
            let mut invalid_owner = frame.clone();
            invalid_owner.cpu_owner = Some(u64::MAX);
            assert!(state.abort_guest_far_callback_after_task_execution_ended(
                &ended, CallbackKind::Font, id, &mut runtime.cpu, &mut runtime.dos,
                &mut runtime.memory, &mut invalid_owner).is_err());
            assert!(!invalid_owner.terminal_aborted);
            assert_eq!(invalid_owner.cpu_owner, Some(u64::MAX));
            let result = state.abort_guest_far_callback_after_task_execution_ended(
                &ended, CallbackKind::Font, id, &mut runtime.cpu, &mut runtime.dos,
                &mut runtime.memory, &mut frame);
            assert_eq!(result.is_ok(), restored && returned);
            assert_eq!(frame.terminal_aborted, restored && returned);
            assert_eq!(frame.cpu_restored, restored);
            assert_eq!(frame.returned_value, returned.then_some(7));
            assert_eq!(runtime.cpu.regs, current);
            assert!(state.legacy_cpu_frames.is_empty());
            assert_eq!(state.require_callback_top(CallbackKind::Font).unwrap(), id);
            if restored && returned {
                state.abort_guest_far_callback_after_task_execution_ended(
                    &ended, CallbackKind::Font, id, &mut runtime.cpu, &mut runtime.dos,
                    &mut runtime.memory, &mut frame).unwrap();
                assert_eq!(runtime.cpu.regs, current);
                assert!(state.finish_guest_far_callback_checked(&mut runtime.cpu,
                    &mut runtime.dos, &mut runtime.memory, &mut frame).is_err());
                assert!(state.abort_guest_far_callback_after_task_execution_ended(
                    &ended, CallbackKind::Font, wrong_id, &mut runtime.cpu, &mut runtime.dos,
                    &mut runtime.memory, &mut frame).is_err());
            }
        }
    }
}
