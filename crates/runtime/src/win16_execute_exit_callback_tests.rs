//! Execute real ToolHelp Pascal callbacks across deferred DOS task exit.
//!
//! These tests deliberately drive the inner CPU/firmware loop. They prove
//! normal checked callback return and its root release, not outer host-resource
//! teardown. Instruction-limit pauses preserve live frames for inspection.

use super::{ExitHost, Kind};
use crate::{Runtime, Win16CanonicalPath};
use crate::win16_runtime::toolhelp_notify::{Win16ToolhelpNotifyData, Win16ToolhelpNotifyEvent};
use guest_core::{OwnerId, Selector};
use win16_abi::{Access, toolhelp_abi::{NF_TASKSWITCH, NFY_EXITTASK, NFY_TASKIN, NFY_TASKOUT}};

const CALLBACK_IP: u16 = 0x40;
const MAIN_IP: u16 = 0xfb;

fn fixture(callback: &[u8]) -> (Runtime, OwnerId, u16) {
    let mut image = crate::win16_runtime::test_support::tiny_ne_executable();
    image[0x54..0x56].copy_from_slice(&MAIN_IP.to_le_bytes());
    let mut runtime = Runtime::load(&image, &[], br"C:\EXITCB.NE").unwrap();
    let data_selector = runtime.cpu.regs.ds;
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.tasks.current().unwrap();
    state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
        drive: 2, components: Vec::new(),
    }).unwrap();
    for (offset, bytes) in [
        (CALLBACK_IP, callback),
        (MAIN_IP, &[0xb8, 0x07, 0x4c, 0xcd, 0x21][..]),
    ] {
        let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.cs), offset).unwrap();
        let address = state.selectors.translate(pointer, Access::Execute, bytes.len(), &runtime.memory).unwrap();
        runtime.memory.write_physical(address, bytes).unwrap();
    }
    assert_eq!(state.toolhelp_notify_register(
        0, (u32::from(runtime.cpu.regs.cs) << 16) | u32::from(CALLBACK_IP),
        NF_TASKSWITCH, &runtime.memory,
    ).unwrap(), 1);
    (runtime, owner, data_selector)
}

fn word(runtime: &Runtime, data_selector: u16, offset: u16) -> u16 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(data_selector), offset).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, 2, &runtime.memory).unwrap();
    let mut bytes = [0; 2];
    runtime.memory.read_physical(address, &mut bytes).unwrap();
    u16::from_le_bytes(bytes)
}

fn pause(runtime: &mut Runtime, host: &mut ExitHost, limit: u64) {
    let error = runtime.run_win16_inner(host, limit).unwrap_err();
    assert_eq!(error.kind(), Kind::ExecutionLimit,
        "pause at instruction {limit}, actual instruction {} at {:04X}:{:04X}: {error:?}",
        runtime.instructions, runtime.cpu.regs.cs, runtime.cpu.regs.ip());
    assert_eq!(runtime.instructions, limit);
    assert!(host.exits.is_empty());
}

fn assert_completed(runtime: &Runtime, host: &ExitHost, owner: OwnerId, markers: &[u16]) {
    assert_eq!(host.terminal_dos_calls, 1, "AH=4Ch must be serviced exactly once");
    assert_eq!(host.exits, [7]);
    assert_eq!(host.callback_markers, markers);
    assert_eq!(host.markers_at_exit, [markers.to_vec()], "TaskExit must follow every guest callback marker");
    assert!(host.resumes >= 2, "the DDE script must delay native retirement");
    assert!(host.active.is_none());
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.toolhelp_task_exit.pending_id().is_none());
    assert!(!state.toolhelp_task_exit.has_active_notification_callback());
    assert!(!state.toolhelp_notify.needs_scheduler_progress());
    assert!(state.toolhelp_notify_frames.is_empty());
    assert!(state.callback_kinds.is_empty());
    assert!(state.callback_frame_ids.is_empty());
    assert!(state.legacy_cpu_frames.is_empty(), "checked RETF must release retained selector/CPU owners");
    assert_eq!(state.toolhelp_notify_code_references().count(), 0);
    assert!(state.classic_dde_task_exit_quiesced(owner));
    assert!(!state.classic_dde_task_exit_needs_pump());
}

#[test]
fn terminal_int21_dispatches_and_executes_exittask_checked_callback() {
    let callback = [
        0x55,                         // push bp
        0x89, 0xe5,                   // mov bp,sp
        0x8b, 0x46, 0x0a,             // mov ax,[bp+10]: notification
        0xa3, 0x12, 0x00,             // mov [0012],ax
        0x8b, 0x46, 0x06,             // mov ax,[bp+6]: low word of dwData
        0xa3, 0x14, 0x00,             // mov [0014],ax
        0xff, 0x06, 0x10, 0x00,       // inc word [0010]: invocation count
        0x8b, 0x5e, 0x0a,             // mov bx,[bp+10]: host-visible marker
        0xb8, 0x00, 0x30, 0xcd, 0x21, // mov ax,3000 / int 21h
        0x31, 0xc0,                   // xor ax,ax: BOOL FALSE
        0x5d,                         // pop bp
        0xca, 0x06, 0x00,             // retf 6: checked Pascal return
    ];
    let (mut runtime, owner, data) = fixture(&callback);
    let code = runtime.cpu.regs.cs;
    let mut host = ExitHost::default();
    // MOV/INT end exactly at the segment limit. The third retired instruction
    // must be the newly dispatched callback's PUSH, never the terminal IRET.
    pause(&mut runtime, &mut host, 3);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip()), (code, CALLBACK_IP + 1));
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.toolhelp_task_exit.pending_id().is_some());
    assert!(state.toolhelp_task_exit.has_active_notification_callback());
    assert_eq!(state.toolhelp_notify_frames.len(), 1);
    assert_eq!(state.toolhelp_notify_frames[0].notification, NFY_EXITTASK);
    assert_eq!(state.toolhelp_notify_frames[0].data, 7);
    assert_eq!(state.legacy_cpu_frames.len(), 1);
    let callback_far = (u32::from(code) << 16) | u32::from(CALLBACK_IP);
    assert!(state.toolhelp_notify_frames[0].code_references().any(|far| far == callback_far));
    assert!(state.toolhelp_notify_code_references().any(|far| far == callback_far));
    let code_generation = state.selectors.reference(Selector(code)).unwrap();
    assert!(state.legacy_cpu_frame_owns_selector(code_generation));
    assert!(!state.classic_dde_task_exit_needs_pump());
    assert_eq!(host.terminal_dos_calls, 1);
    assert_eq!(runtime.run_win16_inner(&mut host, 128).unwrap(), 7);
    assert_eq!(word(&runtime, data, 0x10), 1);
    assert_eq!(word(&runtime, data, 0x12), NFY_EXITTASK);
    assert_eq!(word(&runtime, data, 0x14), 7);
    assert_completed(&runtime, &host, owner, &[NFY_EXITTASK]);
}

#[test]
fn active_toolhelp_callback_returns_after_ah4c_before_fifo_exit_notifications() {
    let callback = [
        0x55,                         // push bp
        0x89, 0xe5,                   // mov bp,sp
        0x8b, 0x1e, 0x10, 0x00,       // mov bx,[0010]: log byte index
        0x8b, 0x46, 0x0a,             // mov ax,[bp+10]: notification
        0x89, 0x47, 0x20,             // mov [bx+20],ax
        0x83, 0x06, 0x10, 0x00, 0x02, // add word [0010],2
        0x3d, NFY_TASKIN as u8, 0x00,  // cmp ax,NFY_TASKIN
        0x75, 0x09,                   // jne past terminal INT and return marker
        0xb8, 0x07, 0x4c, 0xcd, 0x21, // mov ax,4c07 / int 21h
        0xff, 0x06, 0x18, 0x00,       // inc word [0018]: terminal ROM IRET returned
        0x8b, 0x5e, 0x0a,             // mov bx,[bp+10]
        0xb8, 0x00, 0x30, 0xcd, 0x21, // DOS version call reports callback marker
        0x31, 0xc0, 0x5d,             // BOOL FALSE / pop bp
        0xca, 0x06, 0x00,             // retf 6
    ];
    let (mut runtime, owner, data) = fixture(&callback);
    let code = runtime.cpu.regs.cs;
    let initial_sp = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let task = state.current_task_handle().unwrap();
    for notification in [NFY_TASKIN, NFY_TASKOUT] {
        assert!(state.toolhelp_notify.enqueue(Win16ToolhelpNotifyEvent {
            task, notification, data: Win16ToolhelpNotifyData::Scalar(0),
            registrations: Vec::new(), termination_id: None, module_root: None,
        }).unwrap());
    }
    // Enter through the real checked dispatcher, with TASKOUT still queued.
    assert!(state.dispatch_pending_toolhelp_notify(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory,
    ).unwrap());
    let mut host = ExitHost::default();
    // Ten guest instructions reach INT 21h; the eleventh executes ROM IRET.
    pause(&mut runtime, &mut host, 11);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip()), (code, CALLBACK_IP + 28));
    assert_eq!(word(&runtime, data, 0x10), 2);
    assert_eq!(word(&runtime, data, 0x18), 0);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.toolhelp_notify_frames.len(), 1);
    assert_eq!(state.toolhelp_notify_frames[0].notification, NFY_TASKIN);
    assert!(state.toolhelp_notify_frames[0].termination_id.is_none());
    assert!(state.toolhelp_task_exit.pending_id().is_some());
    assert!(state.toolhelp_task_exit.has_active_notification_callback());
    assert_eq!(state.legacy_cpu_frames.len(), 1);
    let callback_far = (u32::from(code) << 16) | u32::from(CALLBACK_IP);
    assert!(state.toolhelp_notify_frames[0].code_references().any(|far| far == callback_far));
    assert!(state.toolhelp_notify_code_references().any(|far| far == callback_far));
    let code_generation = state.selectors.reference(Selector(code)).unwrap();
    assert!(state.legacy_cpu_frame_owns_selector(code_generation));
    assert!(!state.classic_dde_task_exit_needs_pump());
    assert_eq!(host.terminal_dos_calls, 1);
    assert_eq!(runtime.run_win16_inner(&mut host, 128).unwrap(), 7);
    assert_eq!(word(&runtime, data, 0x18), 1, "active callback must resume after terminal IRET");
    assert_eq!(word(&runtime, data, 0x10), 6);
    assert_eq!([word(&runtime, data, 0x20), word(&runtime, data, 0x22), word(&runtime, data, 0x24)],
        [NFY_TASKIN, NFY_TASKOUT, NFY_EXITTASK]);
    assert_eq!(runtime.cpu.regs.sp(), initial_sp, "all Pascal callback frames must unwind");
    assert_completed(&runtime, &host, owner, &[NFY_TASKIN, NFY_TASKOUT, NFY_EXITTASK]);
}
