//! MMSYSTEM 602/603: guest timer ids, Pascal frames, and callback arguments.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16CallbackArgumentData,
    Win16GuestCallbackToken, Win16HostMediaTimeOperation, Win16HostMediaTimeResult,
    multimedia_timer_callback_arguments,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, Selector};
use win16_abi::{
    Access, ExportLookupTarget, Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const AX_SENTINEL: u16 = 0xa55a;
const DX_SENTINEL: u16 = 0x5aa5;
const NATIVE_TIMER: u32 = 0x0001_0001;

#[derive(Default)]
struct TimerHost {
    sets: Vec<Win16HostMediaTimeOperation>,
    kills: Vec<u32>,
    refuse: bool,
    kill_code: u32,
    /// `timeGetDevCaps` reply: result, minimum period, maximum period.
    caps: Option<(u32, u32, u32)>,
}

impl DosHost for TimerHost {
    fn read_stdin(&mut self, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _: &[u8], _: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(&mut self, _: &[u8], _: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _: &[u8],
        _: DosFileAccess,
        _: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _: DosHostFile, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _: DosHostFile, _: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(&mut self, _: DosHostFile, _: i32, _: DosSeekOrigin) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _: DosHostFile, _: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(&mut self, _: u8, _: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _: &[u8], _: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _: &[u8], _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for TimerHost {
    fn win16_media_time(
        &mut self,
        operation: Win16HostMediaTimeOperation,
    ) -> Result<Win16HostMediaTimeResult, RuntimeError> {
        match operation {
            Win16HostMediaTimeOperation::SetEvent { .. } => {
                self.sets.push(operation);
                if self.refuse {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "mock timer set failed",
                    ));
                }
                Ok(Win16HostMediaTimeResult::SetEvent {
                    timer: Some(NATIVE_TIMER),
                })
            }
            Win16HostMediaTimeOperation::KillEvent { timer } => {
                self.kills.push(timer);
                Ok(Win16HostMediaTimeResult::Kill(self.kill_code))
            }
            Win16HostMediaTimeOperation::GetDevCaps => {
                let Some((result, minimum_period, maximum_period)) = self.caps else {
                    panic!("unexpected media time operation");
                };
                Ok(Win16HostMediaTimeResult::DevCaps {
                    result,
                    minimum_period,
                    maximum_period,
                })
            }
            _ => panic!("unexpected media time operation"),
        }
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}

impl crate::RuntimeDdeHost for TimerHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for TimerHost {}
impl crate::RuntimeMidiHost for TimerHost {}
impl crate::RuntimeNetbiosHost for TimerHost {}

fn executable_callback(runtime: &mut Runtime) -> u32 {
    let callback = (u32::from(runtime.cpu.regs.cs) << 16) | 0x80;
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(callback).unwrap();
    let physical = state
        .selectors
        .translate(pointer, Access::Execute, 3, &runtime.memory)
        .unwrap();
    runtime.memory.write(physical, &[0xca, 16, 0]).unwrap();
    callback
}

fn arm(runtime: &mut Runtime, ordinal: u16, arguments: &[u8]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("multimedia timer exports use a fixed Pascal frame");
    };
    assert_eq!(cleanup.caller_pop_bytes, 0);
    assert_eq!(usize::from(cleanup.callee_pop_bytes), arguments.len());
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(arguments);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &frame)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX_SENTINEL);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    (return_cs, return_ip, stack + frame.len() as u16)
}

fn set_arguments(procedure: u32, delay: u16, resolution: u16, user: u32, flags: u16) -> Vec<u8> {
    let mut arguments = Vec::from(flags.to_le_bytes());
    arguments.extend_from_slice(&user.to_le_bytes());
    arguments.extend_from_slice(&procedure.to_le_bytes());
    arguments.extend_from_slice(&resolution.to_le_bytes());
    arguments.extend_from_slice(&delay.to_le_bytes());
    arguments
}

fn kill_arguments(timer: u16) -> Vec<u8> {
    timer.to_le_bytes().to_vec()
}

fn dev_caps_arguments(caps: u32, size: u16) -> Vec<u8> {
    let mut arguments = Vec::from(size.to_le_bytes());
    arguments.extend_from_slice(&caps.to_le_bytes());
    arguments
}

fn poison_time_caps(runtime: &mut Runtime) -> u32 {
    let far = (u32::from(runtime.cpu.regs.ds) << 16) | 0x10;
    let state = runtime.win16.as_mut().unwrap();
    state
        .selectors
        .write(
            &mut runtime.memory,
            state.selectors.pointer_from_far(far).unwrap(),
            &[0xa5; 8],
        )
        .unwrap();
    far
}

fn time_caps_bytes(runtime: &Runtime, far: u32) -> [u8; 8] {
    let state = runtime.win16.as_ref().unwrap();
    let mut bytes = [0; 8];
    state
        .selectors
        .read(
            &runtime.memory,
            state.selectors.pointer_from_far(far).unwrap(),
            &mut bytes,
        )
        .unwrap();
    bytes
}

fn dispatch(runtime: &mut Runtime, host: &mut TimerHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

#[test]
fn timer_callback_arguments_are_the_guest_id_user_and_reserved_zeros() {
    assert_eq!(
        multimedia_timer_callback_arguments(0x42, 0x1122_3344),
        [
            Win16CallbackArgumentData::Word(0x42),
            Win16CallbackArgumentData::Word(0),
            Win16CallbackArgumentData::Dword(0x1122_3344),
            Win16CallbackArgumentData::Dword(0),
            Win16CallbackArgumentData::Dword(0),
        ]
    );
}

#[test]
fn time_set_event_returns_a_guest_id_and_kill_uses_the_native_id() {
    let named = lookup_export(b"MMSYSTEM", ExportLookupTarget::Name(b"timeSetEvent")).unwrap();
    let ordinal = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(602)).unwrap();
    assert_eq!(named.id, ordinal.id);
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let procedure = executable_callback(&mut runtime);
    let arguments = set_arguments(procedure, 25, 5, 0xaabb_ccdd, 1);
    let return_to = arm(&mut runtime, 602, &arguments);
    let mut host = TimerHost::default();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    let guest = runtime.cpu.regs.ax();
    assert_ne!(guest, 0);
    assert_ne!(u32::from(guest), NATIVE_TIMER);
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    let Win16HostMediaTimeOperation::SetEvent {
        delay,
        resolution,
        user,
        periodic,
        callback,
        guest_timer,
    } = host.sets[0]
    else {
        panic!("timeSetEvent did not reach the host")
    };
    assert_eq!(
        (delay, resolution, user, periodic, guest_timer),
        (25, 5, 0xaabb_ccdd, true, guest)
    );
    assert_ne!(callback, Win16GuestCallbackToken(u64::from(procedure)));
    assert!(procedure > 0xffff);

    let kill = kill_arguments(guest);
    let return_to = arm(&mut runtime, 603, &kill);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    assert_eq!(host.kills, vec![NATIVE_TIMER]);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );

    let kill = kill_arguments(guest);
    let return_to = arm(&mut runtime, 603, &kill);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 97);
    assert_eq!(host.kills, vec![NATIVE_TIMER]);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
}

#[test]
fn time_set_event_null_and_unpublished_flags_return_null_without_the_host() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let procedure = executable_callback(&mut runtime);
    let mut host = TimerHost::default();
    for (procedure, flags) in [(0, 1), (procedure, 0x0010), (procedure, 0x0020)] {
        let arguments = set_arguments(procedure, 1, 0, 7, flags);
        let return_to = arm(&mut runtime, 602, &arguments);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
        assert_eq!(runtime.cpu.regs.ax(), 0);
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
        assert_eq!(
            (
                runtime.cpu.regs.cs,
                runtime.cpu.regs.ip(),
                runtime.cpu.regs.sp()
            ),
            return_to
        );
    }
    assert!(host.sets.is_empty());
    let return_to = arm(&mut runtime, 603, &kill_arguments(1));
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 97);
    assert!(host.kills.is_empty());
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
}

#[test]
fn time_set_event_one_shot_retires_when_its_callback_is_delivered() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let procedure = executable_callback(&mut runtime);
    let arguments = set_arguments(procedure, 10, 0, 0x55, 0);
    arm(&mut runtime, 602, &arguments);
    let mut host = TimerHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    let guest = runtime.cpu.regs.ax();
    let Win16HostMediaTimeOperation::SetEvent {
        callback,
        periodic,
        guest_timer,
        ..
    } = host.sets[0]
    else {
        panic!("missing set")
    };
    assert!(!periodic);
    assert_eq!(guest_timer, guest);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .note_multimedia_timer_callback_entered(callback, &mut host)
        .unwrap();
    arm(&mut runtime, 603, &kill_arguments(guest));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 97);
    assert_eq!(host.kills, vec![NATIVE_TIMER]);
}

#[test]
fn time_kill_event_keeps_the_record_when_the_host_cannot_cancel() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let procedure = executable_callback(&mut runtime);
    let arguments = set_arguments(procedure, 10, 1, 3, 1);
    arm(&mut runtime, 602, &arguments);
    let mut host = TimerHost {
        kill_code: 97,
        ..TimerHost::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    let guest = runtime.cpu.regs.ax();
    for _ in 0..2 {
        arm(&mut runtime, 603, &kill_arguments(guest));
        dispatch(&mut runtime, &mut host).unwrap();
        assert_eq!(runtime.cpu.regs.ax(), 97);
    }
    assert_eq!(host.kills, vec![NATIVE_TIMER, NATIVE_TIMER]);
}

#[test]
fn time_set_event_drops_the_reservation_when_the_host_fails() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let procedure = executable_callback(&mut runtime);
    let arguments = set_arguments(procedure, 10, 1, 3, 1);
    arm(&mut runtime, 602, &arguments);
    let mut host = TimerHost {
        refuse: true,
        ..TimerHost::default()
    };
    let before = (
        runtime.cpu.regs.cs,
        runtime.cpu.regs.ip(),
        runtime.cpu.regs.sp(),
    );
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::HostFailure
    );
    assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        before
    );
    host.refuse = false;
    arm(&mut runtime, 603, &kill_arguments(1));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 97);
    assert!(host.kills.is_empty());
}

#[test]
fn multimedia_timer_cleanup_preserves_failed_owner_until_retry() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let procedure = executable_callback(&mut runtime);
    arm(&mut runtime, 602, &set_arguments(procedure, 10, 1, 3, 1));
    let mut host = TimerHost {
        kill_code: 97,
        ..TimerHost::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    let guest = runtime.cpu.regs.ax();
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(
        state
            .retire_multimedia_services(&mut host)
            .unwrap_err()
            .kind(),
        Kind::HostFailure
    );
    assert!(state.media_services.timer(guest).is_some());
    assert!(!state.media_services.native_sources_quiescent());
    host.kill_code = 0;
    state.retire_multimedia_services(&mut host).unwrap();
    assert!(state.media_services.timer(guest).is_none());
    assert!(state.media_services.native_sources_quiescent());
    assert_eq!(host.kills, vec![NATIVE_TIMER, NATIVE_TIMER]);
}

#[test]
fn time_get_dev_caps_clamps_the_maximum_and_rejects_an_unrepresentable_minimum() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TIMER.NE").unwrap();
    let far = poison_time_caps(&mut runtime);
    let mut host = TimerHost {
        caps: Some((0, 1, 1000)),
        ..TimerHost::default()
    };
    let return_to = arm(&mut runtime, 604, &dev_caps_arguments(far, 4));
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    let mut expected = [0xa5; 8];
    expected[0..2].copy_from_slice(&1u16.to_le_bytes());
    expected[2..4].copy_from_slice(&1000u16.to_le_bytes());
    assert_eq!(time_caps_bytes(&runtime, far), expected);

    let far = poison_time_caps(&mut runtime);
    host.caps = Some((0, 1, u32::from(u16::MAX)));
    let return_to = arm(&mut runtime, 604, &dev_caps_arguments(far, 4));
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    expected[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(time_caps_bytes(&runtime, far), expected);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );

    let far = poison_time_caps(&mut runtime);
    host.caps = Some((0, 1, 1_000_000));
    let return_to = arm(&mut runtime, 604, &dev_caps_arguments(far, 4));
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    expected[0..2].copy_from_slice(&1u16.to_le_bytes());
    expected[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(time_caps_bytes(&runtime, far), expected);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );

    let far = poison_time_caps(&mut runtime);
    host.caps = Some((0, 65_536, 1));
    let return_to = arm(&mut runtime, 604, &dev_caps_arguments(far, 4));
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 97);
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    assert_eq!(time_caps_bytes(&runtime, far), [0xa5; 8]);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
}
