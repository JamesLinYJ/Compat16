//! MMSYSTEM joystick gates with a fake host. No physical joystick.

use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostJoystickCaps,
    Win16HostJoystickOperation as Operation, Win16HostJoystickResult as Reply,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup, Win16ReturnKind,
    lookup_export,
};

const SENTINEL: u8 = 0x5a;
const OUTPUT_LEN: usize = 96;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Seen {
    Count,
    Caps {
        device: u16,
    },
    Position {
        device: u16,
    },
    ThresholdGet {
        device: u16,
    },
    ThresholdSet {
        device: u16,
        threshold: u16,
    },
    Capture {
        window: u16,
        device: u16,
        period: u16,
        changed: bool,
    },
    Release {
        device: u16,
    },
}

struct JoyHost {
    seen: Vec<Seen>,
    count: u16,
    caps: Win16HostJoystickCaps,
    caps_result: u16,
    position: (u16, u16, u16, u16),
    position_result: u16,
    threshold: u16,
    threshold_result: u16,
    status: u16,
    fail: bool,
    wrong_shape: bool,
}

impl Default for JoyHost {
    fn default() -> Self {
        Self {
            seen: Vec::new(),
            count: 1,
            caps: sample_caps(),
            caps_result: 0,
            position: (0x1111, 0x2222, 0x3333, 0x0005),
            position_result: 0,
            threshold: 40,
            threshold_result: 0,
            status: 0,
            fail: false,
            wrong_shape: false,
        }
    }
}

impl DosHost for JoyHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for JoyHost {
    fn win16_joystick(&mut self, operation: Operation) -> Result<Reply, RuntimeError> {
        if self.fail {
            return Err(RuntimeError::new(Kind::HostFailure, "joystick host failed"));
        }
        if self.wrong_shape {
            return Ok(Reply::Count(0));
        }
        self.seen.push(match operation {
            Operation::DeviceCount => Seen::Count,
            Operation::DevCaps { device } => Seen::Caps { device },
            Operation::Position { device } => Seen::Position { device },
            Operation::ThresholdGet { device } => Seen::ThresholdGet { device },
            Operation::ThresholdSet { device, threshold } => {
                Seen::ThresholdSet { device, threshold }
            }
            Operation::SetCapture {
                window,
                device,
                period,
                changed,
            } => Seen::Capture {
                window,
                device,
                period,
                changed,
            },
            Operation::ReleaseCapture { device } => Seen::Release { device },
        });
        Ok(match operation {
            Operation::DeviceCount => Reply::Count(self.count),
            Operation::DevCaps { .. } => Reply::Caps {
                result: self.caps_result,
                caps: (self.caps_result == 0).then_some(self.caps),
            },
            Operation::Position { .. } => Reply::Position {
                result: self.position_result,
                x: self.position.0,
                y: self.position.1,
                z: self.position.2,
                buttons: self.position.3,
            },
            Operation::ThresholdGet { .. } => Reply::Threshold {
                result: self.threshold_result,
                value: self.threshold,
            },
            Operation::ThresholdSet { .. }
            | Operation::SetCapture { .. }
            | Operation::ReleaseCapture { .. } => Reply::Status(self.status),
        })
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}

impl crate::RuntimeDdeHost for JoyHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for JoyHost {}
impl crate::RuntimeMidiHost for JoyHost {}
impl crate::RuntimeNetbiosHost for JoyHost {}

struct StackArgs(Vec<u8>);

impl StackArgs {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn word(mut self, value: u16) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    fn dword(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
}

fn sample_caps() -> Win16HostJoystickCaps {
    let mut name = [0; 32];
    name[..4].copy_from_slice(b"Pad\0");
    name[4] = 0x11;
    Win16HostJoystickCaps {
        manufacturer: 0x1234,
        product: 0xabcd,
        name,
        x_min: 1,
        x_max: 2,
        y_min: 3,
        y_max: 4,
        z_min: 5,
        z_max: 6,
        buttons: 4,
        period_min: 10,
        period_max: 100,
    }
}

fn encoded_caps(caps: &Win16HostJoystickCaps) -> [u8; 54] {
    let mut bytes = [0; 54];
    bytes[0..2].copy_from_slice(&caps.manufacturer.to_le_bytes());
    bytes[2..4].copy_from_slice(&caps.product.to_le_bytes());
    bytes[4..36].copy_from_slice(&caps.name);
    for (index, word) in [
        caps.x_min,
        caps.x_max,
        caps.y_min,
        caps.y_max,
        caps.z_min,
        caps.z_max,
        caps.buttons,
        caps.period_min,
        caps.period_max,
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 36 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn fixture() -> (Runtime, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\JOY.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            0x10000,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let pointer = SegmentedPointer::new(selector, 0);
    state
        .selectors
        .write(&mut runtime.memory, pointer, &[SENTINEL; OUTPUT_LEN])
        .unwrap();
    (runtime, pointer.far_value())
}

fn read_output(runtime: &Runtime, far: u32) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; OUTPUT_LEN];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn write_output(runtime: &mut Runtime, far: u32, bytes: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
}

fn gate(runtime: &mut Runtime, ordinal: u16, args: StackArgs) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("joystick export {ordinal} is not a fixed Pascal frame");
    };
    assert_eq!(cleanup.caller_pop_bytes, 0);
    assert_eq!(usize::from(cleanup.callee_pop_bytes), args.0.len());
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&args.0);
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0xa1b2_a55a;
    runtime.cpu.regs.edx = 0xc3d4_5aa5;
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(
    runtime: &mut Runtime,
    host: &mut impl RuntimeHost,
) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

fn assert_word(runtime: &Runtime, back: (u16, u16, u16), result: u16) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result));
    assert_eq!(runtime.cpu.regs.edx, 0xc3d4_5aa5);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        back
    );
}

#[test]
fn joystick_ordinals_keep_names_and_word_returns() {
    for (ordinal, name) in [
        (101, "joyGetNumDevs"),
        (102, "joyGetDevCaps"),
        (103, "joyGetPos"),
        (104, "joyGetThreshold"),
        (105, "joyReleaseCapture"),
        (106, "joySetCapture"),
        (107, "joySetThreshold"),
        (109, "joySetCalibration"),
        (110, "joyGetPosEx"),
    ] {
        let by_ordinal = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let by_name =
            lookup_export(b"MMSYSTEM", ExportLookupTarget::Name(name.as_bytes())).unwrap();
        assert_eq!(by_ordinal.id, by_name.id);
        assert_eq!(by_ordinal.return_kind, Win16ReturnKind::Word);
    }
    assert!(lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(108)).is_none());
}

#[test]
fn joy_get_num_devs_returns_the_host_count_in_ax() {
    let (mut runtime, _) = fixture();
    let back = gate(&mut runtime, 101, StackArgs::new());
    let mut host = JoyHost {
        count: 2,
        ..JoyHost::default()
    };
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_word(&runtime, back, 2);
    assert_eq!(host.seen, [Seen::Count]);
}

#[test]
fn joy_get_dev_caps_writes_the_3_1_record_and_stops_at_the_caller_size() {
    let caps = sample_caps();
    let encoded = encoded_caps(&caps);
    let (mut runtime, output) = fixture();
    let back = gate(
        &mut runtime,
        102,
        StackArgs::new().word(54).dword(output).word(1),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(host.seen, [Seen::Caps { device: 1 }]);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..54], &encoded);
    assert_eq!(&bytes[54..], &[SENTINEL; OUTPUT_LEN - 54]);

    let (mut runtime, output) = fixture();
    let back = gate(
        &mut runtime,
        102,
        StackArgs::new().word(4).dword(output).word(0),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(host.seen, [Seen::Caps { device: 0 }]);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..4], &encoded[..4]);
    assert_eq!(&bytes[4..], &[SENTINEL; OUTPUT_LEN - 4]);
}

#[test]
fn joy_get_dev_caps_zero_size_skips_the_host_and_a_bad_pointer_is_parms() {
    let (mut runtime, output) = fixture();
    let back = gate(&mut runtime, 102, StackArgs::new().word(0).dword(0).word(3));
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert!(host.seen.is_empty());
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);

    let (mut runtime, output) = fixture();
    let back = gate(
        &mut runtime,
        102,
        StackArgs::new().word(54).dword(0).word(0),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 165);
    assert!(host.seen.is_empty());
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);
}

#[test]
fn joy_get_dev_caps_host_errors_do_not_write() {
    let (mut runtime, output) = fixture();
    let back = gate(
        &mut runtime,
        102,
        StackArgs::new().word(54).dword(output).word(0),
    );
    let mut host = JoyHost {
        caps_result: 6,
        ..JoyHost::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 6);
    assert_eq!(host.seen, [Seen::Caps { device: 0 }]);
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);

    let (mut runtime, output) = fixture();
    let _back = gate(
        &mut runtime,
        102,
        StackArgs::new().word(54).dword(output).word(0),
    );
    let mut host = JoyHost {
        wrong_shape: true,
        ..JoyHost::default()
    };
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::InternalInvariant
    );
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);

    let (mut runtime, output) = fixture();
    let _back = gate(
        &mut runtime,
        102,
        StackArgs::new().word(54).dword(output).word(0),
    );
    let mut host = JoyHost {
        fail: true,
        ..JoyHost::default()
    };
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::HostFailure
    );
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);
}

#[test]
fn joy_get_pos_and_threshold_write_words_only_on_success() {
    let (mut runtime, output) = fixture();
    let back = gate(&mut runtime, 103, StackArgs::new().dword(output).word(0));
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(host.seen, [Seen::Position { device: 0 }]);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..8], &{
        let mut expected = [0; 8];
        expected[0..2].copy_from_slice(&0x1111_u16.to_le_bytes());
        expected[2..4].copy_from_slice(&0x2222_u16.to_le_bytes());
        expected[4..6].copy_from_slice(&0x3333_u16.to_le_bytes());
        expected[6..8].copy_from_slice(&0x0005_u16.to_le_bytes());
        expected
    });
    assert_eq!(&bytes[8..], &[SENTINEL; OUTPUT_LEN - 8]);

    let (mut runtime, output) = fixture();
    let back = gate(&mut runtime, 103, StackArgs::new().dword(output).word(1));
    let mut host = JoyHost {
        position_result: 167,
        ..JoyHost::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 167);
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);

    let (mut runtime, output) = fixture();
    let back = gate(
        &mut runtime,
        103,
        StackArgs::new().dword(output | 0xfffe).word(0),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 165);
    assert!(host.seen.is_empty());

    let mut host = JoyHost::default();
    let (mut runtime, _) = fixture();
    let back = gate(&mut runtime, 107, StackArgs::new().word(40).word(0));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(
        host.seen,
        [Seen::ThresholdSet {
            device: 0,
            threshold: 40
        }]
    );
    let (mut runtime, output) = fixture();
    let back = gate(&mut runtime, 104, StackArgs::new().dword(output).word(0));
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..2], &40_u16.to_le_bytes());
    assert_eq!(&bytes[2..], &[SENTINEL; OUTPUT_LEN - 2]);
}

#[test]
fn joy_capture_passes_the_guest_window_and_rejects_a_null_window() {
    let (mut runtime, _) = fixture();
    let back = gate(
        &mut runtime,
        106,
        StackArgs::new().word(2).word(25).word(1).word(0x1111),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(
        host.seen,
        [Seen::Capture {
            window: 0x1111,
            device: 1,
            period: 25,
            changed: true,
        }]
    );

    let (mut runtime, _) = fixture();
    let back = gate(
        &mut runtime,
        106,
        StackArgs::new().word(0).word(25).word(1).word(0x2222),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(
        host.seen,
        [Seen::Capture {
            window: 0x2222,
            device: 1,
            period: 25,
            changed: false,
        }]
    );

    let (mut runtime, _) = fixture();
    let back = gate(
        &mut runtime,
        106,
        StackArgs::new().word(0).word(25).word(1).word(0),
    );
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 165);
    assert!(host.seen.is_empty());

    let (mut runtime, _) = fixture();
    let back = gate(&mut runtime, 105, StackArgs::new().word(1));
    let mut host = JoyHost {
        status: 167,
        ..JoyHost::default()
    };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 167);
    assert_eq!(host.seen, [Seen::Release { device: 1 }]);
}

#[test]
fn joy_set_calibration_returns_nocando_without_a_host_call() {
    let (mut runtime, _) = fixture();
    let back = gate(&mut runtime, 109, StackArgs::new().word(0));
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 166);
    assert!(host.seen.is_empty());
}

#[test]
fn joy_get_pos_ex_writes_only_requested_info_axes() {
    let (mut runtime, output) = fixture();
    let mut header = [SENTINEL; 52];
    header[0..4].copy_from_slice(&52_u32.to_le_bytes());
    header[4..8].copy_from_slice(&(0x0000_0001_u32 | 0x0000_0080).to_le_bytes());
    write_output(&mut runtime, output, &header);
    let back = gate(&mut runtime, 110, StackArgs::new().dword(output).word(0));
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 0);
    assert_eq!(host.seen, [Seen::Position { device: 0 }]);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[0..8], &header[0..8]);
    assert_eq!(&bytes[8..12], &u32::from(0x1111_u16).to_le_bytes());
    assert_eq!(&bytes[12..32], &[SENTINEL; 20]);
    assert_eq!(&bytes[32..36], &u32::from(0x0005_u16).to_le_bytes());
    assert_eq!(&bytes[36..52], &[SENTINEL; 16]);

    let (mut runtime, output) = fixture();
    let mut header = [SENTINEL; 52];
    header[0..4].copy_from_slice(&52_u32.to_le_bytes());
    header[4..8].copy_from_slice(&(0x0000_0001_u32 | 0x0000_0008).to_le_bytes());
    write_output(&mut runtime, output, &header);
    let back = gate(&mut runtime, 110, StackArgs::new().dword(output).word(0));
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 166);
    assert!(host.seen.is_empty());
    assert_eq!(&read_output(&runtime, output)[..52], &header);

    let (mut runtime, output) = fixture();
    let mut header = [SENTINEL; 8];
    header[0..4].copy_from_slice(&51_u32.to_le_bytes());
    write_output(&mut runtime, output, &header);
    let back = gate(&mut runtime, 110, StackArgs::new().dword(output).word(0));
    let mut host = JoyHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_word(&runtime, back, 165);
    assert!(host.seen.is_empty());
}

#[test]
fn default_host_reports_no_joystick_driver() {
    let (mut runtime, _) = fixture();
    let back = gate(&mut runtime, 101, StackArgs::new());
    dispatch(&mut runtime, &mut NoHost).unwrap();
    assert_word(&runtime, back, 0);

    let (mut runtime, output) = fixture();
    let back = gate(&mut runtime, 103, StackArgs::new().dword(output).word(0));
    dispatch(&mut runtime, &mut NoHost).unwrap();
    assert_word(&runtime, back, 6);
    assert_eq!(read_output(&runtime, output), [SENTINEL; OUTPUT_LEN]);

    let (mut runtime, _) = fixture();
    let back = gate(
        &mut runtime,
        106,
        StackArgs::new().word(1).word(10).word(0).word(0x20),
    );
    dispatch(&mut runtime, &mut NoHost).unwrap();
    assert_word(&runtime, back, 6);
}
