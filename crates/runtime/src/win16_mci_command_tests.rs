//! MCI command ordinals 701, 702, 703, 706, and 712 through the service gate.

use std::collections::VecDeque;

use super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16HostMciCall, Win16HostMciDevice, Win16HostMciOutput,
    Win16HostMciParameters, Win16HostMciResult, Win16HostMciStep, Win16HostMciTarget,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, SelectorRef, lookup_export};

const BASE: u32 = 0x80000;
const EAX_SENTINEL: u32 = 0x1357_a55a;
const EDX_SENTINEL: u32 = 0x2468_5aa5;
const DX_WORD: u16 = (EDX_SENTINEL & 0xffff) as u16;
const MCI_OPEN: u16 = 0x0803;
const MCI_CLOSE: u16 = 0x0804;
const MCI_PLAY: u16 = 0x0806;
const MCI_SYSINFO: u16 = 0x0810;
const MCI_BREAK: u16 = 0x0811;
const MCI_WHERE: u16 = 0x0843;
const MCI_NOTIFY: u32 = 1;
const MCI_SYSINFO_QUANTITY: u32 = 0x0100;
const MCI_BREAK_KEY: u32 = 0x0100;
const MCI_ALL_DEVICE_ID: u16 = 0xffff;
const MCIERR_INVALID_DEVICE_ID: u16 = 257;
const MCIERR_MISSING_COMMAND_STRING: u16 = 267;
const MCIERR_PARAM_OVERFLOW: u16 = 268;
const MCIERR_MISSING_DEVICE_NAME: u32 = 292;
const MCIERR_NO_CLOSING_QUOTE: u16 = 294;
const MCIERR_NULL_PARAMETER_BLOCK: u16 = 297;
const MCIERR_NEW_REQUIRES_ALIAS: u32 = 299;

const DEVICE: Win16HostMciDevice = Win16HostMciDevice {
    token: 7,
    generation: 1,
};

struct MciHost {
    calls: Vec<Win16HostMciCall>,
    pending: VecDeque<Win16HostMciResult>,
}

impl MciHost {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    fn enqueue(&mut self, result: Win16HostMciResult) {
        self.pending.push_back(result);
    }
}

impl DosHost for MciHost {
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

impl RuntimeHost for MciHost {
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

impl crate::RuntimeDdeHost for MciHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for MciHost {
    fn win16_mci_call(&mut self, call: Win16HostMciCall) -> Result<Win16HostMciStep, RuntimeError> {
        let result = self
            .pending
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected MCI host call: {call:?}"));
        self.calls.push(call);
        Ok(Win16HostMciStep::Complete(result))
    }
}
impl crate::RuntimeMidiHost for MciHost {}
impl crate::RuntimeNetbiosHost for MciHost {}

fn runtime() -> (Runtime, SelectorRef) {
    let bytes = vec![0xA5; 0x400];
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\MCI.NE").unwrap();
    runtime
        .memory
        .write_physical(PhysAddr(BASE), &bytes)
        .unwrap();
    let selector = runtime
        .win16
        .as_mut()
        .unwrap()
        .selectors
        .alloc_block(
            PhysAddr(BASE),
            bytes.len() as u32,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    (runtime, selector)
}

fn far(selector: SelectorRef, offset: u16) -> u32 {
    SegmentedPointer::new(selector, offset).far_value()
}

fn word(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}
fn dword(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

fn write_at(runtime: &mut Runtime, offset: usize, bytes: &[u8]) {
    runtime
        .memory
        .write_physical(PhysAddr(BASE + offset as u32), bytes)
        .unwrap();
}

fn place(runtime: &mut Runtime, offset: usize, text: &[u8]) {
    write_at(runtime, offset, text);
    write_at(runtime, offset + text.len(), &[0]);
}

fn read_at(runtime: &Runtime, offset: usize, bytes: &mut [u8]) {
    runtime
        .memory
        .read_physical(PhysAddr(BASE + offset as u32), bytes)
        .unwrap();
}

fn fill(runtime: &mut Runtime, offset: usize, byte: u8, length: usize) {
    write_at(runtime, offset, &vec![byte; length]);
}

fn invoke(runtime: &mut Runtime, host: &mut MciHost, ordinal: u16, args: &[&[u8]]) -> (u16, u16) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    for argument in args.iter().rev() {
        frame.extend_from_slice(argument);
    }
    let state = runtime.win16.as_mut().unwrap();
    let stack_pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, stack_pointer, &frame)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    assert_eq!(
        runtime
            .win16
            .as_mut()
            .unwrap()
            .dispatch(
                &mut runtime.cpu,
                &mut runtime.memory,
                &mut runtime.dos,
                host,
                0,
            )
            .unwrap(),
        None
    );
    let ax = runtime.cpu.regs.ax();
    let dx = runtime.cpu.regs.dx();
    assert_eq!(runtime.cpu.regs.cs, return_cs);
    assert_eq!(runtime.cpu.regs.ip(), return_ip);
    assert_eq!(runtime.cpu.regs.sp(), stack + frame.len() as u16);
    (ax, dx)
}

fn string_receipt(bytes: Vec<u8>, closed_all: bool) -> Win16HostMciResult {
    Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::StringCommand {
            bytes,
            opened: None,
            closed: None,
            closed_all,
            unsupported_owner: false,
        },
    }
}

fn scalar(code: u32) -> Win16HostMciResult {
    Win16HostMciResult {
        return_value: code,
        output: Win16HostMciOutput::Scalar(0),
    }
}

fn send_string(
    runtime: &mut Runtime,
    host: &mut MciHost,
    selector: SelectorRef,
    command: u16,
    output: u16,
    capacity: u16,
) -> (u16, u16) {
    invoke(
        runtime,
        host,
        702,
        &[
            &dword(far(selector, command)),
            &dword(far(selector, output)),
            &word(capacity),
            &word(0),
        ],
    )
}

#[test]
fn string_failures_clear_the_return_buffer_and_execute_is_false() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    fill(&mut runtime, 0, 0x5A, 8);
    place(&mut runtime, 0x20, b"");
    let (ax, dx) = send_string(&mut runtime, &mut host, selector, 0x20, 0, 8);
    assert_eq!((ax, dx), (MCIERR_MISSING_COMMAND_STRING, 0));
    let mut buffer = [0; 8];
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, [0; 8]);
    assert!(host.calls.is_empty());

    fill(&mut runtime, 0, 0x5A, 8);
    place(&mut runtime, 0x30, b"open \"abc");
    let (ax, dx) = send_string(&mut runtime, &mut host, selector, 0x30, 0, 8);
    assert_eq!((ax, dx), (MCIERR_NO_CLOSING_QUOTE, 0));
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, [0; 8]);
    assert!(host.calls.is_empty());

    let (ax, dx) = invoke(&mut runtime, &mut host, 712, &[&dword(far(selector, 0x20))]);
    assert_eq!((ax, dx), (0, DX_WORD));
    assert!(host.calls.is_empty());
}

#[test]
fn open_without_an_alias_returns_the_host_error() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    fill(&mut runtime, 0, 0x5A, 8);
    place(&mut runtime, 0x40, b"open");
    place(&mut runtime, 0x50, b"open new type waveaudio");
    host.enqueue(scalar(MCIERR_MISSING_DEVICE_NAME));
    let (ax, dx) = send_string(&mut runtime, &mut host, selector, 0x40, 0, 8);
    assert_eq!((ax, dx), (MCIERR_MISSING_DEVICE_NAME as u16, 0));
    let mut buffer = [0; 8];
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, [0; 8]);

    fill(&mut runtime, 0, 0x5A, 8);
    host.enqueue(scalar(MCIERR_NEW_REQUIRES_ALIAS));
    let (ax, dx) = send_string(&mut runtime, &mut host, selector, 0x50, 0, 8);
    assert_eq!((ax, dx), (MCIERR_NEW_REQUIRES_ALIAS as u16, 0));
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, [0; 8]);
    assert!(matches!(
        &host.calls[0],
        Win16HostMciCall::SendString { command, callback_target: None, .. } if command == b"open"
    ));
    assert!(matches!(
        &host.calls[1],
        Win16HostMciCall::SendString { command, .. } if command == b"open new type waveaudio"
    ));
}

#[test]
fn close_all_notify_reaches_the_host() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    fill(&mut runtime, 0, 0x5A, 4);
    place(&mut runtime, 0x80, b"close all notify");
    host.enqueue(string_receipt(vec![0; 4], true));
    let (ax, dx) = send_string(&mut runtime, &mut host, selector, 0x80, 0, 4);
    assert_eq!((ax, dx), (0, 0));
    let mut buffer = [0; 4];
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, [0; 4]);
    assert!(matches!(
        &host.calls[0],
        Win16HostMciCall::SendString { command, callback_target: None, .. }
            if command == b"close all notify"
    ));

    host.enqueue(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::None,
    });
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[
            &word(MCI_ALL_DEVICE_ID),
            &word(MCI_CLOSE),
            &dword(MCI_NOTIFY),
            &dword(0),
        ],
    );
    assert_eq!((ax, dx), (0, 0));
    assert!(matches!(
        &host.calls[1],
        Win16HostMciCall::SendCommand {
            target: Win16HostMciTarget::All,
            message: MCI_CLOSE,
            flags: MCI_NOTIFY,
            parameters: Win16HostMciParameters::Null,
            notify_target: None,
        }
    ));
}

#[test]
fn null_parameter_block_and_short_quantity_do_not_call_the_host() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[&word(0), &word(MCI_OPEN), &dword(0), &dword(0)],
    );
    assert_eq!((ax, dx), (MCIERR_NULL_PARAMETER_BLOCK, 0));

    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[&word(0), &word(MCI_PLAY), &dword(0), &dword(0)],
    );
    assert_eq!((ax, dx), (MCIERR_INVALID_DEVICE_ID, 0));

    fill(&mut runtime, 0x10, 0x5A, 8);
    let output = far(selector, 0x10);
    let mut record = [0_u8; 20];
    record[4..8].copy_from_slice(&output.to_le_bytes());
    record[8..12].copy_from_slice(&3_u32.to_le_bytes());
    write_at(&mut runtime, 0x100, &record);
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[
            &word(MCI_ALL_DEVICE_ID),
            &word(MCI_SYSINFO),
            &dword(MCI_SYSINFO_QUANTITY),
            &dword(far(selector, 0x100)),
        ],
    );
    assert_eq!((ax, dx), (MCIERR_PARAM_OVERFLOW, 0));
    let mut unchanged = [0; 8];
    read_at(&runtime, 0x10, &mut unchanged);
    assert_eq!(unchanged, [0x5A; 8]);
    assert!(host.calls.is_empty());
}

#[test]
fn device_id_and_error_string_follow_the_host_result() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    place(&mut runtime, 0xC0, b"all");
    place(&mut runtime, 0xD0, b"nope");
    host.enqueue(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::All,
    });
    let (ax, dx) = invoke(&mut runtime, &mut host, 703, &[&dword(far(selector, 0xC0))]);
    assert_eq!((ax, dx), (MCI_ALL_DEVICE_ID, DX_WORD));
    host.enqueue(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::None,
    });
    let (ax, dx) = invoke(&mut runtime, &mut host, 703, &[&dword(far(selector, 0xD0))]);
    assert_eq!((ax, dx), (0, DX_WORD));

    fill(&mut runtime, 0, 0x5A, 8);
    host.enqueue(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::None,
    });
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        706,
        &[&dword(1), &dword(far(selector, 0)), &word(8)],
    );
    assert_eq!((ax, dx), (0, DX_WORD));
    let mut buffer = [0; 8];
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, [0x5A; 8]);

    let text = *b"bad id\0\0";
    host.enqueue(Win16HostMciResult {
        return_value: 1,
        output: Win16HostMciOutput::Bytes(text.to_vec()),
    });
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        706,
        &[&dword(257), &dword(far(selector, 0)), &word(8)],
    );
    assert_eq!((ax, dx), (1, DX_WORD));
    read_at(&runtime, 0, &mut buffer);
    assert_eq!(buffer, text);
    assert!(matches!(
        &host.calls[2],
        Win16HostMciCall::GetErrorString {
            error: 1,
            capacity: Some(8)
        }
    ));
    assert!(matches!(
        &host.calls[3],
        Win16HostMciCall::GetErrorString {
            error: 257,
            capacity: Some(8)
        }
    ));
}

#[test]
fn execute_projects_success_and_failure_to_bool() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    place(&mut runtime, 0xE0, b"play x");
    host.enqueue(string_receipt(Vec::new(), false));
    let (ax, dx) = invoke(&mut runtime, &mut host, 712, &[&dword(far(selector, 0xE0))]);
    assert_eq!((ax, dx), (1, DX_WORD));
    host.enqueue(scalar(261));
    let (ax, dx) = invoke(&mut runtime, &mut host, 712, &[&dword(far(selector, 0xE0))]);
    assert_eq!((ax, dx), (0, DX_WORD));
    assert!(matches!(
        &host.calls[0],
        Win16HostMciCall::SendString { command, output_capacity: None, .. } if command == b"play x"
    ));
}

#[test]
fn break_key_sign_extends_and_where_overflow_preserves_the_rect() {
    let (mut runtime, selector) = runtime();
    let mut host = MciHost::new();
    write_at(&mut runtime, 0x140, &[0; 20]);
    host.enqueue(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::Device {
            device: DEVICE,
            device_type: Some(522),
        },
    });
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[
            &word(0),
            &word(MCI_OPEN),
            &dword(0),
            &dword(far(selector, 0x140)),
        ],
    );
    assert_eq!((ax, dx), (0, 0));
    let mut id = [0; 2];
    read_at(&runtime, 0x144, &mut id);
    assert_eq!(u16::from_le_bytes(id), 1);

    let mut record = [0_u8; 12];
    record[4..6].copy_from_slice(&0xffff_u16.to_le_bytes());
    write_at(&mut runtime, 0x160, &record);
    host.enqueue(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::None,
    });
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[
            &word(1),
            &word(MCI_BREAK),
            &dword(MCI_BREAK_KEY),
            &dword(far(selector, 0x160)),
        ],
    );
    assert_eq!((ax, dx), (0, 0));
    assert!(matches!(
        &host.calls[1],
        Win16HostMciCall::SendCommand {
            target: Win16HostMciTarget::Device(DEVICE),
            message: MCI_BREAK,
            flags: MCI_BREAK_KEY,
            parameters: Win16HostMciParameters::Break {
                virtual_key: -1,
                window: None
            },
            notify_target: None,
        }
    ));

    fill(&mut runtime, 0x180, 0x5A, 12);
    host.enqueue(scalar(u32::from(MCIERR_PARAM_OVERFLOW)));
    let (ax, dx) = invoke(
        &mut runtime,
        &mut host,
        701,
        &[
            &word(1),
            &word(MCI_WHERE),
            &dword(0),
            &dword(far(selector, 0x180)),
        ],
    );
    assert_eq!((ax, dx), (MCIERR_PARAM_OVERFLOW, 0));
    let mut rect = [0; 12];
    read_at(&runtime, 0x180, &mut rect);
    assert_eq!(rect, [0x5A; 12]);
}
