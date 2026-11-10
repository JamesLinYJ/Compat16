//! USER communications service gate with a host that only records transfers.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostCommConfig,
    Win16HostCommControl, Win16HostCommDevice, Win16HostCommLine, Win16HostCommLines,
    Win16HostCommPort, Win16HostCommQueue, win16_comm_device_is_serial,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::comm_abi::{CBR_2400, CBR_9600, CSTF_EOF, EV_RXCHAR, EV_RXFLAG, EV_TXEMPTY};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, lookup_export};

const DX: u16 = 0x5aa5;
const TOKEN: u64 = 0x1000_0001;

struct CommHost {
    opens: Vec<(Win16HostCommDevice, u16, u16)>,
    reads: Vec<(Win16HostCommPort, usize)>,
    writes: Vec<(Win16HostCommPort, Vec<u8>)>,
    closed: Vec<Win16HostCommPort>,
    pending: Vec<u8>,
    fail_open: Option<RuntimeError>,
    token: Win16HostCommPort,
    device: Option<Win16HostCommDevice>,
    configs: Vec<(Win16HostCommPort, Win16HostCommConfig)>,
    controls: Vec<(Win16HostCommPort, Win16HostCommControl)>,
    flushes: Vec<(Win16HostCommPort, Win16HostCommQueue)>,
    fail_serial: bool,
    fail_close: bool,
    lines: Win16HostCommLines,
}

impl CommHost {
    fn new() -> Self {
        Self {
            opens: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
            closed: Vec::new(),
            pending: Vec::new(),
            fail_open: None,
            token: Win16HostCommPort(TOKEN),
            device: None,
            configs: Vec::new(),
            controls: Vec::new(),
            flushes: Vec::new(),
            fail_serial: false,
            fail_close: false,
            lines: Win16HostCommLines {
                cts: true,
                dsr: true,
                rlsd: true,
            },
        }
    }

    fn reject_serial(&self) -> Result<(), RuntimeError> {
        let device = self.device.expect("serial control follows an open");
        if !win16_comm_device_is_serial(device) {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "LPT handle does not accept serial control",
            ));
        }
        if self.fail_serial {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "device rejected serial control",
            ));
        }
        Ok(())
    }
}

impl DosHost for CommHost {
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
        text_codec::CodePage::CP437
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

impl RuntimeHost for CommHost {
    fn win16_comm_open(
        &mut self,
        device: Win16HostCommDevice,
        in_queue: u16,
        out_queue: u16,
    ) -> Result<Win16HostCommPort, RuntimeError> {
        self.opens.push((device, in_queue, out_queue));
        if let Some(error) = self.fail_open.take() {
            return Err(error);
        }
        self.device = Some(device);
        Ok(self.token)
    }

    fn win16_comm_read(
        &mut self,
        port: Win16HostCommPort,
        output: &mut [u8],
    ) -> Result<usize, RuntimeError> {
        self.reads.push((port, output.len()));
        let count = self.pending.len().min(output.len());
        output[..count].copy_from_slice(&self.pending[..count]);
        self.pending.drain(..count);
        Ok(count)
    }

    fn win16_comm_write(
        &mut self,
        port: Win16HostCommPort,
        input: &[u8],
    ) -> Result<usize, RuntimeError> {
        self.writes.push((port, input.to_vec()));
        Ok(input.len())
    }

    fn win16_comm_close(&mut self, port: Win16HostCommPort) -> Result<(), RuntimeError> {
        if self.fail_close {
            return Err(RuntimeError::new(Kind::HostFailure, "comm close failed"));
        }
        self.closed.push(port);
        Ok(())
    }

    fn win16_comm_configure(
        &mut self,
        port: Win16HostCommPort,
        config: &Win16HostCommConfig,
    ) -> Result<(), RuntimeError> {
        self.configs.push((port, *config));
        self.reject_serial()
    }

    fn win16_comm_control(
        &mut self,
        port: Win16HostCommPort,
        control: Win16HostCommControl,
    ) -> Result<(), RuntimeError> {
        self.controls.push((port, control));
        self.reject_serial()
    }

    fn win16_comm_flush(
        &mut self,
        port: Win16HostCommPort,
        queue: Win16HostCommQueue,
    ) -> Result<(), RuntimeError> {
        self.flushes.push((port, queue));
        self.reject_serial()
    }

    fn win16_comm_lines(
        &mut self,
        _port: Win16HostCommPort,
    ) -> Result<Win16HostCommLines, RuntimeError> {
        Ok(self.lines)
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

impl crate::RuntimeDdeHost for CommHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for CommHost {}
impl crate::RuntimeMidiHost for CommHost {}
impl crate::RuntimeNetbiosHost for CommHost {}

enum Slot {
    Word(u16),
    Dword(u32),
}

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\COMM.NE").unwrap()
}

fn guest(runtime: &mut Runtime, base: u32, bytes: &[u8]) -> u32 {
    runtime
        .memory
        .write_physical(PhysAddr(base), bytes)
        .unwrap();
    let selector = runtime
        .win16
        .as_mut()
        .unwrap()
        .selectors
        .alloc_block(
            PhysAddr(base),
            bytes.len() as u32,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    SegmentedPointer::new(selector, 0).far_value()
}

fn read_guest(runtime: &Runtime, far: u32, len: usize) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; len];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn call(runtime: &mut Runtime, host: &mut CommHost, ordinal: u16, slots: &[Slot]) -> (u16, u16) {
    runtime.cpu.regs.set_sp(0x80);
    let return_cs = runtime.cpu.regs.cs;
    let mut frame = Vec::from(0x12_u16.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    for slot in slots.iter().rev() {
        match slot {
            Slot::Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
            Slot::Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
        }
    }
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), 0x80)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &frame)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap(),
    ));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_dx(DX);
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
        .unwrap();
    assert_eq!(runtime.cpu.regs.cs, return_cs);
    assert_eq!(runtime.cpu.regs.ip(), 0x12);
    assert_eq!(runtime.cpu.regs.sp(), 0x80 + frame.len() as u16);
    (runtime.cpu.regs.ax(), runtime.cpu.regs.dx())
}

#[test]
fn open_write_read_close_records_the_host_token_not_the_guest_id() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let device = guest(&mut runtime, 0x8_0000, b"COM1:\0");
    let source = guest(&mut runtime, 0x8_0100, b"Hi");
    let output = guest(&mut runtime, 0x8_0200, &[0xa5; 4]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!((ax, dx), (0, DX));
    assert_eq!(host.opens, vec![(Win16HostCommDevice::Com(1), 64, 32)]);
    assert_ne!(host.token.0 & 0xffff, 0);
    assert_ne!(u64::from(ax), host.token.0);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!((ax, dx), (0xfffe, DX));
    assert_eq!(host.opens.len(), 1);

    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        208,
        &[Slot::Word(0), Slot::Word(EV_RXCHAR | EV_TXEMPTY)],
    );
    assert_eq!(ax, 0);
    assert_ne!(dx, 0);
    let event = (u32::from(dx) << 16) | u32::from(ax);
    assert_eq!(read_guest(&runtime, event, 2), [0, 0]);

    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        205,
        &[Slot::Word(0), Slot::Dword(source), Slot::Word(2)],
    );
    assert_eq!((ax, dx), (2, DX));
    assert_eq!(host.writes, vec![(host.token, b"Hi".to_vec())]);
    assert_eq!(read_guest(&runtime, event, 2), EV_TXEMPTY.to_le_bytes());

    host.pending = b"AB".to_vec();
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        204,
        &[Slot::Word(0), Slot::Dword(output), Slot::Word(4)],
    );
    assert_eq!((ax, dx), (2, DX));
    assert_eq!(host.reads, vec![(host.token, 4)]);
    assert_eq!(read_guest(&runtime, output, 4), b"AB\xa5\xa5");
    assert_eq!(
        read_guest(&runtime, event, 2),
        (EV_RXCHAR | EV_TXEMPTY).to_le_bytes()
    );

    let (ax, dx) = call(&mut runtime, &mut host, 207, &[Slot::Word(0)]);
    assert_eq!((ax, dx), (0, DX));
    assert_eq!(host.closed, vec![host.token]);
    let (ax, dx) = call(&mut runtime, &mut host, 207, &[Slot::Word(0)]);
    assert_eq!((ax, dx), (0xfffd, DX));
    assert_eq!(host.closed.len(), 1);
}

#[test]
fn bad_name_lpt_and_missing_device_do_not_publish_a_host_pointer() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let bad = guest(&mut runtime, 0x8_0000, b"COM10\0");
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(bad), Slot::Word(1), Slot::Word(1)],
    );
    assert_eq!((ax, dx), (0xffff, DX));
    assert!(host.opens.is_empty());

    let lpt = guest(&mut runtime, 0x8_0100, b"LPT1:\0");
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(lpt), Slot::Word(8), Slot::Word(8)],
    );
    assert_eq!((ax, dx), (0x80, DX));
    assert_eq!(host.opens, vec![(Win16HostCommDevice::Lpt(1), 8, 8)]);
    let (ax, _) = call(&mut runtime, &mut host, 207, &[Slot::Word(0x80)]);
    assert_eq!(ax, 0);
    assert_eq!(host.closed, vec![Win16HostCommPort(TOKEN)]);

    host.fail_open = Some(RuntimeError::new(Kind::HostFailure, "missing device"));
    let com = guest(&mut runtime, 0x8_0200, b"COM2\0");
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(com), Slot::Word(4), Slot::Word(4)],
    );
    assert_eq!((ax, dx), (0xfffa, DX));
    assert_eq!(host.closed, vec![Win16HostCommPort(TOKEN)]);
    let (ax, _) = call(&mut runtime, &mut host, 207, &[Slot::Word(1)]);
    assert_eq!(ax, 0xfffd);
    assert_eq!(host.closed.len(), 1);
}

#[test]
fn escape_widths_and_build_dcb_stay_inside_the_guest() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        214,
        &[Slot::Word(0), Slot::Word(9)],
    );
    assert_eq!((ax, dx), (8, 0));
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        214,
        &[Slot::Word(0), Slot::Word(8)],
    );
    assert_eq!((ax, dx), (0x82, 0));
    let device = guest(&mut runtime, 0x8_0000, b"COM1\0");
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(16), Slot::Word(16)],
    );
    assert_eq!(ax, 0);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        214,
        &[Slot::Word(0), Slot::Word(10)],
    );
    assert_eq!((ax, dx), (0xfffa, 0xffff));
    assert!(host.reads.is_empty() && host.writes.is_empty());

    let definition = guest(&mut runtime, 0x8_0100, b"COM2:2400,e,7,2\0");
    let dcb = guest(&mut runtime, 0x8_0200, &[0xa5; 25]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        213,
        &[Slot::Dword(definition), Slot::Dword(dcb)],
    );
    assert_eq!((ax, dx), (0, DX));
    let bytes = read_guest(&runtime, dcb, 25);
    assert_eq!(bytes[0], 1);
    assert_eq!(u16::from_le_bytes([bytes[1], bytes[2]]), CBR_2400);
    assert_eq!((bytes[3], bytes[4], bytes[5]), (7, 2, 2));
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        245,
        &[
            Slot::Word(0),
            Slot::Word(0x1234),
            Slot::Word(1),
            Slot::Word(2),
        ],
    );
    assert_eq!((ax, dx), (1, DX));
    assert_eq!(host.closed, Vec::<Win16HostCommPort>::new());
}

fn packed_dcb(id: u8, flags: u16, xoff: u8, tx_delay: u16) -> [u8; 25] {
    let mut dcb = [0; 25];
    dcb[0] = id;
    dcb[1..3].copy_from_slice(&CBR_2400.to_le_bytes());
    dcb[3] = 7;
    dcb[4] = 2;
    dcb[5] = 2;
    dcb[12..14].copy_from_slice(&flags.to_le_bytes());
    dcb[14] = 0x11;
    dcb[15] = xoff;
    dcb[23..25].copy_from_slice(&tx_delay.to_le_bytes());
    dcb
}

#[test]
fn serial_timeouts_and_line_control_apply_only_to_com() {
    assert!(win16_comm_device_is_serial(Win16HostCommDevice::Com(1)));
    assert!(!win16_comm_device_is_serial(Win16HostCommDevice::Lpt(1)));
}

#[test]
fn set_state_break_and_flush_reach_the_host_or_keep_the_previous_record() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let device = guest(&mut runtime, 0x8_0000, b"COM1:\0");
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!((ax, dx), (0, DX));
    let state = guest(&mut runtime, 0x8_1000, &[0xa5; 25]);
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        202,
        &[Slot::Word(0), Slot::Dword(state)],
    );
    assert_eq!(ax, 0);
    let initial = read_guest(&runtime, state, 25);
    assert_eq!(u16::from_le_bytes([initial[1], initial[2]]), CBR_9600);
    assert_eq!((initial[3], initial[4], initial[5]), (7, 2, 0));
    assert_eq!(u16::from_le_bytes([initial[12], initial[13]]), 1);
    assert_eq!(u16::from_le_bytes([initial[16], initial[17]]), 10);
    assert_eq!(u16::from_le_bytes([initial[18], initial[19]]), 10);
    assert_eq!(host.configs.len(), 1);

    let mut bad_parity = packed_dcb(0, 1, 0x13, 0);
    bad_parity[4] = 9;
    let unsupported = guest(&mut runtime, 0x8_1100, &bad_parity);
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(unsupported)]);
    assert_eq!((ax, dx), (0xfffb, DX));
    assert_eq!(host.configs.len(), 1);

    let same_xon = guest(&mut runtime, 0x8_1200, &packed_dcb(0, 1, 0x11, 0));
    let (ax, _) = call(&mut runtime, &mut host, 201, &[Slot::Dword(same_xon)]);
    assert_eq!(ax, 0xfffb);
    assert_eq!(host.configs.len(), 1);

    let flags = 1 | (1 << 1) | (1 << 8) | (1 << 13);
    let requested = guest(&mut runtime, 0x8_1300, &packed_dcb(0, flags, 0x13, 0));
    host.fail_serial = true;
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(requested)]);
    assert_eq!((ax, dx), (0xfffa, DX));
    assert_eq!(host.configs.len(), 2);
    assert_eq!(host.configs[1].0, host.token);
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        202,
        &[Slot::Word(0), Slot::Dword(state)],
    );
    assert_eq!(ax, 0);
    assert_eq!(read_guest(&runtime, state, 25), initial);

    host.fail_serial = false;
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(requested)]);
    assert_eq!((ax, dx), (0, DX));
    let applied = &host.configs[2].1;
    assert_eq!(
        (
            applied.baud_rate,
            applied.byte_size,
            applied.parity,
            applied.stop_bits,
            applied.binary,
            applied.rts,
            applied.dtr,
            applied.xon_output,
            applied.xon_char,
            applied.xoff_char,
        ),
        (
            2400,
            7,
            2,
            2,
            true,
            Win16HostCommLine::Disable,
            Win16HostCommLine::Handshake,
            true,
            0x11,
            0x13,
        )
    );
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        202,
        &[Slot::Word(0), Slot::Dword(state)],
    );
    assert_eq!(ax, 0);
    let stored = read_guest(&runtime, state, 25);
    assert_eq!(u16::from_le_bytes([stored[1], stored[2]]), CBR_2400);
    assert_eq!((stored[3], stored[4], stored[5]), (7, 2, 2));

    let pushed = guest(&mut runtime, 0x8_1400, &[0xa5]);
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        212,
        &[Slot::Word(0), Slot::Word(0x41)],
    );
    assert_eq!(ax, 0);
    host.fail_serial = true;
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        215,
        &[Slot::Word(0), Slot::Word(1)],
    );
    assert_eq!((ax, dx), (0xfffa, DX));
    assert_eq!(
        host.flushes,
        vec![(host.token, Win16HostCommQueue::Receive)]
    );
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        204,
        &[Slot::Word(0), Slot::Dword(pushed), Slot::Word(1)],
    );
    assert_eq!(ax, 1);
    assert_eq!(read_guest(&runtime, pushed, 1), [0x41]);
    assert!(host.reads.is_empty());

    host.fail_serial = false;
    let (ax, dx) = call(&mut runtime, &mut host, 210, &[Slot::Word(0)]);
    assert_eq!((ax, dx), (0, DX));
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        214,
        &[Slot::Word(0), Slot::Word(3)],
    );
    assert_eq!((ax, dx), (0, 0));
    host.fail_serial = true;
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        214,
        &[Slot::Word(0), Slot::Word(6)],
    );
    assert_eq!((ax, dx), (0xfffa, 0xffff));
    assert_eq!(
        host.controls,
        vec![
            (host.token, Win16HostCommControl::SetBreak),
            (host.token, Win16HostCommControl::SetRts),
            (host.token, Win16HostCommControl::ClearDtr),
        ]
    );
}

#[test]
fn lpt_does_not_accept_serial_state_or_line_control() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let device = guest(&mut runtime, 0x8_0000, b"LPT1:\0");
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(8), Slot::Word(8)],
    );
    assert_eq!(ax, 0x80);
    assert!(!win16_comm_device_is_serial(host.opens[0].0));
    let requested = guest(&mut runtime, 0x8_1000, &packed_dcb(0x80, 1, 0x13, 0));
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(requested)]);
    assert_eq!((ax, dx), (0xfffa, DX));
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        214,
        &[Slot::Word(0x80), Slot::Word(5)],
    );
    assert_eq!((ax, dx), (0xfffa, 0xffff));
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        215,
        &[Slot::Word(0x80), Slot::Word(0)],
    );
    assert_eq!(ax, 0xfffa);
    assert_eq!(host.configs.len(), 1);
    assert_eq!(
        host.controls,
        vec![(host.token, Win16HostCommControl::SetDtr)]
    );
    assert_eq!(
        host.flushes,
        vec![(host.token, Win16HostCommQueue::Transmit)]
    );
    let state = guest(&mut runtime, 0x8_1100, &[0xa5; 25]);
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        202,
        &[Slot::Word(0x80), Slot::Dword(state)],
    );
    assert_eq!(ax, 0);
    let stored = read_guest(&runtime, state, 25);
    assert_eq!(stored[0], 0x80);
    assert_eq!(u16::from_le_bytes([stored[1], stored[2]]), CBR_9600);
}

#[test]
fn task_exit_retries_comm_port_and_event_word_retirement() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let device = guest(&mut runtime, 0x8_0000, b"COM1:\0");
    let (ax, _) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!(ax, 0);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        208,
        &[Slot::Word(0), Slot::Word(EV_RXCHAR)],
    );
    assert_eq!(ax, 0);
    let event = (u32::from(dx) << 16) | u32::from(ax);
    assert_eq!(read_guest(&runtime, event, 2), [0, 0]);

    host.fail_close = true;
    let state = runtime.win16.as_mut().unwrap();
    assert!(state.retire_comm_ports(&mut host).is_err());
    assert!(host.closed.is_empty());
    assert!(!state.comm_ports.is_empty());
    assert_eq!(read_guest(&runtime, event, 2), [0, 0]);

    let (ax, _) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!(ax, 0xfffe);

    host.fail_close = false;
    runtime
        .win16
        .as_mut()
        .unwrap()
        .retire_comm_ports(&mut host)
        .unwrap();
    assert_eq!(host.closed, vec![host.token]);
    assert!(runtime.win16.as_ref().unwrap().comm_ports.is_empty());
    let state = runtime.win16.as_ref().unwrap();
    let still_readable = state
        .selectors
        .pointer_from_far(event)
        .ok()
        .and_then(|pointer| {
            state
                .selectors
                .read(&runtime.memory, pointer, &mut [0, 0])
                .ok()
        });
    assert!(still_readable.is_none());

    runtime
        .win16
        .as_mut()
        .unwrap()
        .retire_comm_ports(&mut host)
        .unwrap();
    assert_eq!(host.closed.len(), 1);

    let (ax, _) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!(ax, 0);
    assert_eq!(host.opens.len(), 2);
}

#[test]
fn build_and_set_state_follow_the_windows_31_dcb_contract() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let device = guest(&mut runtime, 0x8_0000, b"COM1\0");
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!((ax, dx), (0, DX));

    let definition = guest(&mut runtime, 0x8_0100, b"COM1:15,n,8,1\0");
    let dcb = guest(&mut runtime, 0x8_0200, &[0xa5; 25]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        213,
        &[Slot::Dword(definition), Slot::Dword(dcb)],
    );
    assert_eq!((ax, dx), (0, DX));
    let bytes = read_guest(&runtime, dcb, 25);
    assert_eq!(u16::from_le_bytes([bytes[1], bytes[2]]), 150);
    assert_eq!((bytes[3], bytes[4], bytes[5]), (8, 0, 0));

    let bad = guest(&mut runtime, 0x8_0300, b"COM1:9600,n,8,1.5\0");
    let unchanged = guest(&mut runtime, 0x8_0400, &[0xa5; 25]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        213,
        &[Slot::Dword(bad), Slot::Dword(unchanged)],
    );
    assert_eq!((ax, dx), (0xfffb, DX));
    assert_eq!(read_guest(&runtime, unchanged, 25), vec![0xa5; 25]);

    let paced = guest(&mut runtime, 0x8_0500, b"COM1:96,n,8,1,P\0");
    let paced_dcb = guest(&mut runtime, 0x8_0600, &[0xa5; 25]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        213,
        &[Slot::Dword(paced), Slot::Dword(paced_dcb)],
    );
    assert_eq!((ax, dx), (0, DX));
    let paced_bytes = read_guest(&runtime, paced_dcb, 25);
    assert_eq!(u16::from_le_bytes([paced_bytes[6], paced_bytes[7]]), 0xffff);
    assert_eq!(u16::from_le_bytes([paced_bytes[8], paced_bytes[9]]), 0xffff);
    assert_eq!(
        u16::from_le_bytes([paced_bytes[10], paced_bytes[11]]),
        0xffff
    );

    let mut literal = packed_dcb(0, 1 | (1 << 1) | (1 << 12) | (1 << 14), 0x13, 1);
    literal[1..3].copy_from_slice(&9600_u16.to_le_bytes());
    let requested = guest(&mut runtime, 0x8_0700, &literal);
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(requested)]);
    assert_eq!((ax, dx), (0, DX));
    let applied = &host.configs.last().expect("literal baud was applied").1;
    assert_eq!(applied.baud_rate, 9600);
    assert_eq!(applied.rts, Win16HostCommLine::Disable);

    let mut rejected = packed_dcb(0, 1, 0x13, 0);
    rejected[1..3].copy_from_slice(&1_u16.to_le_bytes());
    let rejected_far = guest(&mut runtime, 0x8_0800, &rejected);
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(rejected_far)]);
    assert_eq!((ax, dx), (0xfff8, DX));
    let state = guest(&mut runtime, 0x8_0900, &[0xa5; 25]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        202,
        &[Slot::Word(0), Slot::Dword(state)],
    );
    assert_eq!((ax, dx), (0, DX));
    let stored = read_guest(&runtime, state, 25);
    assert_eq!(u16::from_le_bytes([stored[1], stored[2]]), 9600);
    assert_ne!(stored[12] & (1 << 1), 0);
}

#[test]
fn read_eof_event_flag_and_write_line_timeout_match_the_sdk() {
    let mut runtime = fixture();
    let mut host = CommHost::new();
    let device = guest(&mut runtime, 0x8_0000, b"COM1\0");
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        200,
        &[Slot::Dword(device), Slot::Word(64), Slot::Word(32)],
    );
    assert_eq!((ax, dx), (0, DX));
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        208,
        &[Slot::Word(0), Slot::Word(EV_RXCHAR | EV_RXFLAG)],
    );
    assert_eq!(ax, 0);
    let event = (u32::from(dx) << 16) | u32::from(ax);

    let mut marked = packed_dcb(0, 1, 0x13, 0);
    marked[22] = b'B';
    let marked_far = guest(&mut runtime, 0x8_0100, &marked);
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(marked_far)]);
    assert_eq!((ax, dx), (0, DX));
    host.pending = b"B".to_vec();
    let output = guest(&mut runtime, 0x8_0200, &[0xa5; 2]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        204,
        &[Slot::Word(0), Slot::Dword(output), Slot::Word(2)],
    );
    assert_eq!((ax, dx), (1, DX));
    assert_eq!(read_guest(&runtime, output, 2), b"B\xa5");
    assert_eq!(
        read_guest(&runtime, event, 2),
        (EV_RXCHAR | EV_RXFLAG).to_le_bytes()
    );

    let mut text = packed_dcb(0, 0, 0x13, 0);
    text[21] = 0x1a;
    let text_far = guest(&mut runtime, 0x8_0300, &text);
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(text_far)]);
    assert_eq!((ax, dx), (0, DX));
    host.pending = b"A\x1aB".to_vec();
    let received = guest(&mut runtime, 0x8_0400, &[0xa5; 4]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        204,
        &[Slot::Word(0), Slot::Dword(received), Slot::Word(4)],
    );
    assert_eq!((ax, dx), (0xffff, DX));
    assert_eq!(read_guest(&runtime, received, 4), b"A\xa5\xa5\xa5");
    let status = guest(&mut runtime, 0x8_0500, &[0xa5; 5]);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        203,
        &[Slot::Word(0), Slot::Dword(status)],
    );
    assert_eq!((ax, dx), (1, DX));
    assert_eq!(read_guest(&runtime, status, 5)[0], CSTF_EOF);

    let mut timed = packed_dcb(0, 1, 0x13, 0);
    timed[8..10].copy_from_slice(&1_u16.to_le_bytes());
    let timed_far = guest(&mut runtime, 0x8_0600, &timed);
    let (ax, dx) = call(&mut runtime, &mut host, 201, &[Slot::Dword(timed_far)]);
    assert_eq!((ax, dx), (0, DX));
    host.lines.cts = false;
    let source = guest(&mut runtime, 0x8_0700, b"Z");
    let writes = host.writes.len();
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        205,
        &[Slot::Word(0), Slot::Dword(source), Slot::Word(1)],
    );
    assert_eq!((ax, dx), (0, DX));
    assert_eq!(host.writes.len(), writes);
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        203,
        &[Slot::Word(0), Slot::Dword(0)],
    );
    assert_eq!((ax, dx), (0x20, DX));

    host.lines.cts = true;
    let (ax, dx) = call(
        &mut runtime,
        &mut host,
        205,
        &[Slot::Word(0), Slot::Dword(source), Slot::Word(1)],
    );
    assert_eq!((ax, dx), (1, DX));
    assert_eq!(host.writes.len(), writes + 1);
}
