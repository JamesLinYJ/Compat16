//! USER communications service gate with a host that only records transfers.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostCommDevice,
    Win16HostCommPort,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::comm_abi::{CBR_2400, EV_RXCHAR, EV_TXEMPTY};
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
        }
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
        self.closed.push(port);
        Ok(())
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
