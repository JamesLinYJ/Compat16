//! Mixer ordinals 800–809 through the service gate and a session-mixer host.

use super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{Runtime, RuntimeError, RuntimeHost, Win16HostMixerOperation, Win16SessionMixer};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, SelectorRef, lookup_export,
    MIXERCAPS16_SIZE, MIXERCONTROL16_SIZE, MIXERCONTROLDETAILS16_SIZE, MIXERLINE16_SIZE,
    MIXERLINECONTROLS16_SIZE,
};

const BASE: u32 = 0x80000;
const EAX_SENTINEL: u32 = 0x1357_a55a;
const EDX_SENTINEL: u32 = 0x2468_5aa5;
const CALLBACK_WINDOW: u32 = 0x0001_0000;
const MIXER_OBJECTF_HMIXER: u32 = 0x8000_0000;
const MIXER_OBJECTF_WAVEOUT: u32 = 0x1000_0000;

struct MixerHost {
    mixer: Win16SessionMixer,
    calls: Vec<&'static str>,
}

impl MixerHost {
    fn new() -> Self {
        Self { mixer: Win16SessionMixer::default(), calls: Vec::new() }
    }
}

impl DosHost for MixerHost {
    fn read_stdin(&mut self, _: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _: &[u8], _: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _: &[u8], _: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _: &[u8], _: DosFileAccess, _: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _: DosHostFile, _: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _: DosHostFile, _: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _: DosHostFile, _: i32, _: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _: DosHostFile, _: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _: u8, _: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _: &[u8], _: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _: &[u8], _: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

impl RuntimeHost for MixerHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
    fn win16_mixer(
        &mut self,
        operation: Win16HostMixerOperation,
    ) -> Result<crate::Win16HostMixerResult, RuntimeError> {
        self.calls.push(match operation {
            Win16HostMixerOperation::DeviceCount => "count",
            Win16HostMixerOperation::DeviceCaps { .. } => "caps",
            Win16HostMixerOperation::Open { .. } => "open",
            Win16HostMixerOperation::Close { .. } => "close",
            Win16HostMixerOperation::Message { .. } => "message",
            Win16HostMixerOperation::LineInfo { .. } => "line",
            Win16HostMixerOperation::GetId { .. } => "id",
            Win16HostMixerOperation::LineControls { .. } => "controls",
            Win16HostMixerOperation::GetDetails { .. } => "get-details",
            Win16HostMixerOperation::SetDetails { .. } => "set-details",
        });
        Ok(self.mixer.execute(operation))
    }
}

impl crate::RuntimeDdeHost for MixerHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for MixerHost {}
impl crate::RuntimeMidiHost for MixerHost {}
impl crate::RuntimeNetbiosHost for MixerHost {}

fn runtime() -> (Runtime, SelectorRef) {
    let bytes = vec![0xA5; 0x400];
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\MIXER.NE").unwrap();
    runtime.memory.write_physical(PhysAddr(BASE), &bytes).unwrap();
    let selector = runtime.win16.as_mut().unwrap().selectors.alloc_block(
        PhysAddr(BASE), bytes.len() as u32, AccessRights::read_write(), &runtime.memory,
    ).unwrap();
    (runtime, selector)
}

fn far(selector: SelectorRef, offset: u16) -> u32 {
    SegmentedPointer::new(selector, offset).far_value()
}

fn word(value: u16) -> [u8; 2] { value.to_le_bytes() }
fn dword(value: u32) -> [u8; 4] { value.to_le_bytes() }

fn invoke(
    runtime: &mut Runtime,
    host: &mut MixerHost,
    ordinal: u16,
    args: &[&[u8]],
) -> (u16, u16) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    // Pascal places the last declared argument next to the far return address.
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    for argument in args.iter().rev() {
        frame.extend_from_slice(argument);
    }
    let state = runtime.win16.as_mut().unwrap();
    let stack_pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, stack_pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    assert_eq!(runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    ).unwrap(), None);
    let ax = runtime.cpu.regs.ax();
    let dx = runtime.cpu.regs.dx();
    assert_eq!(runtime.cpu.regs.cs, return_cs);
    assert_eq!(runtime.cpu.regs.ip(), return_ip);
    assert_eq!(runtime.cpu.regs.sp(), stack + frame.len() as u16);
    (ax, dx)
}

fn read_at(runtime: &Runtime, offset: usize, bytes: &mut [u8]) {
    runtime.memory.read_physical(PhysAddr(BASE + offset as u32), bytes).unwrap();
}

#[test]
fn mixer_session_reports_one_device_and_preserves_the_high_registers() {
    let (mut runtime, _) = runtime();
    let mut host = MixerHost::new();
    let (ax, dx) = invoke(&mut runtime, &mut host, 800, &[]);
    assert_eq!((ax, dx), (1, (EDX_SENTINEL & 0xffff) as u16));
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | 1);
    assert_eq!(host.calls, ["count"]);
}

#[test]
fn mixer_caps_use_the_sixteen_bit_version_and_reject_a_bad_device() {
    let (mut runtime, selector) = runtime();
    let mut host = MixerHost::new();
    let caps = far(selector, 0);
    let (ax, _) = invoke(&mut runtime, &mut host, 801, &[
        word(0).as_slice(), &dword(caps), &word(MIXERCAPS16_SIZE as u16),
    ]);
    assert_eq!(ax, 0);
    let mut record = [0; MIXERCAPS16_SIZE];
    read_at(&runtime, 0, &mut record);
    assert_eq!(&record[6..20], b"Session Mixer\0");
    assert_eq!(&record[20..42], &[0; 22]);
    assert_eq!(u16::from_le_bytes([record[4], record[5]]), 0x030A);
    assert_eq!(u32::from_le_bytes(record[42..46].try_into().unwrap()), 1);

    let (ax, _) = invoke(&mut runtime, &mut host, 801, &[
        word(3).as_slice(), &dword(caps), &word(4),
    ]);
    assert_eq!(ax, 2);
    let mut unchanged = [0; 4];
    read_at(&runtime, 0, &mut unchanged);
    assert_eq!(&unchanged, &record[..4]);

    host.calls.clear();
    let (ax, _) = invoke(&mut runtime, &mut host, 801, &[
        word(9).as_slice(), &dword(caps), &word(0),
    ]);
    assert_eq!(ax, 0);
    assert!(host.calls.is_empty());
}

#[test]
fn mixer_open_close_id_line_control_and_message_stay_on_the_session_host() {
    let (mut runtime, selector) = runtime();
    let mut host = MixerHost::new();
    let handle_far = far(selector, 0x40);
    let (ax, _) = invoke(&mut runtime, &mut host, 802, &[
        dword(handle_far).as_slice(), &word(0), &dword(0), &dword(0), &dword(0),
    ]);
    assert_eq!(ax, 0);
    let mut handle = [0; 2];
    read_at(&runtime, 0x40, &mut handle);
    assert_eq!(u16::from_le_bytes(handle), 1);

    let (ax, _) = invoke(&mut runtime, &mut host, 802, &[
        dword(0).as_slice(), &word(0), &dword(0), &dword(0), &dword(CALLBACK_WINDOW),
    ]);
    assert_eq!(ax, 8);
    assert_eq!(host.calls.iter().filter(|call| **call == "open").count(), 1);

    let id_far = far(selector, 0x50);
    let (ax, _) = invoke(&mut runtime, &mut host, 806, &[
        word(1).as_slice(), &dword(id_far), &dword(MIXER_OBJECTF_HMIXER),
    ]);
    assert_eq!(ax, 0);
    let mut id = [0; 2];
    read_at(&runtime, 0x50, &mut id);
    assert_eq!(u16::from_le_bytes(id), 0);

    host.calls.clear();
    let (ax, _) = invoke(&mut runtime, &mut host, 806, &[
        word(0).as_slice(), &dword(id_far), &dword(MIXER_OBJECTF_WAVEOUT),
    ]);
    assert_eq!(ax, 10);
    assert!(host.calls.is_empty());

    let line_far = far(selector, 0x60);
    let mut line_in = vec![0; MIXERLINE16_SIZE];
    line_in[..4].copy_from_slice(&(MIXERLINE16_SIZE as u32).to_le_bytes());
    runtime.memory.write_physical(PhysAddr(BASE + 0x60), &line_in).unwrap();
    let (ax, _) = invoke(&mut runtime, &mut host, 805, &[
        word(0).as_slice(), &dword(line_far), &dword(0),
    ]);
    assert_eq!(ax, 0);
    let mut line = [0; MIXERLINE16_SIZE];
    read_at(&runtime, 0x60, &mut line);
    assert_eq!(u32::from_le_bytes(line[24..28].try_into().unwrap()), 4);
    assert_eq!(u32::from_le_bytes(line[36..40].try_into().unwrap()), 1);
    assert_eq!(&line[40..48], b"Speakers");

    let mut controls = vec![0; MIXERLINECONTROLS16_SIZE];
    controls[..4].copy_from_slice(&(MIXERLINECONTROLS16_SIZE as u32).to_le_bytes());
    controls[8..12].copy_from_slice(&0x5003_0001_u32.to_le_bytes());
    controls[12..16].copy_from_slice(&1_u32.to_le_bytes());
    controls[16..20].copy_from_slice(&(MIXERCONTROL16_SIZE as u32).to_le_bytes());
    let control_far = far(selector, 0x180);
    controls[20..24].copy_from_slice(&control_far.to_le_bytes());
    runtime.memory.write_physical(PhysAddr(BASE + 0x120), &controls).unwrap();
    let header_far = far(selector, 0x120);
    let (ax, _) = invoke(&mut runtime, &mut host, 807, &[
        word(1).as_slice(), &dword(header_far), &dword(MIXER_OBJECTF_HMIXER | 2),
    ]);
    assert_eq!(ax, 0);
    let mut control = [0; MIXERCONTROL16_SIZE];
    read_at(&runtime, 0x180, &mut control);
    assert_eq!(u32::from_le_bytes(control[8..12].try_into().unwrap()), 0x5003_0001);
    assert_eq!(u32::from_le_bytes(control[104..108].try_into().unwrap()), 0xFFFF);

    let mut details = vec![0; MIXERCONTROLDETAILS16_SIZE];
    details[..4].copy_from_slice(&(MIXERCONTROLDETAILS16_SIZE as u32).to_le_bytes());
    details[4..8].copy_from_slice(&1_u32.to_le_bytes());
    details[8..12].copy_from_slice(&1_u32.to_le_bytes());
    details[16..20].copy_from_slice(&4_u32.to_le_bytes());
    let value_far = far(selector, 0x220);
    details[20..24].copy_from_slice(&value_far.to_le_bytes());
    runtime.memory.write_physical(PhysAddr(BASE + 0x220), &0x1234_u32.to_le_bytes()).unwrap();
    runtime.memory.write_physical(PhysAddr(BASE + 0x240), &details).unwrap();
    let details_far = far(selector, 0x240);
    let (ax, _) = invoke(&mut runtime, &mut host, 809, &[
        word(0).as_slice(), &dword(details_far), &dword(0),
    ]);
    assert_eq!(ax, 0);
    let (ax, _) = invoke(&mut runtime, &mut host, 808, &[
        word(1).as_slice(), &dword(details_far), &dword(MIXER_OBJECTF_HMIXER),
    ]);
    assert_eq!(ax, 0);
    let mut value = [0; 4];
    read_at(&runtime, 0x220, &mut value);
    assert_eq!(u32::from_le_bytes(value), 0x1234);

    runtime.memory.write_physical(PhysAddr(BASE + 0x220), &0x1_0000_u32.to_le_bytes()).unwrap();
    let (ax, _) = invoke(&mut runtime, &mut host, 809, &[
        word(0).as_slice(), &dword(details_far), &dword(0),
    ]);
    assert_eq!(ax, 1026);

    let (ax, dx) = invoke(&mut runtime, &mut host, 804, &[
        word(1).as_slice(), &word(7), &dword(0), &dword(0),
    ]);
    assert_eq!((ax, dx), (8, 0));
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL & 0xffff_0000);

    let (ax, _) = invoke(&mut runtime, &mut host, 803, &[word(1).as_slice()]);
    assert_eq!(ax, 0);
    let (ax, _) = invoke(&mut runtime, &mut host, 803, &[word(1).as_slice()]);
    assert_eq!(ax, 5);
    assert!(host.calls.iter().all(|call| !matches!(*call, "wave" | "midi")));
}

#[test]
fn mixer_short_line_and_null_open_stay_parameter_errors() {
    let (mut runtime, selector) = runtime();
    let mut host = MixerHost::new();
    let line_far = far(selector, 0);
    runtime.memory.write_physical(PhysAddr(BASE), &10_u32.to_le_bytes()).unwrap();
    let (ax, _) = invoke(&mut runtime, &mut host, 805, &[
        word(0).as_slice(), &dword(line_far), &dword(0),
    ]);
    assert_eq!(ax, 11);
    assert!(host.calls.is_empty());
    let (ax, _) = invoke(&mut runtime, &mut host, 802, &[
        dword(0).as_slice(), &word(0), &dword(0), &dword(0), &dword(0),
    ]);
    assert_eq!(ax, 11);
}
