//! MMSYSTEM auxiliary audio, ordinals 350–354, against a fake host.

use super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::{
    DiagnosticKind as Kind, MMSYSERR_BADDEVICEID, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR, Runtime,
    RuntimeError, RuntimeHost, Win16HostAuxCapabilities, Win16HostAuxOperation, Win16HostAuxResult,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{
    AUXCAPS_CDAUDIO, AUXCAPS_LRVOLUME, AUXCAPS_VOLUME, AUXCAPS16_SIZE, Access, AccessRights,
    ExportLookupTarget, SegmentedPointer, Win16AuxCapabilities16, Win16ExportStackCleanup,
    Win16ReturnKind, lookup_export,
};

const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

struct AuxHost {
    count: u16,
    caps: Win16HostAuxCapabilities,
    volume: u32,
    message_status: u32,
    calls: Vec<Win16HostAuxOperation>,
    wrong_shape: bool,
}

impl AuxHost {
    fn new() -> Self {
        let mut product_name = [0; 32];
        let name = b"Aux Line\x81";
        product_name[..name.len()].copy_from_slice(name);
        Self {
            count: 1,
            caps: Win16HostAuxCapabilities {
                manufacturer_id: 0x1111,
                product_id: 0x2222,
                driver_version: 0x030a,
                product_name,
                technology: AUXCAPS_CDAUDIO,
                support: AUXCAPS_VOLUME | AUXCAPS_LRVOLUME,
            },
            volume: 0,
            message_status: 0x1234_5678,
            calls: Vec::new(),
            wrong_shape: false,
        }
    }
}

impl DosHost for AuxHost {
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

impl RuntimeHost for AuxHost {
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
    fn win16_aux(
        &mut self,
        operation: Win16HostAuxOperation,
    ) -> Result<Win16HostAuxResult, RuntimeError> {
        self.calls.push(operation.clone());
        if self.wrong_shape {
            return Ok(Win16HostAuxResult::Count(9));
        }
        let bad = match &operation {
            Win16HostAuxOperation::GetNumDevs => false,
            Win16HostAuxOperation::GetDevCaps { device }
            | Win16HostAuxOperation::GetVolume { device }
            | Win16HostAuxOperation::SetVolume { device, .. }
            | Win16HostAuxOperation::OutMessage { device, .. } => *device >= self.count,
        };
        Ok(match operation {
            Win16HostAuxOperation::GetNumDevs => Win16HostAuxResult::Count(self.count),
            Win16HostAuxOperation::GetDevCaps { .. } if bad => Win16HostAuxResult::Capabilities {
                result: MMSYSERR_BADDEVICEID,
                capabilities: None,
            },
            Win16HostAuxOperation::GetDevCaps { .. } => Win16HostAuxResult::Capabilities {
                result: MMSYSERR_NOERROR,
                capabilities: Some(self.caps),
            },
            Win16HostAuxOperation::GetVolume { .. } if bad => Win16HostAuxResult::Volume {
                result: MMSYSERR_BADDEVICEID,
                value: None,
            },
            Win16HostAuxOperation::GetVolume { .. } => Win16HostAuxResult::Volume {
                result: MMSYSERR_NOERROR,
                value: Some(self.volume),
            },
            Win16HostAuxOperation::SetVolume { value, .. } if !bad => {
                self.volume = value;
                Win16HostAuxResult::Status(MMSYSERR_NOERROR)
            }
            Win16HostAuxOperation::SetVolume { .. } => {
                Win16HostAuxResult::Status(MMSYSERR_BADDEVICEID)
            }
            Win16HostAuxOperation::OutMessage { .. } if bad => {
                Win16HostAuxResult::Status(MMSYSERR_BADDEVICEID)
            }
            Win16HostAuxOperation::OutMessage { .. } => {
                Win16HostAuxResult::Status(self.message_status)
            }
        })
    }
}

impl crate::RuntimeDdeHost for AuxHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for AuxHost {}
impl crate::RuntimeMidiHost for AuxHost {}
impl crate::RuntimeNetbiosHost for AuxHost {}

fn loaded() -> (Runtime, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\AUX.NE").unwrap();
    let far = (u32::from(runtime.cpu.regs.ds) << 16) | 0x10;
    let state = runtime.win16.as_mut().unwrap();
    state
        .selectors
        .write(
            &mut runtime.memory,
            state.selectors.pointer_from_far(far).unwrap(),
            &[0xa5; 48],
        )
        .unwrap();
    (runtime, far)
}

fn prepare(runtime: &mut Runtime, ordinal: u16, args: &[u8]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("auxiliary export {ordinal} must use a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes as usize, args.len());
    assert_eq!(cleanup.caller_pop_bytes, 0);
    assert_eq!(descriptor.return_kind, if ordinal == 354 { Win16ReturnKind::Dword } else { Win16ReturnKind::Word });
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(args);
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
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + 4 + cleanup.callee_pop_bytes)
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

fn output_bytes(runtime: &Runtime, far: u32) -> [u8; 48] {
    let state = runtime.win16.as_ref().unwrap();
    let mut bytes = [0; 48];
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

fn word(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}
fn dword(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

fn packed_caps(caps: &Win16HostAuxCapabilities) -> [u8; AUXCAPS16_SIZE] {
    let encoded = Win16AuxCapabilities16 {
        manufacturer_id: caps.manufacturer_id,
        product_id: caps.product_id,
        driver_version: caps.driver_version,
        product_name: caps.product_name,
        technology: caps.technology,
        support: caps.support,
    }
    .encode();
    let mut manual = [0; AUXCAPS16_SIZE];
    manual[0..2].copy_from_slice(&caps.manufacturer_id.to_le_bytes());
    manual[2..4].copy_from_slice(&caps.product_id.to_le_bytes());
    manual[4..6].copy_from_slice(&caps.driver_version.to_le_bytes());
    manual[6..38].copy_from_slice(&caps.product_name);
    manual[38..40].copy_from_slice(&caps.technology.to_le_bytes());
    manual[40..44].copy_from_slice(&caps.support.to_le_bytes());
    assert_eq!(encoded, manual);
    manual
}

#[test]
fn aux_ordinals_keep_far_pascal_result_widths() {
    let cases = [
        (350, "auxGetNumDevs", 0),
        (351, "auxGetDevCaps", 8),
        (352, "auxGetVolume", 6),
        (353, "auxSetVolume", 6),
        (354, "auxOutMessage", 12),
    ];
    for (ordinal, name, pop) in cases {
        let by_ordinal = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let by_name =
            lookup_export(b"MMSYSTEM", ExportLookupTarget::Name(name.as_bytes())).unwrap();
        assert_eq!(by_ordinal.id, by_name.id);
        assert_eq!(by_ordinal.ordinal(), ordinal);
        assert_eq!(by_ordinal.return_kind, if ordinal == 354 { Win16ReturnKind::Dword } else { Win16ReturnKind::Word });
        let Win16ExportStackCleanup::Fixed(cleanup) = by_ordinal.stack_cleanup else {
            panic!("{name} lost its fixed Pascal frame");
        };
        assert_eq!(cleanup.callee_pop_bytes, pop);
        assert_eq!(cleanup.caller_pop_bytes, 0);
    }
}

#[test]
fn aux_get_num_devs_returns_the_host_count_or_zero() {
    let (mut runtime, _) = loaded();
    let return_to = prepare(&mut runtime, 350, &[]);
    let mut host = AuxHost::new();
    host.count = 0x0102;
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0x0102);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    assert_eq!(host.calls, vec![Win16HostAuxOperation::GetNumDevs]);

    let (mut runtime, _) = loaded();
    prepare(&mut runtime, 350, &[]);
    assert_eq!(dispatch(&mut runtime, &mut NoHost).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX);
}

#[test]
fn aux_get_dev_caps_writes_the_packed_record_prefix() {
    let (mut runtime, far) = loaded();
    let mut args = Vec::from(word(AUXCAPS16_SIZE as u16).as_slice());
    args.extend_from_slice(&dword(far));
    args.extend_from_slice(&word(0));
    let return_to = prepare(&mut runtime, 351, &args);
    let mut host = AuxHost::new();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    let mut seen = output_bytes(&runtime, far);
    let packed = packed_caps(&host.caps);
    assert_eq!(&seen[..AUXCAPS16_SIZE], &packed);
    assert_eq!(&seen[AUXCAPS16_SIZE..], &[0xa5; 4]);
    assert_eq!(
        host.calls,
        vec![Win16HostAuxOperation::GetDevCaps { device: 0 }]
    );

    let (mut runtime, far) = loaded();
    let mut args = Vec::from(word(10).as_slice());
    args.extend_from_slice(&dword(far));
    args.extend_from_slice(&word(0));
    prepare(&mut runtime, 351, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    seen = output_bytes(&runtime, far);
    assert_eq!(&seen[..10], &packed[..10]);
    assert_eq!(&seen[10..], &[0xa5; 38]);

    let (mut runtime, far) = loaded();
    let mut args = Vec::from(word(0).as_slice());
    args.extend_from_slice(&dword(0));
    args.extend_from_slice(&word(7));
    prepare(&mut runtime, 351, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert!(host.calls.is_empty());
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);

    let (mut runtime, far) = loaded();
    let mut args = Vec::from(word(AUXCAPS16_SIZE as u16).as_slice());
    args.extend_from_slice(&dword(0));
    args.extend_from_slice(&word(0));
    prepare(&mut runtime, 351, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), MMSYSERR_INVALPARAM as u16);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert!(host.calls.is_empty());
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);

    let (mut runtime, far) = loaded();
    let mut args = Vec::from(word(AUXCAPS16_SIZE as u16).as_slice());
    args.extend_from_slice(&dword(far));
    args.extend_from_slice(&word(0xffff));
    prepare(&mut runtime, 351, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), MMSYSERR_BADDEVICEID as u16);
    assert_eq!(
        host.calls,
        vec![Win16HostAuxOperation::GetDevCaps { device: 0xffff }]
    );
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);
}

#[test]
fn aux_volume_round_trip_keeps_the_guest_dword() {
    let (mut runtime, far) = loaded();
    let mut args = Vec::from(dword(0xaabb_ccdd).as_slice());
    args.extend_from_slice(&word(0));
    prepare(&mut runtime, 353, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);
    assert_eq!(
        host.calls,
        vec![Win16HostAuxOperation::SetVolume {
            device: 0,
            value: 0xaabb_ccdd
        }]
    );

    let mut args = Vec::from(dword(far).as_slice());
    args.extend_from_slice(&word(0));
    let return_to = prepare(&mut runtime, 352, &args);
    host.calls.clear();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 0);
    assert_eq!(runtime.cpu.regs.dx(), DX);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    let bytes = output_bytes(&runtime, far);
    assert_eq!(&bytes[..4], &0xaabb_ccdd_u32.to_le_bytes());
    assert_eq!(&bytes[4..], &[0xa5; 44]);

    let (mut runtime, far) = loaded();
    let mut args = Vec::from(dword(far).as_slice());
    args.extend_from_slice(&word(1));
    prepare(&mut runtime, 352, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), MMSYSERR_BADDEVICEID as u16);
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);

    let (mut runtime, far) = loaded();
    let state = runtime.win16.as_mut().unwrap();
    let base = state.selectors.pointer_from_far(far).unwrap();
    let address = state
        .selectors
        .translate(base, Access::Write, 3, &runtime.memory)
        .unwrap();
    let selector = state
        .selectors
        .alloc_block(address, 3, AccessRights::read_write(), &runtime.memory)
        .unwrap();
    let short = SegmentedPointer::new(selector, 0).far_value();
    let mut args = Vec::from(dword(short).as_slice());
    args.extend_from_slice(&word(0));
    prepare(&mut runtime, 352, &args);
    let mut host = AuxHost::new();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), MMSYSERR_INVALPARAM as u16);
    assert!(host.calls.is_empty());
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);

    let (mut runtime, _) = loaded();
    let mut args = Vec::from(dword(0x55aa_55aa).as_slice());
    args.extend_from_slice(&word(4));
    prepare(&mut runtime, 353, &args);
    assert_eq!(dispatch(&mut runtime, &mut NoHost).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), MMSYSERR_BADDEVICEID as u16);
    assert_eq!(runtime.cpu.regs.dx(), DX);
}

#[test]
fn aux_out_message_forwards_guest_dwords_without_reading_them() {
    let (mut runtime, far) = loaded();
    let mut args = Vec::from(dword(0x9abc_def0).as_slice());
    args.extend_from_slice(&dword(far));
    args.extend_from_slice(&word(0x4001));
    args.extend_from_slice(&word(0));
    let return_to = prepare(&mut runtime, 354, &args);
    let mut host = AuxHost::new();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0x5678);
    assert_eq!(runtime.cpu.regs.dx(), 0x1234);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);
    assert_eq!(
        host.calls,
        vec![Win16HostAuxOperation::OutMessage {
            device: 0,
            message: 0x4001,
            parameter1: far,
            parameter2: 0x9abc_def0,
        }]
    );
}

#[test]
fn aux_wrong_host_shape_does_not_commit_the_return() {
    let (mut runtime, far) = loaded();
    let mut args = Vec::from(dword(far).as_slice());
    args.extend_from_slice(&word(0));
    prepare(&mut runtime, 352, &args);
    let before = runtime.cpu.regs.clone();
    let mut host = AuxHost::new();
    host.wrong_shape = true;
    let error = dispatch(&mut runtime, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::InternalInvariant);
    assert_eq!(runtime.cpu.regs, before);
    assert_eq!(output_bytes(&runtime, far), [0xa5; 48]);
}
