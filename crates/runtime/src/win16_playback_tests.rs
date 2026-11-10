//! Wave and MIDI playback gates with a fake host. No physical audio device.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16HostMidiCall,
    Win16HostMidiCaps, Win16HostMidiDevice, Win16HostMidiResult, Win16HostWaveCapabilities,
    Win16HostWaveDevice, Win16HostWaveHeaderState, Win16HostWaveInitialBuffer,
    Win16HostWaveOperation, Win16HostWaveResult,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, SelectorRef, Win16ReturnKind, lookup_export,
};

const BASE: u32 = 0x90000;
const MEMORY: usize = 0x400;
const SENTINEL: u8 = 0xA5;
const EAX_SENTINEL: u32 = 0xA1B2_A55A;
const EDX_SENTINEL: u32 = 0xC3D4_5AA5;
const WAVE_FORMAT_QUERY: u32 = 1;
const WHDR_PREPARED: u32 = 2;
const WHDR_BEGINLOOP: u32 = 4;
const WHDR_ENDLOOP: u32 = 8;
const MMSYSERR_BADDEVICEID: u16 = 2;
const MMSYSERR_INVALHANDLE: u16 = 5;
const MMSYSERR_BADERRNUM: u16 = 9;
const MMSYSERR_INVALPARAM: u16 = 11;
const WAVERR_STILLPLAYING: u16 = 33;
const WAVERR_UNPREPARED: u16 = 34;
const MIDIERR_UNPREPARED: u16 = 64;

struct PlaybackHost {
    wave_count: u32,
    wave_caps_result: u32,
    wave_version: u32,
    wave_error: Vec<u8>,
    wave_open_result: u32,
    wave_seen_device: Option<u16>,
    wave_seen_flags: Option<u32>,
    wave_prepare_loops: Option<u32>,
    midi_count: u32,
    midi_caps_result: u32,
    midi_error: Vec<u8>,
    midi_open_result: u32,
    calls: Vec<&'static str>,
}

impl Default for PlaybackHost {
    fn default() -> Self {
        Self {
            wave_count: 1,
            wave_caps_result: 0,
            wave_version: 0x030A,
            wave_error: b"play\0".to_vec(),
            wave_open_result: 0,
            wave_seen_device: None,
            wave_seen_flags: None,
            wave_prepare_loops: None,
            midi_count: 1,
            midi_caps_result: 0,
            midi_error: b"midi\0".to_vec(),
            midi_open_result: 0,
            calls: Vec::new(),
        }
    }
}

impl DosHost for PlaybackHost {
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

impl RuntimeHost for PlaybackHost {
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
    fn win16_wave(
        &mut self,
        operation: Win16HostWaveOperation,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        self.calls.push(match &operation {
            Win16HostWaveOperation::DeviceCount { .. } => "wave-count",
            Win16HostWaveOperation::DeviceCapabilities { .. } => "wave-caps",
            Win16HostWaveOperation::ErrorText { .. } => "wave-error",
            Win16HostWaveOperation::Open { .. } => "wave-open",
            Win16HostWaveOperation::Prepare { .. } => "wave-prepare",
            Win16HostWaveOperation::Submit { .. } => "wave-submit",
            Win16HostWaveOperation::Control { .. } => "wave-control",
            Win16HostWaveOperation::GetPosition { .. } => "wave-position",
            other => panic!("unexpected WAVE host call {other:?}"),
        });
        Ok(match operation {
            Win16HostWaveOperation::DeviceCount { .. } => {
                Win16HostWaveResult::DeviceCount(self.wave_count)
            }
            Win16HostWaveOperation::DeviceCapabilities { .. } => {
                Win16HostWaveResult::DeviceCapabilities {
                    result: self.wave_caps_result,
                    capabilities: (self.wave_caps_result == 0)
                        .then_some(sample_wave_caps(self.wave_version)),
                }
            }
            Win16HostWaveOperation::ErrorText { .. } => Win16HostWaveResult::ErrorText {
                result: 0,
                bytes: Some(self.wave_error.clone()),
            },
            Win16HostWaveOperation::Open {
                device_id, flags, ..
            } => {
                self.wave_seen_device = Some(device_id);
                self.wave_seen_flags = Some(flags);
                let query = flags & WAVE_FORMAT_QUERY != 0;
                Win16HostWaveResult::Opened {
                    result: self.wave_open_result,
                    device: (!query && self.wave_open_result == 0)
                        .then_some(Win16HostWaveDevice(1)),
                }
            }
            Win16HostWaveOperation::Prepare { loops, initial, .. } => {
                self.wave_prepare_loops = Some(loops);
                assert!(matches!(initial, Win16HostWaveInitialBuffer::Null));
                Win16HostWaveResult::Header {
                    result: 0,
                    buffer: Some(crate::Win16HostWaveBuffer(1)),
                    submission: None,
                    completion_pending: false,
                    state: Some(Win16HostWaveHeaderState {
                        flags: WHDR_PREPARED,
                        bytes_recorded: 0,
                    }),
                    input_bytes: None,
                }
            }
            Win16HostWaveOperation::GetPosition { .. } => Win16HostWaveResult::Position {
                result: 0,
                position: None,
            },
            Win16HostWaveOperation::Control { .. } => Win16HostWaveResult::Scalar(0),
            _ => unreachable!("recorded WAVE call has no scripted result"),
        })
    }
}

impl crate::RuntimeDdeHost for PlaybackHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for PlaybackHost {}
impl crate::RuntimeNetbiosHost for PlaybackHost {}
impl crate::RuntimeMidiHost for PlaybackHost {
    fn win16_midi(&mut self, call: Win16HostMidiCall) -> Result<Win16HostMidiResult, RuntimeError> {
        self.calls.push(match &call {
            Win16HostMidiCall::DeviceCount { .. } => "midi-count",
            Win16HostMidiCall::GetCaps { .. } => "midi-caps",
            Win16HostMidiCall::GetErrorText { .. } => "midi-error",
            Win16HostMidiCall::Open { .. } => "midi-open",
            Win16HostMidiCall::OutputShort { .. } => "midi-short",
            Win16HostMidiCall::OutputLong { .. } => "midi-long",
            Win16HostMidiCall::OutputReset { .. } => "midi-reset",
            other => panic!("unexpected MIDI host call {other:?}"),
        });
        Ok(match call {
            Win16HostMidiCall::DeviceCount { .. } => Win16HostMidiResult::Scalar(self.midi_count),
            Win16HostMidiCall::GetCaps { .. } => Win16HostMidiResult::Caps {
                result: self.midi_caps_result,
                caps: (self.midi_caps_result == 0).then_some(sample_midi_caps()),
            },
            Win16HostMidiCall::GetErrorText { .. } => Win16HostMidiResult::ErrorText {
                result: 0,
                bytes: self.midi_error.clone(),
            },
            Win16HostMidiCall::Open { .. } => Win16HostMidiResult::Opened {
                result: self.midi_open_result,
                device: (self.midi_open_result == 0).then_some(Win16HostMidiDevice {
                    token: 1,
                    generation: 1,
                }),
            },
            Win16HostMidiCall::OutputShort { .. } | Win16HostMidiCall::OutputReset { .. } => {
                Win16HostMidiResult::Scalar(0)
            }
            _ => unreachable!("recorded MIDI call has no scripted result"),
        })
    }
}

fn sample_wave_caps(version: u32) -> Win16HostWaveCapabilities {
    let mut product_name = [0; 32];
    product_name[..5].copy_from_slice(b"Wave\0");
    Win16HostWaveCapabilities::Output {
        manufacturer_id: 0x0001,
        product_id: 0x0002,
        driver_version: version,
        product_name,
        formats: 0x0000_0FFF,
        channels: 2,
        support: 0x0000_0003,
    }
}

fn sample_midi_caps() -> Win16HostMidiCaps {
    let mut product_name = [0; 32];
    product_name[..5].copy_from_slice(b"Midi\0");
    Win16HostMidiCaps::Output {
        manufacturer: 0x0011,
        product: 0x0022,
        driver_version: 0x0100,
        product_name,
        technology: 1,
        voices: 16,
        notes: 32,
        channel_mask: 0xFFFF,
        support: 1,
    }
}

fn fixture() -> (Runtime, SelectorRef) {
    let bytes = vec![SENTINEL; MEMORY];
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PLAY.NE").unwrap();
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

fn invoke(
    runtime: &mut Runtime,
    host: &mut PlaybackHost,
    ordinal: u16,
    args: &[&[u8]],
) -> Result<u16, RuntimeError> {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
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
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )?;
    assert_eq!(runtime.cpu.regs.cs, return_cs);
    assert_eq!(runtime.cpu.regs.ip(), return_ip);
    assert_eq!(runtime.cpu.regs.sp(), stack + frame.len() as u16);
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    let result = runtime.cpu.regs.ax();
    assert_eq!(
        runtime.cpu.regs.eax,
        (EAX_SENTINEL & 0xFFFF_0000) | u32::from(result)
    );
    Ok(result)
}

fn read_bytes(runtime: &Runtime, offset: usize, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    runtime
        .memory
        .read_physical(PhysAddr(BASE + offset as u32), &mut bytes)
        .unwrap();
    bytes
}

fn write_bytes(runtime: &mut Runtime, offset: usize, bytes: &[u8]) {
    runtime
        .memory
        .write_physical(PhysAddr(BASE + offset as u32), bytes)
        .unwrap();
}

fn pcm_format() -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0..2].copy_from_slice(&1_u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&11_025_u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&11_025_u32.to_le_bytes());
    bytes[12..14].copy_from_slice(&1_u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&8_u16.to_le_bytes());
    bytes
}

fn wave_header(flags: u32, loops: u32) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[16..20].copy_from_slice(&flags.to_le_bytes());
    bytes[20..24].copy_from_slice(&loops.to_le_bytes());
    bytes
}

#[test]
fn playback_ordinals_keep_names_and_word_returns() {
    for (ordinal, name) in [
        (401, "waveOutGetNumDevs"),
        (402, "waveOutGetDevCaps"),
        (403, "waveOutGetErrorText"),
        (404, "waveOutOpen"),
        (405, "waveOutClose"),
        (406, "waveOutPrepareHeader"),
        (407, "waveOutUnprepareHeader"),
        (408, "waveOutWrite"),
        (409, "waveOutPause"),
        (410, "waveOutRestart"),
        (411, "waveOutReset"),
        (412, "waveOutGetPosition"),
        (201, "midiOutGetNumDevs"),
        (202, "midiOutGetDevCaps"),
        (203, "midiOutGetErrorText"),
        (204, "midiOutOpen"),
        (205, "midiOutClose"),
        (208, "midiOutShortMsg"),
        (209, "midiOutLongMsg"),
        (210, "midiOutReset"),
    ] {
        let by_ordinal = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let by_name =
            lookup_export(b"MMSYSTEM", ExportLookupTarget::Name(name.as_bytes())).unwrap();
        assert_eq!(by_ordinal.id, by_name.id);
        assert_eq!(by_ordinal.return_kind, Win16ReturnKind::Word);
    }
}

#[test]
fn wave_out_get_num_devs_keeps_a_word_count() {
    let (mut runtime, _) = fixture();
    let mut host = PlaybackHost {
        wave_count: 3,
        ..PlaybackHost::default()
    };
    assert_eq!(invoke(&mut runtime, &mut host, 401, &[]).unwrap(), 3);
    assert_eq!(host.calls, ["wave-count"]);

    let (mut runtime, _) = fixture();
    let mut host = PlaybackHost {
        wave_count: 0x1_0000,
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(&mut runtime, &mut host, 401, &[])
            .unwrap_err()
            .kind(),
        Kind::CompatibilityGap
    );
    assert_eq!(runtime.cpu.regs.eax, EAX_SENTINEL);
}

#[test]
fn wave_out_get_dev_caps_uses_the_3_1_record() {
    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            402,
            &[&word(0), &dword(output), &word(0)]
        )
        .unwrap(),
        0
    );
    assert!(host.calls.is_empty());
    assert_eq!(read_bytes(&runtime, 0, 48), vec![SENTINEL; 48]);

    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost {
        wave_caps_result: u32::from(MMSYSERR_BADDEVICEID),
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            402,
            &[&word(0), &dword(output), &word(48)]
        )
        .unwrap(),
        MMSYSERR_BADDEVICEID
    );
    assert_eq!(host.calls, ["wave-caps"]);
    assert_eq!(read_bytes(&runtime, 0, 48), vec![SENTINEL; 48]);

    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost {
        wave_version: 0x1_0000,
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            402,
            &[&word(0), &dword(output), &word(48)]
        )
        .unwrap_err()
        .kind(),
        Kind::CompatibilityGap
    );
    assert_eq!(read_bytes(&runtime, 0, 48), vec![SENTINEL; 48]);

    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            402,
            &[&word(0), &dword(output), &word(6)]
        )
        .unwrap(),
        0
    );
    let bytes = read_bytes(&runtime, 0, 8);
    assert_eq!(&bytes[..2], &1_u16.to_le_bytes());
    assert_eq!(&bytes[2..4], &2_u16.to_le_bytes());
    assert_eq!(&bytes[4..6], &0x030A_u16.to_le_bytes());
    assert_eq!(&bytes[6..], &[SENTINEL; 2]);
}

#[test]
fn wave_out_get_error_text_uses_the_3_1_range() {
    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    for error in [12_u16, 36, 64] {
        host.calls.clear();
        assert_eq!(
            invoke(
                &mut runtime,
                &mut host,
                403,
                &[&word(error), &dword(output), &word(16)]
            )
            .unwrap(),
            MMSYSERR_BADERRNUM,
        );
        assert!(host.calls.is_empty());
        assert_eq!(read_bytes(&runtime, 0, 16), vec![SENTINEL; 16]);
    }

    let (mut runtime, _) = fixture();
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            403,
            &[&word(0), &dword(0), &word(0)]
        )
        .unwrap(),
        0
    );
    assert!(host.calls.is_empty());

    let (mut runtime, _selector) = fixture();
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            403,
            &[&word(WAVERR_STILLPLAYING), &dword(0), &word(8)]
        )
        .unwrap(),
        MMSYSERR_INVALPARAM,
    );
    assert!(host.calls.is_empty());
    assert_eq!(read_bytes(&runtime, 0, 8), vec![SENTINEL; 8]);

    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            403,
            &[&word(WAVERR_STILLPLAYING), &dword(output), &word(8)]
        )
        .unwrap(),
        0,
    );
    assert_eq!(host.calls, ["wave-error"]);
    let bytes = read_bytes(&runtime, 0, 8);
    assert_eq!(&bytes[..5], b"play\0");
    assert_eq!(&bytes[5..], &[SENTINEL; 3]);
}

#[test]
fn wave_out_open_query_and_failure_leave_the_handle() {
    let (mut runtime, selector) = fixture();
    write_bytes(&mut runtime, 0x100, &pcm_format());
    let handle = far(selector, 0);
    let format = far(selector, 0x100);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            404,
            &[
                &dword(handle),
                &word(0xFFFF),
                &dword(format),
                &dword(0),
                &dword(0),
                &dword(WAVE_FORMAT_QUERY),
            ]
        )
        .unwrap(),
        0
    );
    assert_eq!(host.calls, ["wave-open"]);
    assert_eq!(host.wave_seen_device, Some(0xFFFF));
    assert_eq!(host.wave_seen_flags, Some(WAVE_FORMAT_QUERY));
    assert_eq!(read_bytes(&runtime, 0, 2), vec![SENTINEL; 2]);

    let (mut runtime, selector) = fixture();
    write_bytes(&mut runtime, 0x100, &pcm_format());
    let handle = far(selector, 0);
    let format = far(selector, 0x100);
    let mut host = PlaybackHost {
        wave_open_result: u32::from(MMSYSERR_BADDEVICEID),
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            404,
            &[
                &dword(handle),
                &word(9),
                &dword(format),
                &dword(0),
                &dword(0),
                &dword(0),
            ]
        )
        .unwrap(),
        MMSYSERR_BADDEVICEID
    );
    assert_eq!(read_bytes(&runtime, 0, 2), vec![SENTINEL; 2]);
}

#[test]
fn wave_out_prepare_keeps_loop_flags() {
    let (mut runtime, selector) = fixture();
    write_bytes(&mut runtime, 0x100, &pcm_format());
    write_bytes(
        &mut runtime,
        0x120,
        &wave_header(WHDR_BEGINLOOP | WHDR_ENDLOOP, 2),
    );
    let handle = far(selector, 0);
    let format = far(selector, 0x100);
    let header = far(selector, 0x120);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            404,
            &[
                &dword(handle),
                &word(0),
                &dword(format),
                &dword(0),
                &dword(0),
                &dword(0),
            ]
        )
        .unwrap(),
        0
    );
    let guest = u16::from_le_bytes(read_bytes(&runtime, 0, 2).try_into().unwrap());
    assert_ne!(guest, 0);
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            406,
            &[&word(guest), &dword(header), &word(32),]
        )
        .unwrap(),
        0
    );
    assert_eq!(host.wave_prepare_loops, Some(2));
    let flags = u32::from_le_bytes(read_bytes(&runtime, 0x120 + 16, 4).try_into().unwrap());
    assert_eq!(flags, WHDR_PREPARED | WHDR_BEGINLOOP | WHDR_ENDLOOP);
    assert_eq!(
        u32::from_le_bytes(read_bytes(&runtime, 0x120 + 20, 4).try_into().unwrap()),
        2
    );

    let (mut runtime, selector) = fixture();
    write_bytes(&mut runtime, 0x120, &wave_header(WHDR_BEGINLOOP, 1));
    let header = far(selector, 0x120);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            406,
            &[&word(0), &dword(header), &word(32),]
        )
        .unwrap(),
        MMSYSERR_INVALHANDLE
    );
    assert!(!host.calls.contains(&"wave-prepare"));
    let flags = u32::from_le_bytes(read_bytes(&runtime, 0x120 + 16, 4).try_into().unwrap());
    assert_eq!(flags, WHDR_BEGINLOOP);
}

#[test]
fn wave_out_write_and_controls_fail_closed() {
    let (mut runtime, selector) = fixture();
    write_bytes(&mut runtime, 0x100, &pcm_format());
    write_bytes(&mut runtime, 0x120, &wave_header(0, 0));
    let handle = far(selector, 0);
    let format = far(selector, 0x100);
    let header = far(selector, 0x120);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            404,
            &[
                &dword(handle),
                &word(0),
                &dword(format),
                &dword(0),
                &dword(0),
                &dword(0),
            ]
        )
        .unwrap(),
        0
    );
    let guest = u16::from_le_bytes(read_bytes(&runtime, 0, 2).try_into().unwrap());
    host.calls.clear();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            408,
            &[&word(guest), &dword(header), &word(32),]
        )
        .unwrap(),
        WAVERR_UNPREPARED
    );
    assert!(host.calls.is_empty());
    assert_eq!(read_bytes(&runtime, 0x120, 32), wave_header(0, 0));

    for ordinal in [405_u16, 409, 410, 411] {
        host.calls.clear();
        assert_eq!(
            invoke(&mut runtime, &mut host, ordinal, &[&word(0)]).unwrap(),
            MMSYSERR_INVALHANDLE
        );
        assert!(host.calls.is_empty());
    }
}

#[test]
fn wave_out_get_position_rejects_a_short_buffer() {
    let (mut runtime, selector) = fixture();
    let time = far(selector, 0);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            412,
            &[&word(1), &dword(time), &word(7)]
        )
        .unwrap(),
        MMSYSERR_INVALPARAM
    );
    assert!(host.calls.is_empty());
    assert_eq!(read_bytes(&runtime, 0, 8), vec![SENTINEL; 8]);
}

#[test]
fn midi_out_get_num_devs_keeps_a_word_count() {
    let (mut runtime, _) = fixture();
    let mut host = PlaybackHost {
        midi_count: 4,
        ..PlaybackHost::default()
    };
    assert_eq!(invoke(&mut runtime, &mut host, 201, &[]).unwrap(), 4);

    let (mut runtime, _) = fixture();
    let mut host = PlaybackHost {
        midi_count: 0x1_0000,
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(&mut runtime, &mut host, 201, &[])
            .unwrap_err()
            .kind(),
        Kind::CompatibilityGap
    );
    assert_eq!(runtime.cpu.regs.eax, EAX_SENTINEL);
}

#[test]
fn midi_out_get_dev_caps_leaves_memory_on_failure() {
    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            202,
            &[&word(3), &dword(0), &word(0)]
        )
        .unwrap(),
        0
    );
    assert!(host.calls.is_empty());

    let mut host = PlaybackHost {
        midi_caps_result: u32::from(MMSYSERR_BADDEVICEID),
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            202,
            &[&word(3), &dword(output), &word(50)]
        )
        .unwrap(),
        MMSYSERR_BADDEVICEID
    );
    assert_eq!(read_bytes(&runtime, 0, 50), vec![SENTINEL; 50]);

    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            202,
            &[&word(0), &dword(output), &word(4)]
        )
        .unwrap(),
        0
    );
    let bytes = read_bytes(&runtime, 0, 6);
    assert_eq!(&bytes[..2], &0x0011_u16.to_le_bytes());
    assert_eq!(&bytes[2..4], &0x0022_u16.to_le_bytes());
    assert_eq!(&bytes[4..], &[SENTINEL; 2]);
}

#[test]
fn midi_out_get_error_text_uses_the_3_1_range() {
    let (mut runtime, selector) = fixture();
    let output = far(selector, 0);
    let mut host = PlaybackHost::default();
    for error in [12_u16, 32, 72] {
        host.calls.clear();
        assert_eq!(
            invoke(
                &mut runtime,
                &mut host,
                203,
                &[&word(error), &dword(output), &word(16)]
            )
            .unwrap(),
            MMSYSERR_BADERRNUM,
        );
        assert!(host.calls.is_empty());
        assert_eq!(read_bytes(&runtime, 0, 16), vec![SENTINEL; 16]);
    }
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            203,
            &[&word(0), &dword(0), &word(0)]
        )
        .unwrap(),
        0
    );
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            203,
            &[&word(MIDIERR_UNPREPARED), &dword(output), &word(8)]
        )
        .unwrap(),
        0,
    );
    let bytes = read_bytes(&runtime, 0, 8);
    assert_eq!(&bytes[..5], b"midi\0");
    assert_eq!(&bytes[5..], &[SENTINEL; 3]);
}

#[test]
fn midi_out_open_failure_leaves_the_handle() {
    let (mut runtime, selector) = fixture();
    let handle = far(selector, 0);
    let mut host = PlaybackHost {
        midi_open_result: u32::from(MMSYSERR_BADDEVICEID),
        ..PlaybackHost::default()
    };
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            204,
            &[
                &dword(handle),
                &word(0xFFFF),
                &dword(0),
                &dword(0),
                &dword(0),
            ]
        )
        .unwrap(),
        MMSYSERR_BADDEVICEID
    );
    assert_eq!(host.calls, ["midi-open"]);
    assert_eq!(read_bytes(&runtime, 0, 2), vec![SENTINEL; 2]);
}

#[test]
fn midi_out_short_long_and_reset_use_documented_failures() {
    let (mut runtime, selector) = fixture();
    let header = far(selector, 0x140);
    write_bytes(&mut runtime, 0x140, &[SENTINEL; 28]);
    let mut host = PlaybackHost::default();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            208,
            &[&word(0), &dword(0x90_3C_40)]
        )
        .unwrap(),
        MMSYSERR_INVALHANDLE
    );
    assert_eq!(
        invoke(&mut runtime, &mut host, 210, &[&word(0)]).unwrap(),
        MMSYSERR_INVALHANDLE
    );
    assert!(host.calls.is_empty());

    let handle = far(selector, 0);
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            204,
            &[&dword(handle), &word(0), &dword(0), &dword(0), &dword(0),]
        )
        .unwrap(),
        0
    );
    let guest = u16::from_le_bytes(read_bytes(&runtime, 0, 2).try_into().unwrap());
    host.calls.clear();
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            209,
            &[&word(guest), &dword(header), &word(28),]
        )
        .unwrap(),
        MIDIERR_UNPREPARED
    );
    assert_eq!(
        invoke(
            &mut runtime,
            &mut host,
            209,
            &[&word(guest), &dword(header), &word(10),]
        )
        .unwrap(),
        MMSYSERR_INVALPARAM
    );
    assert!(host.calls.is_empty());
    assert_eq!(read_bytes(&runtime, 0x140, 28), vec![SENTINEL; 28]);
}
