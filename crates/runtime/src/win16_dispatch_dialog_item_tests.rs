//! GetDlgItemInt when the dialog handle is not a window.

use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::{Runtime, RuntimeError};
use Win16Argument::{Dword, Word};
use guest_core::Selector;
use win16_abi::{
    ExportLookupTarget, Win16Argument, Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const OFFSET: u16 = 0x30;
const AX: u16 = 0xa55a;
const DX: u16 = 0x5aa5;

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\DLGITEM.NE").unwrap()
}

fn far(runtime: &Runtime) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(OFFSET)
}

fn write_word(runtime: &mut Runtime, value: u16) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &value.to_le_bytes())
        .unwrap();
}

fn read_word(runtime: &Runtime) -> u16 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far(runtime)).unwrap();
    let mut bytes = [0u8; 2];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    u16::from_le_bytes(bytes)
}

fn prepare(runtime: &mut Runtime, arguments: &[Win16Argument]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(95)).unwrap();
    assert_eq!(
        descriptor.id,
        lookup_export(b"USER", ExportLookupTarget::Name(b"GetDlgItemInt"))
            .unwrap()
            .id,
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("GetDlgItemInt uses a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 10);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    for argument in arguments.iter().rev() {
        match argument {
            Word(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            Dword(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            _ => panic!("unexpected GetDlgItemInt argument width"),
        }
    }
    assert_eq!(bytes.len(), 14);
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
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut NoHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

#[test]
fn get_dlg_item_int_stores_false_when_the_dialog_is_missing() {
    let mut runtime = fixture();
    write_word(&mut runtime, 0xFFFF);
    let translated = far(&runtime);
    let return_to = prepare(
        &mut runtime,
        &[Word(0), Word(0xFFFF), Dword(translated), Word(0)],
    );
    let mut host = NoHost;
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
    assert_eq!(read_word(&runtime), 0);
}

#[test]
fn get_dlg_item_int_leaves_memory_alone_when_translated_is_null() {
    let mut runtime = fixture();
    write_word(&mut runtime, 0xFFFF);
    let return_to = prepare(&mut runtime, &[Word(7), Word(0xFFFF), Dword(0), Word(1)]);
    let mut host = NoHost;
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
    assert_eq!(read_word(&runtime), 0xFFFF);
}
