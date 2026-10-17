//! WINMEM32 dispatch: checked guest selectors, tiled objects, and aliases.

use guest_core::Selector;
use win16_abi::{AccessRights, ExportLookupTarget, Win16ReturnKind, lookup_export};

use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::{Runtime, RuntimeError};

const RETURN_IP: u16 = 0x0012;
const DX_SENTINEL: u16 = 0x5aa5;

enum Arg {
    Word(u16),
    Dword(u32),
}

fn invoke(runtime: &mut Runtime, ordinal: u16, args: &[Arg]) -> Result<u16, RuntimeError> {
    let descriptor = lookup_export(b"WINMEM32", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    runtime.cpu.regs.set_sp(0x80);
    let return_cs = runtime.cpu.regs.cs;
    let stack = runtime.cpu.regs.sp();
    let mut frame = Vec::from(RETURN_IP.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    for arg in args.iter().rev() {
        match arg {
            Arg::Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
            Arg::Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
        }
    }
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
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        &mut NoHost,
        0,
    )?;
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    assert_eq!(runtime.cpu.regs.cs, return_cs);
    assert_eq!(runtime.cpu.regs.ip(), RETURN_IP);
    assert_eq!(
        runtime.cpu.regs.sp(),
        stack.wrapping_add(frame.len() as u16)
    );
    Ok(runtime.cpu.regs.ax())
}

fn fresh() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], b"C:\\WINMEM.NE").unwrap()
}

fn far(runtime: &Runtime, offset: u16) -> u32 {
    (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(offset)
}

fn write_ds(runtime: &mut Runtime, offset: u16, bytes: &[u8]) {
    let ds = runtime.cpu.regs.ds;
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(ds), offset)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
}

fn read_ds(runtime: &Runtime, offset: u16, bytes: &mut [u8]) {
    let ds = runtime.cpu.regs.ds;
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(ds), offset)
        .unwrap();
    state
        .selectors
        .read(&runtime.memory, pointer, bytes)
        .unwrap();
}

fn read_word(runtime: &Runtime, offset: u16) -> u16 {
    let mut bytes = [0; 2];
    read_ds(runtime, offset, &mut bytes);
    u16::from_le_bytes(bytes)
}

fn read_dword(runtime: &Runtime, offset: u16) -> u32 {
    let mut bytes = [0; 4];
    read_ds(runtime, offset, &mut bytes);
    u32::from_le_bytes(bytes)
}

fn write_selector(runtime: &mut Runtime, selector: u16, offset: u16, bytes: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(selector), offset)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
}

fn read_selector(runtime: &Runtime, selector: u16, offset: u16, bytes: &mut [u8]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(selector), offset)
        .unwrap();
    state
        .selectors
        .read(&runtime.memory, pointer, bytes)
        .unwrap();
}

#[test]
fn version_is_1_00_and_rejected_alloc_writes_nothing() {
    let mut runtime = fresh();
    assert_eq!(invoke(&mut runtime, 1, &[]).unwrap(), 0x0100);

    write_ds(&mut runtime, 0x10, &0xffff_u16.to_le_bytes());
    let output = far(&runtime, 0x10);
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(32),
                Arg::Dword(output),
                Arg::Dword(64),
                Arg::Word(1)
            ],
        )
        .unwrap(),
        2,
    );
    assert_eq!(read_word(&runtime, 0x10), 0xffff);
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(0),
                Arg::Dword(output),
                Arg::Dword(64),
                Arg::Word(0)
            ],
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(128),
                Arg::Dword(output),
                Arg::Dword(64),
                Arg::Word(0)
            ],
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(16),
                Arg::Dword(output),
                Arg::Dword(0x0400_0001),
                Arg::Word(0),
            ],
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[Arg::Dword(16), Arg::Dword(0), Arg::Dword(16), Arg::Word(0)],
        )
        .unwrap(),
        3,
    );
    assert_eq!(read_word(&runtime, 0x10), 0xffff);
}

#[test]
fn alloc_realloc_and_free_use_checked_guest_selectors() {
    let mut runtime = fresh();
    let output = far(&runtime, 0x10);
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(0x40),
                Arg::Dword(output),
                Arg::Dword(0x1_0020),
                Arg::Word(0)
            ],
        )
        .unwrap(),
        0,
    );
    let selector = read_word(&runtime, 0x10);
    assert_ne!(selector, 0);
    assert_eq!(selector & 0x7, 0);
    write_selector(&mut runtime, selector, 0, &[0xa5, 0x5a]);
    let mut bytes = [0; 2];
    read_selector(&runtime, selector, 0, &mut bytes);
    assert_eq!(bytes, [0xa5, 0x5a]);

    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(selector), Arg::Dword(0x1_0020), Arg::Word(1)]
        )
        .unwrap(),
        2,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(0), Arg::Dword(0x20), Arg::Word(0)]
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(selector), Arg::Dword(0x1_0021), Arg::Word(0)],
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(selector), Arg::Dword(0x1_0020), Arg::Word(0)],
        )
        .unwrap(),
        0,
    );
    assert_eq!(read_word(&runtime, 0x10), selector);
    read_selector(&runtime, selector, 0, &mut bytes);
    assert_eq!(bytes, [0xa5, 0x5a]);
    write_selector(&mut runtime, selector.wrapping_add(8), 0, &[0x11]);
    let state = runtime.win16.as_ref().unwrap();
    let head = state
        .selectors
        .describe(state.selectors.reference(Selector(selector)).unwrap())
        .unwrap();
    let tile = state
        .selectors
        .describe(
            state
                .selectors
                .reference(Selector(selector.wrapping_add(8)))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(head.limit, 0xffff);
    assert_eq!(
        state
            .selectors
            .allocation_size(state.selectors.reference(Selector(selector)).unwrap())
            .unwrap(),
        0x1_0020
    );
    assert_eq!(tile.base.0, head.base.0 + 0x1_0000);
    assert!(!head.rights.executable());
    assert!(head.rights.writable());

    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(selector), Arg::Dword(0x40), Arg::Word(0)]
        )
        .unwrap(),
        0,
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .selectors
            .pointer_from_raw(Selector(selector.wrapping_add(8)), 0)
            .is_err()
    );
    read_selector(&runtime, selector, 0, &mut bytes);
    assert_eq!(bytes, [0xa5, 0x5a]);

    assert_eq!(
        invoke(&mut runtime, 4, &[Arg::Word(selector), Arg::Word(1)]).unwrap(),
        2
    );
    read_selector(&runtime, selector, 0, &mut bytes);
    assert_eq!(
        invoke(&mut runtime, 4, &[Arg::Word(selector), Arg::Word(0)]).unwrap(),
        0
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .selectors
            .pointer_from_raw(Selector(selector), 0)
            .is_err()
    );
    assert_eq!(
        invoke(&mut runtime, 4, &[Arg::Word(selector), Arg::Word(0)]).unwrap(),
        3
    );
}

#[test]
fn aliases_are_guest_selectors_and_die_with_the_object() {
    let mut runtime = fresh();
    let selector_out = far(&runtime, 0x10);
    let alias_out = far(&runtime, 0x14);
    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(0x1_0020),
                Arg::Dword(selector_out),
                Arg::Dword(0x1_0020),
                Arg::Word(0),
            ],
        )
        .unwrap(),
        0,
    );
    let selector = read_word(&runtime, 0x10);
    write_ds(&mut runtime, 0x14, &0u32.to_le_bytes());
    assert_eq!(
        invoke(
            &mut runtime,
            5,
            &[
                Arg::Word(selector),
                Arg::Dword(0xfff8),
                Arg::Dword(alias_out),
                Arg::Dword(0x1_0001),
                Arg::Word(0),
            ],
        )
        .unwrap(),
        3,
    );
    assert_eq!(read_dword(&runtime, 0x14), 0);
    assert_eq!(
        invoke(
            &mut runtime,
            5,
            &[
                Arg::Word(selector),
                Arg::Dword(0xfff8),
                Arg::Dword(alias_out),
                Arg::Dword(0x20),
                Arg::Word(0),
            ],
        )
        .unwrap(),
        0,
    );
    let alias = read_dword(&runtime, 0x14);
    assert_eq!(alias & 0xffff, 0, "16-bit alias offset stays zero");
    let alias_selector = (alias >> 16) as u16;
    assert_ne!(alias_selector, selector);
    assert_eq!(alias_selector & 0x7, 0);
    write_selector(&mut runtime, alias_selector, 0, &[0x11]);
    write_selector(&mut runtime, alias_selector, 0x1f, &[0x22]);
    let mut byte = [0];
    read_selector(&runtime, selector, 0xfff8, &mut byte);
    assert_eq!(byte, [0x11]);
    read_selector(&runtime, selector.wrapping_add(8), 0x17, &mut byte);
    assert_eq!(byte, [0x22]);

    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(selector), Arg::Dword(0x1000), Arg::Word(0)]
        )
        .unwrap(),
        3,
    );
    read_selector(&runtime, alias_selector, 0, &mut byte);
    assert_eq!(byte, [0x11]);
    assert_eq!(
        invoke(
            &mut runtime,
            6,
            &[Arg::Word(selector), Arg::Dword(alias), Arg::Word(0)]
        )
        .unwrap(),
        0,
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .selectors
            .pointer_from_raw(Selector(alias_selector), 0)
            .is_err()
    );
    assert_eq!(
        invoke(
            &mut runtime,
            6,
            &[Arg::Word(selector), Arg::Dword(alias), Arg::Word(0)]
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            3,
            &[Arg::Word(selector), Arg::Dword(0x1000), Arg::Word(0)]
        )
        .unwrap(),
        0,
    );

    write_ds(&mut runtime, 0x18, &0xffff_u16.to_le_bytes());
    let code_out = far(&runtime, 0x18);
    assert_eq!(
        invoke(
            &mut runtime,
            7,
            &[Arg::Word(selector), Arg::Dword(code_out), Arg::Word(0)],
        )
        .unwrap(),
        0,
    );
    let code = read_word(&runtime, 0x18);
    assert_ne!(code, selector);
    assert_ne!(code, 0xffff);
    let state = runtime.win16.as_ref().unwrap();
    let described = state
        .selectors
        .describe(state.selectors.reference(Selector(code)).unwrap())
        .unwrap();
    assert!(described.rights.executable());
    assert!(described.rights.readable());
    assert!(!described.rights.writable());
    assert_eq!(described.rights, AccessRights::code());
    write_selector(&mut runtime, selector, 0, &[0x3c]);
    read_selector(&runtime, code, 0, &mut byte);
    assert_eq!(byte, [0x3c]);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(code), 0).unwrap();
    assert!(
        state
            .selectors
            .write(&mut runtime.memory, pointer, &[0x7e])
            .is_err()
    );

    assert_eq!(
        invoke(
            &mut runtime,
            8,
            &[Arg::Word(selector), Arg::Word(selector), Arg::Word(0)]
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            6,
            &[
                Arg::Word(selector),
                Arg::Dword(u32::from(code) << 16),
                Arg::Word(0)
            ]
        )
        .unwrap(),
        3,
    );
    assert_eq!(
        invoke(
            &mut runtime,
            8,
            &[Arg::Word(selector), Arg::Word(code), Arg::Word(0)]
        )
        .unwrap(),
        0
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .selectors
            .pointer_from_raw(Selector(code), 0)
            .is_err()
    );
    read_selector(&runtime, selector, 0, &mut byte);
    assert_eq!(byte, [0x3c]);
    assert_eq!(
        invoke(&mut runtime, 4, &[Arg::Word(selector), Arg::Word(0)]).unwrap(),
        0
    );
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .selectors
            .pointer_from_raw(Selector(selector), 0)
            .is_err()
    );

    assert_eq!(
        invoke(
            &mut runtime,
            2,
            &[
                Arg::Dword(64),
                Arg::Dword(selector_out),
                Arg::Dword(64),
                Arg::Word(0),
            ],
        )
        .unwrap(),
        0,
    );
    let held = read_word(&runtime, 0x10);
    assert_eq!(
        invoke(
            &mut runtime,
            5,
            &[
                Arg::Word(held),
                Arg::Dword(8),
                Arg::Dword(alias_out),
                Arg::Dword(4),
                Arg::Word(0),
            ],
        )
        .unwrap(),
        0,
    );
    let held_alias = (read_dword(&runtime, 0x14) >> 16) as u16;
    assert_eq!(
        invoke(&mut runtime, 4, &[Arg::Word(held), Arg::Word(0)]).unwrap(),
        0,
    );
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.selectors.pointer_from_raw(Selector(held), 0).is_err());
    assert!(
        state
            .selectors
            .pointer_from_raw(Selector(held_alias), 0)
            .is_err()
    );
}
