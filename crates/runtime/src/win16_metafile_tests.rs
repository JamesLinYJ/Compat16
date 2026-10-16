//! Metafile service gates and callback stack layout without native graphics.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use super::*;
use crate::*;
use crate::{RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, PhysAddr, Selector};
use std::{collections::VecDeque, sync::Arc};
use win16_abi::{Access, AccessRights, ExportLookupTarget, Win16ReturnKind, lookup_export};

#[path = "win16_metafile_test_host.rs"]
mod host;
use host::MetafileHost;

fn fixture() -> (Runtime, MetafileHost, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\METAFILE.NE").unwrap();
    runtime.cpu.regs.set_sp(0xc0);
    let dc = runtime
        .win16
        .as_mut()
        .unwrap()
        .guest_gdi
        .allocate_dc(Win16HostDc(0x1234_5678_0000_0001))
        .unwrap();
    (runtime, MetafileHost::default(), dc)
}
fn buffer(runtime: &mut Runtime, base: u32, bytes: &[u8], writable: bool) -> u32 {
    runtime.memory.write(PhysAddr(base), bytes).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(base),
            bytes.len() as u32,
            if writable {
                AccessRights::read_write()
            } else {
                AccessRights::read_only()
            },
            &runtime.memory,
        )
        .unwrap();
    state
        .selectors
        .pointer_from_raw(selector.raw(), 0)
        .unwrap()
        .far_value()
}
fn record(function: u16, parameters: &[u16]) -> Vec<u8> {
    let mut bytes = ((parameters.len() + 3) as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&function.to_le_bytes());
    for p in parameters {
        bytes.extend_from_slice(&p.to_le_bytes());
    }
    bytes
}
fn dispatch(
    runtime: &mut Runtime,
    host: &mut MetafileHost,
    ordinal: u16,
    physical: &[u8],
) -> (u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let saved_cs = runtime.cpu.regs.cs;
    let sp = runtime.cpu.regs.sp();
    let mut stack = 0x12u16.to_le_bytes().to_vec();
    stack.extend_from_slice(&saved_cs.to_le_bytes());
    stack.extend_from_slice(physical);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), sp)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &stack)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    state
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            host,
            0,
        )
        .unwrap();
    (saved_cs, sp + stack.len() as u16)
}
fn play(
    runtime: &mut Runtime,
    host: &mut MetafileHost,
    dc: u16,
    table: u32,
    record: u32,
    count: u16,
) {
    let mut args = count.to_le_bytes().to_vec();
    args.extend_from_slice(&record.to_le_bytes());
    args.extend_from_slice(&table.to_le_bytes());
    args.extend_from_slice(&dc.to_le_bytes());
    let (cs, sp) = dispatch(runtime, host, 176, &args);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        (cs, 0x12, sp)
    );
    assert_eq!(
        (runtime.cpu.regs.ax(), runtime.cpu.regs.dx()),
        (0xa55a, 0x5aa5),
        "Win16 void ABI"
    );
    runtime.cpu.regs.set_sp(sp - 16);
}
#[test]
fn metafile_record_creation_and_deletion_publish_exact_guest_aliases_and_void_abi() {
    let (mut runtime, mut host, dc) = fixture();
    assert_eq!(
        lookup_export(b"GDI", ExportLookupTarget::Ordinal(176))
            .unwrap()
            .return_kind,
        Win16ReturnKind::Void
    );
    let table = buffer(&mut runtime, 0x88000, &[0, 0], true);
    let create = buffer(
        &mut runtime,
        0x89000,
        &record(0x02fa, &[0, 1, 0, 0xff, 0]),
        false,
    );
    play(&mut runtime, &mut host, dc, table, create, 1);
    let mut word = [0; 2];
    runtime.memory.read(PhysAddr(0x88000), &mut word).unwrap();
    let handle = u16::from_le_bytes(word);
    assert_ne!(handle, 0);
    assert_eq!(
        runtime.win16.as_ref().unwrap().guest_gdi.object(handle),
        Some(Win16HostGdiObject(0xfedc_0000_0000_0001))
    );
    let delete = buffer(&mut runtime, 0x8a000, &record(0x01f0, &[0]), false);
    play(&mut runtime, &mut host, dc, table, delete, 1);
    runtime.memory.read(PhysAddr(0x88000), &mut word).unwrap();
    assert_eq!(word, [0, 0]);
    assert!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .guest_gdi
            .object(handle)
            .is_none()
    );
    assert_eq!(host.calls, 2);
}
#[test]
fn metafile_record_invalid_table_extent_precedes_native_side_effects() {
    let (mut runtime, mut host, dc) = fixture();
    let table = buffer(&mut runtime, 0x88000, &[0, 0], false);
    let create = buffer(
        &mut runtime,
        0x89000,
        &record(0x02fa, &[0, 1, 0, 0xff, 0]),
        false,
    );
    let state = runtime.win16.as_mut().unwrap();
    assert!(
        state
            .play_metafile_record(dc, table, create, 1, &mut runtime.memory, &mut host)
            .is_err()
    );
    assert_eq!(host.calls, 0);
}
fn enum_fixture(runtime: &mut Runtime, host: &mut MetafileHost, dc: u16) -> (u32, u16) {
    enum_records(
        runtime,
        host,
        dc,
        &[record(0x0214, &[1, 2]), record(0x0213, &[3, 4])],
    )
}
fn enum_records(
    runtime: &mut Runtime,
    host: &mut MetafileHost,
    dc: u16,
    records: &[Vec<u8>],
) -> (u32, u16) {
    let mut bits = vec![0; 18];
    bits[0] = 1;
    bits[2] = 9;
    bits[4..6].copy_from_slice(&0x300u16.to_le_bytes());
    bits[10..12].copy_from_slice(&1u16.to_le_bytes());
    for r in records {
        bits.extend_from_slice(r);
    }
    bits.extend(record(0, &[]));
    let words = (bits.len() / 2) as u32;
    bits[6..10].copy_from_slice(&words.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let metafile = state
        .allocate_metafile_global(&bits, 0, &mut runtime.cpu.regs, &mut runtime.memory, host)
        .unwrap();
    let procedure = (u32::from(runtime.cpu.regs.cs) << 16) | 0x20;
    let pointer = state.selectors.pointer_from_far(procedure).unwrap();
    let address = state
        .selectors
        .translate(pointer, Access::Execute, 6, &runtime.memory)
        .unwrap();
    runtime
        .memory
        .write(address, &[0xb8, 1, 0, 0xca, 16, 0])
        .unwrap(); // MOV AX,1; RETF 16
    let mut args = 0x89ab_cdefu32.to_le_bytes().to_vec();
    args.extend_from_slice(&procedure.to_le_bytes());
    args.extend_from_slice(&metafile.to_le_bytes());
    args.extend_from_slice(&dc.to_le_bytes());
    let (_, returned_sp) = dispatch(runtime, host, 175, &args);
    (procedure, returned_sp)
}
#[test]
fn metafile_callback_uses_five_pascal_arguments_and_cleans_every_record_frame() {
    let (mut runtime, mut host, dc) = fixture();
    let (procedure, returned_sp) = enum_fixture(&mut runtime, &mut host, dc);
    for function in [0x0214, 0x0213] {
        let state = runtime.win16.as_mut().unwrap();
        let caller_sp = runtime.cpu.regs.sp();
        assert!(
            state
                .service_pending_native_function_callback(
                    &mut runtime.cpu,
                    &mut runtime.dos,
                    &mut runtime.memory
                )
                .unwrap()
        );
        assert_eq!(runtime.cpu.regs.cs, (procedure >> 16) as u16);
        assert_eq!(runtime.cpu.regs.sp(), caller_sp - 20);
        let stack = state
            .selectors
            .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
            .unwrap();
        let stack = state.read_text_bytes(&runtime.memory, stack, 20).unwrap();
        assert_eq!(
            u32::from_le_bytes(stack[4..8].try_into().unwrap()),
            0x89ab_cdef
        );
        assert_eq!(u16::from_le_bytes(stack[8..10].try_into().unwrap()), 1);
        let record = u32::from_le_bytes(stack[10..14].try_into().unwrap());
        let table = u32::from_le_bytes(stack[14..18].try_into().unwrap());
        assert_eq!(u16::from_le_bytes(stack[18..20].try_into().unwrap()), dc);
        let p = state.selectors.pointer_from_far(record).unwrap();
        let bytes = state.read_text_bytes(&runtime.memory, p, 6).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), function);
        assert!(state.metafile_callback_for_table(table, 1).is_some());
        let segments = crate::win16_loader::Win16Segments {
            selectors: &state.selectors,
            memory_len: runtime.memory.len(),
        };
        runtime
            .cpu
            .step_with_context(
                &mut runtime.memory.bus(),
                &mut guest_core::io::NoPorts,
                &segments,
            )
            .unwrap();
        runtime
            .cpu
            .step_with_context(
                &mut runtime.memory.bus(),
                &mut guest_core::io::NoPorts,
                &segments,
            )
            .unwrap();
        state
            .record_window_callback_return(
                super::super::CallbackKind::NativeFunction,
                runtime.cpu.control_transfer().unwrap(),
            )
            .unwrap();
        state
            .finish_native_function_callback(
                &mut runtime.cpu,
                &mut runtime.dos,
                &mut runtime.memory,
                &mut host,
            )
            .unwrap();
    }
    let state = runtime.win16.as_mut().unwrap();
    state
        .drive_pending_window_completion(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut host,
        )
        .unwrap();
    assert!(state.native_function_callbacks.is_empty());
    assert!(state.window_operations.is_empty());
    assert_eq!(runtime.cpu.regs.sp(), returned_sp);
    assert_eq!(runtime.cpu.regs.ax(), 1);
    assert_eq!(host.commits, 2);
    assert_eq!(host.consumed, 1);
}

fn enter_callback(runtime: &mut Runtime) {
    let state = runtime.win16.as_mut().unwrap();
    assert!(
        state
            .service_pending_native_function_callback(
                &mut runtime.cpu,
                &mut runtime.dos,
                &mut runtime.memory
            )
            .unwrap()
    );
}
fn return_callback(runtime: &mut Runtime, host: &mut MetafileHost) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    let segments = crate::win16_loader::Win16Segments {
        selectors: &state.selectors,
        memory_len: runtime.memory.len(),
    };
    runtime
        .cpu
        .step_with_context(
            &mut runtime.memory.bus(),
            &mut guest_core::io::NoPorts,
            &segments,
        )
        .unwrap();
    runtime
        .cpu
        .step_with_context(
            &mut runtime.memory.bus(),
            &mut guest_core::io::NoPorts,
            &segments,
        )
        .unwrap();
    state
        .record_window_callback_return(
            super::super::CallbackKind::NativeFunction,
            runtime.cpu.control_transfer().unwrap(),
        )
        .unwrap();
    state.finish_native_function_callback(
        &mut runtime.cpu,
        &mut runtime.dos,
        &mut runtime.memory,
        host,
    )
}
fn complete(runtime: &mut Runtime, host: &mut MetafileHost) {
    runtime
        .win16
        .as_mut()
        .unwrap()
        .drive_pending_window_completion(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            host,
        )
        .unwrap();
}
fn callback_table(runtime: &Runtime) -> u32 {
    let state = runtime.win16.as_ref().unwrap();
    let stack = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    let bytes = state.read_text_bytes(&runtime.memory, stack, 20).unwrap();
    u32::from_le_bytes(bytes[14..18].try_into().unwrap())
}
#[test]
fn metafile_callback_early_stop_and_signed_nonzero_return_follow_bool_contract() {
    for value in [0u16, 0xffff] {
        let (mut runtime, mut host, dc) = fixture();
        let (procedure, _) = enum_fixture(&mut runtime, &mut host, dc);
        let state = runtime.win16.as_mut().unwrap();
        let p = state.selectors.pointer_from_far(procedure).unwrap();
        let address = state
            .selectors
            .translate(p, Access::Execute, 6, &runtime.memory)
            .unwrap();
        runtime
            .memory
            .write(
                address,
                &[0xb8, value as u8, (value >> 8) as u8, 0xca, 16, 0],
            )
            .unwrap();
        let expected = if value == 0 { 1 } else { 2 };
        for _ in 0..expected {
            enter_callback(&mut runtime);
            return_callback(&mut runtime, &mut host).unwrap();
        }
        complete(&mut runtime, &mut host);
        assert_eq!(host.commits, expected);
        assert_eq!(runtime.cpu.regs.ax(), u16::from(value != 0));
        assert!(
            runtime
                .win16
                .as_ref()
                .unwrap()
                .native_function_callbacks
                .is_empty()
        );
    }
}
#[test]
fn metafile_callback_table_edits_survive_record_buffer_replacement() {
    let (mut runtime, mut host, dc) = fixture();
    let token = Win16HostGdiObject(0xfedc_0000_0000_0011);
    let handle = runtime
        .win16
        .as_mut()
        .unwrap()
        .guest_gdi
        .allocate_object(token)
        .unwrap();
    enum_fixture(&mut runtime, &mut host, dc);
    enter_callback(&mut runtime);
    let table = callback_table(&runtime);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_far(table).unwrap();
    state
        .write_text_bytes(&mut runtime.memory, pointer, &handle.to_le_bytes())
        .unwrap();
    return_callback(&mut runtime, &mut host).unwrap();
    assert_eq!(host.tables.last().unwrap(), &vec![Some(token)]);
    enter_callback(&mut runtime);
    let table = callback_table(&runtime);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(table).unwrap();
    assert_eq!(
        state.read_text_bytes(&runtime.memory, pointer, 2).unwrap(),
        handle.to_le_bytes()
    );
    return_callback(&mut runtime, &mut host).unwrap();
    complete(&mut runtime, &mut host);
}
#[test]
fn metafile_callback_cleanup_retry_does_not_replay_guest_or_table_acknowledgement() {
    let (mut runtime, mut host, dc) = fixture();
    enum_fixture(&mut runtime, &mut host, dc);
    enter_callback(&mut runtime);
    let table = callback_table(&runtime);
    let selector = (table >> 16) as u16;
    assert_eq!(
        runtime
            .win16
            .as_mut()
            .unwrap()
            .kernel_global_page_lock(selector)
            .unwrap(),
        1
    );
    assert!(return_callback(&mut runtime, &mut host).is_err());
    assert_eq!(host.commits, 1);
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.native_function_callbacks.len(), 1);
    assert_eq!(state.kernel_global_page_unlock(selector).unwrap(), 0);
    state
        .finish_native_function_callback(
            &mut runtime.cpu,
            &mut runtime.dos,
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(host.commits, 1);
    enter_callback(&mut runtime);
    return_callback(&mut runtime, &mut host).unwrap();
    complete(&mut runtime, &mut host);
    assert_eq!(host.commits, 2);
    assert_eq!(host.consumed, 1);
}

#[test]
fn metafile_nested_guest_enumeration_preserves_outer_callback_and_cpu_owners() {
    let (mut runtime, mut host, dc) = fixture();
    enum_fixture(&mut runtime, &mut host, dc);
    enter_callback(&mut runtime);
    let outer_table = callback_table(&runtime);
    let outer_sp = runtime.cpu.regs.sp();
    runtime.cpu.regs.set_sp(outer_sp - 16);
    enum_fixture(&mut runtime, &mut host, dc);
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .native_function_callbacks
            .len(),
        2
    );
    for _ in 0..2 {
        enter_callback(&mut runtime);
        return_callback(&mut runtime, &mut host).unwrap();
    }
    complete(&mut runtime, &mut host);
    assert_eq!(runtime.cpu.regs.sp(), outer_sp);
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .native_function_callbacks
            .len(),
        1
    );
    assert_eq!(callback_table(&runtime), outer_table);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.cs), 0x12)
        .unwrap();
    let address = state
        .selectors
        .translate(pointer, Access::Execute, 6, &runtime.memory)
        .unwrap();
    runtime
        .memory
        .write(address, &[0xb8, 1, 0, 0xca, 16, 0])
        .unwrap();
    return_callback(&mut runtime, &mut host).unwrap();
    enter_callback(&mut runtime);
    return_callback(&mut runtime, &mut host).unwrap();
    complete(&mut runtime, &mut host);
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.native_function_callbacks.is_empty());
    assert!(state.window_operations.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
    assert_eq!(host.commits, 4);
    assert_eq!(host.consumed, 2);
}
#[test]
fn metafile_huge_record_callback_checks_and_releases_every_selector() {
    let (mut runtime, mut host, dc) = fixture();
    let bytes = record(0x7777, &vec![0u16; 40000]);
    enum_records(&mut runtime, &mut host, dc, &[bytes.clone()]);
    let before = runtime.win16.as_ref().unwrap().heap.allocation_count();
    enter_callback(&mut runtime);
    let state = runtime.win16.as_ref().unwrap();
    let stack = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    let stack = state.read_text_bytes(&runtime.memory, stack, 20).unwrap();
    let record = u32::from_le_bytes(stack[10..14].try_into().unwrap());
    let pointer = state.selectors.pointer_from_far(record).unwrap();
    assert_eq!(
        state
            .read_text_bytes(&runtime.memory, pointer, bytes.len())
            .unwrap(),
        bytes
    );
    return_callback(&mut runtime, &mut host).unwrap();
    complete(&mut runtime, &mut host);
    assert_eq!(
        runtime.win16.as_ref().unwrap().heap.allocation_count(),
        before - 1
    );
}
