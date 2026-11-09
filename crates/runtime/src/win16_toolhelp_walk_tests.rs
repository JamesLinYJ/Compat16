//! ToolHelp memory-walk contracts: task-image lock counts, BP frames, and module identity.

use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::Runtime;
use guest_core::Selector;
use win16_abi::toolhelp_abi::{
    GlobalEntry16, ModuleEntry16, StackTraceEntry16, GLOBAL_ALL, GT_CODE, GT_DGROUP,
};
use win16_abi::{ExportLookupTarget, Win16Argument, lookup_export};

const FRAME_FAR: u16 = 0;
const FRAME_NEAR: u16 = 1;
const OUTPUT_OFFSET: u16 = 0x200;

fn load() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\TOOLHELP.NE").unwrap()
}

fn far_pointer(selector: u16, offset: u16) -> u32 {
    (u32::from(selector) << 16) | u32::from(offset)
}

fn write_guest(runtime: &mut Runtime, selector: u16, offset: u16, bytes: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(selector), offset).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, bytes).unwrap();
}

fn read_guest(runtime: &Runtime, selector: u16, offset: u16, bytes: &mut [u8]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(selector), offset).unwrap();
    state.selectors.read(&runtime.memory, pointer, bytes).unwrap();
}

fn prepare_output(runtime: &mut Runtime, selector: u16, size: u32) -> u32 {
    prepare_at(runtime, selector, OUTPUT_OFFSET, size)
}

fn prepare_at(runtime: &mut Runtime, selector: u16, offset: u16, size: u32) -> u32 {
    write_guest(runtime, selector, offset, &size.to_le_bytes());
    far_pointer(selector, offset)
}

fn read_global(runtime: &Runtime, selector: u16) -> GlobalEntry16 {
    let mut bytes = [0_u8; GlobalEntry16::SIZE];
    read_guest(runtime, selector, OUTPUT_OFFSET, &mut bytes);
    GlobalEntry16::decode(&bytes)
}

fn entry_module(runtime: &mut Runtime, module: u16, segment: u16, caller_code: u16) -> GlobalEntry16 {
    let selector = runtime.cpu.regs.ss;
    let output = prepare_output(runtime, selector, GlobalEntry16::SIZE as u32);
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(
        state.toolhelp_global_entry_module(
            output, module, segment, caller_code, &mut runtime.memory,
        ).unwrap(),
        1,
    );
    read_global(runtime, selector)
}

#[test]
fn task_image_segments_report_the_system_lock_count() {
    let mut runtime = load();
    let module = runtime.win16.as_ref().unwrap().modules.main;
    let code = runtime.cpu.regs.cs;
    let data = runtime.cpu.regs.ss;
    assert_ne!(code, data);

    let idle_code = entry_module(&mut runtime, module, 1, 0);
    assert_eq!(idle_code.block_type, GT_CODE);
    assert_eq!(idle_code.data, 1);
    assert_eq!(idle_code.lock_count, 0);
    assert_eq!(idle_code.page_lock_count, 0);

    let running_code = entry_module(&mut runtime, module, 1, code);
    assert_eq!(running_code.lock_count, 1);
    assert_eq!(running_code.page_lock_count, 0);

    let data_segment = entry_module(&mut runtime, module, 2, code);
    assert_eq!(data_segment.block_type, GT_DGROUP);
    assert_eq!(data_segment.lock_count, 1);
    assert_eq!(data_segment.page_lock_count, 0);

    let data_and_code = entry_module(&mut runtime, module, 2, data);
    assert_eq!(data_and_code.lock_count, 2);

    let selector = runtime.cpu.regs.ss;
    let handle = running_code.block_handle;
    let output = prepare_output(&mut runtime, selector, GlobalEntry16::SIZE as u32);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_global_entry_handle(
            output, handle, code, &mut runtime.memory,
        ).unwrap(),
        1,
    );
    assert_eq!(read_global(&runtime, selector).lock_count, 1);

    let output = prepare_output(&mut runtime, selector, GlobalEntry16::SIZE as u32);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_global_first(
            output, GLOBAL_ALL, code, &mut runtime.memory,
        ).unwrap(),
        1,
    );
    let mut found = None;
    for _ in 0..64 {
        let entry = read_global(&runtime, selector);
        if entry.block_type == GT_CODE && entry.data == 1 {
            found = Some(entry.lock_count);
            break;
        }
        let continued = runtime.win16.as_mut().unwrap().toolhelp_global_next(
            output, GLOBAL_ALL, code, &mut runtime.memory,
        ).unwrap();
        if continued == 0 { break; }
    }
    assert_eq!(found, Some(1));
}

#[test]
fn global_entry_module_uses_the_callers_return_selector() {
    let mut runtime = load();
    let module = runtime.win16.as_ref().unwrap().modules.main;
    let data = runtime.cpu.regs.ss;
    let stack = runtime.cpu.regs.sp();
    let output = prepare_output(&mut runtime, data, GlobalEntry16::SIZE as u32);
    let args = pascal_arguments(&[
        Win16Argument::Dword(output),
        Win16Argument::Word(module),
        Win16Argument::Word(1),
    ]);
    assert_eq!(invoke_toolhelp(&mut runtime, stack, 55, &args), 1);
    assert_eq!(read_global(&runtime, data).lock_count, 1);
    assert_eq!(read_global(&runtime, data).page_lock_count, 0);
}

#[test]
fn stack_trace_next_distinguishes_near_and_far_frames() {
    let mut runtime = load();
    let stack = runtime.cpu.regs.ss;
    let code = runtime.cpu.regs.cs;
    write_words(&mut runtime, stack, 0x40, &[0x0060, 0x0010]);
    write_words(&mut runtime, stack, 0x60, &[0x0000]);
    let output = prepare_output(&mut runtime, stack, StackTraceEntry16::SIZE as u32);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_stack_trace_csip_first(
            output, stack, code, 0, 0x40, &mut runtime.memory,
        ).unwrap(),
        1,
    );
    assert_eq!(state_next(&mut runtime, output), 1);
    let (dw_size, near) = read_stack(&runtime, stack);
    assert_eq!(dw_size, StackTraceEntry16::SIZE as u32);
    assert_eq!(near.flags, FRAME_NEAR);
    assert_eq!(near.code_segment, code);
    assert_eq!(near.instruction_pointer, 0x0010);
    assert_eq!(near.base_pointer, 0x0060);
    let preserved = stack_bytes(&runtime, stack);
    assert_eq!(state_next(&mut runtime, output), 0);
    assert_eq!(stack_bytes(&runtime, stack), preserved);

    write_words(&mut runtime, stack, 0x40, &[0x0061, 0x0020, code]);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_stack_trace_csip_first(
            output, stack, code, 0, 0x40, &mut runtime.memory,
        ).unwrap(),
        1,
    );
    assert_eq!(state_next(&mut runtime, output), 1);
    let (_, far_frame) = read_stack(&runtime, stack);
    assert_eq!(far_frame.flags, FRAME_FAR);
    assert_eq!(far_frame.code_segment, code);
    assert_eq!(far_frame.instruction_pointer, 0x0020);
    assert_eq!(far_frame.base_pointer, 0x0060);
}

#[test]
fn stack_trace_accepts_a_larger_structure_and_rejects_a_short_one() {
    let mut runtime = load();
    let stack = runtime.cpu.regs.ss;
    let code = runtime.cpu.regs.cs;
    let mut buffer = vec![0_u8; StackTraceEntry16::SIZE + 4];
    buffer[..4].copy_from_slice(&((StackTraceEntry16::SIZE as u32) + 4).to_le_bytes());
    buffer[StackTraceEntry16::SIZE..].fill(0xA5);
    write_guest(&mut runtime, stack, OUTPUT_OFFSET, &buffer);
    let output = far_pointer(stack, OUTPUT_OFFSET);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_stack_trace_csip_first(
            output, stack, code, 0, 0, &mut runtime.memory,
        ).unwrap(),
        1,
    );
    let mut written = vec![0_u8; buffer.len()];
    read_guest(&runtime, stack, OUTPUT_OFFSET, &mut written);
    assert_eq!(&written[..4], &((StackTraceEntry16::SIZE as u32) + 4).to_le_bytes());
    assert_eq!(&written[StackTraceEntry16::SIZE..], &[0xA5; 4]);

    let mut short = [0x5A_u8; StackTraceEntry16::SIZE];
    short[..4].copy_from_slice(&8_u32.to_le_bytes());
    write_guest(&mut runtime, stack, OUTPUT_OFFSET, &short);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_stack_trace_csip_first(
            output, stack, code, 0, 0, &mut runtime.memory,
        ).unwrap(),
        0,
    );
    let mut unchanged = [0_u8; StackTraceEntry16::SIZE];
    read_guest(&runtime, stack, OUTPUT_OFFSET, &mut unchanged);
    assert_eq!(unchanged, short);
}

#[test]
fn module_find_handle_resolves_an_instance_and_continues() {
    let mut runtime = load();
    let (module, instance, code) = {
        let state = runtime.win16.as_ref().unwrap();
        (state.modules.main, state.instance_handle, runtime.cpu.regs.cs)
    };
    let data = runtime.cpu.regs.ss;
    let output = prepare_at(&mut runtime, data, 0, ModuleEntry16::SIZE as u32);
    assert_eq!(
        runtime.win16.as_mut().unwrap()
            .toolhelp_module_find_handle(output, instance, &mut runtime.memory).unwrap(),
        1,
    );
    let (_, found) = read_module(&runtime, data, 0);
    assert_eq!(found.module_handle, module);
    assert_ne!(found.next, 0);
    assert_ne!(found.next, module);
    assert_eq!(
        runtime.win16.as_mut().unwrap().toolhelp_module_next(output, &mut runtime.memory).unwrap(),
        1,
    );
    let (_, next) = read_module(&runtime, data, 0);
    assert_eq!(next.module_handle, found.next);

    let output = prepare_at(&mut runtime, data, 0, ModuleEntry16::SIZE as u32);
    assert_eq!(
        runtime.win16.as_mut().unwrap()
            .toolhelp_module_find_handle(output, code, &mut runtime.memory).unwrap(),
        1,
    );
    assert_eq!(read_module(&runtime, data, 0).1.module_handle, module);

    let mut original = [0x3C_u8; ModuleEntry16::SIZE];
    original[..4].copy_from_slice(&(ModuleEntry16::SIZE as u32).to_le_bytes());
    write_guest(&mut runtime, data, 0, &original);
    assert_eq!(
        runtime.win16.as_mut().unwrap()
            .toolhelp_module_find_handle(output, 0xBEEF, &mut runtime.memory).unwrap(),
        0,
    );
    let mut unchanged = [0_u8; ModuleEntry16::SIZE];
    read_guest(&runtime, data, 0, &mut unchanged);
    assert_eq!(unchanged, original);
}

fn write_words(runtime: &mut Runtime, selector: u16, offset: u16, words: &[u16]) {
    let mut bytes = Vec::new();
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    write_guest(runtime, selector, offset, &bytes);
}

fn read_stack(runtime: &Runtime, selector: u16) -> (u32, StackTraceEntry16) {
    let mut bytes = [0_u8; StackTraceEntry16::SIZE];
    read_guest(runtime, selector, OUTPUT_OFFSET, &mut bytes);
    StackTraceEntry16::decode(&bytes)
}

fn stack_bytes(runtime: &Runtime, selector: u16) -> [u8; StackTraceEntry16::SIZE] {
    let mut bytes = [0_u8; StackTraceEntry16::SIZE];
    read_guest(runtime, selector, OUTPUT_OFFSET, &mut bytes);
    bytes
}

fn state_next(runtime: &mut Runtime, output: u32) -> u16 {
    runtime.win16.as_mut().unwrap()
        .toolhelp_stack_trace_next(output, &mut runtime.memory, &mut NoHost)
        .unwrap()
}

fn read_module(runtime: &Runtime, selector: u16, offset: u16) -> (u32, ModuleEntry16) {
    let mut bytes = [0_u8; ModuleEntry16::SIZE];
    read_guest(runtime, selector, offset, &mut bytes);
    ModuleEntry16::decode(&bytes)
}

fn pascal_arguments(arguments: &[Win16Argument]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for argument in arguments.iter().rev() {
        match argument {
            Win16Argument::Word(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            Win16Argument::Dword(value) => bytes.extend_from_slice(&value.to_le_bytes()),
            _ => panic!("unexpected argument"),
        }
    }
    bytes
}

fn invoke_toolhelp(runtime: &mut Runtime, stack_sp: u16, ordinal: u16, args: &[u8]) -> u16 {
    let descriptor = lookup_export(b"TOOLHELP", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    runtime.cpu.regs.set_sp(stack_sp);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let mut bytes = return_ip.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(args);
    let state = runtime.win16.as_mut().unwrap();
    let stack = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp())
        .unwrap();
    state.selectors.write(&mut runtime.memory, stack, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        &mut NoHost,
        0,
    ).unwrap();
    runtime.cpu.regs.ax()
}
