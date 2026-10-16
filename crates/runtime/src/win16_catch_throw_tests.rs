use super::super::{CallbackKind, code_lifetime::FarCallResume};
use super::*;
use crate::Runtime;
use guest_core::PhysAddr;

fn fixture() -> Runtime {
    Runtime::load(
        &super::super::test_support::tiny_ne_executable(),
        &[],
        br"C:\CHECKPOINT.NE",
    )
    .unwrap()
}
fn buffer(runtime: &Runtime, offset: u16) -> u32 {
    u32::from(runtime.cpu.regs.ds) << 16 | u32::from(offset)
}
fn read_buffer(runtime: &Runtime, raw: u32) -> [u8; BUFFER_BYTES] {
    let state = runtime.win16.as_ref().unwrap();
    let mut bytes = [0; BUFFER_BYTES];
    state
        .selectors
        .read(
            &runtime.memory,
            state.checkpoint_buffer(raw).unwrap(),
            &mut bytes,
        )
        .unwrap();
    bytes
}
fn write_buffer(runtime: &mut Runtime, raw: u32, bytes: &[u8]) {
    let state = runtime.win16.as_ref().unwrap();
    state
        .selectors
        .write(
            &mut runtime.memory,
            state.checkpoint_buffer(raw).unwrap(),
            bytes,
        )
        .unwrap();
}
fn prepare(runtime: &mut Runtime, raw: u32) {
    let cs = runtime.cpu.regs.cs;
    runtime.cpu.regs.set_sp(0x80);
    let mut bytes = [0; 8];
    bytes[0..2].copy_from_slice(&0x10u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&cs.to_le_bytes());
    bytes[4..8].copy_from_slice(&raw.to_le_bytes());
    let stack = u32::from(runtime.cpu.regs.ss) << 16 | 0x80;
    write_buffer(runtime, stack, &bytes);
}
fn catch(runtime: &mut Runtime, raw: u32) -> Result<(), RuntimeError> {
    runtime.win16.as_mut().unwrap().catch_guest(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        raw,
    )
}
fn throw(runtime: &mut Runtime, raw: u32, value: u16) -> Result<(), RuntimeError> {
    runtime.win16.as_mut().unwrap().throw_guest(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        raw,
        value,
    )
}

#[test]
fn initial_catch_and_copied_reusable_throw_restore_only_saved_words() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    let copy = buffer(&runtime, 0x40);
    prepare(&mut runtime, raw);
    runtime.cpu.regs.set_bp(0x1111);
    runtime.cpu.regs.set_si(0x2222);
    runtime.cpu.regs.set_di(0x3333);
    catch(&mut runtime, raw).unwrap();
    assert_eq!(
        (
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp(),
            runtime.cpu.regs.ax()
        ),
        (0x10, 0x88, 0)
    );
    let saved = read_buffer(&runtime, raw);
    write_buffer(&mut runtime, copy, &saved);
    write_buffer(&mut runtime, raw, &[0; BUFFER_BYTES]);
    for value in [0, 1, 0x8000, 0xffff] {
        runtime.cpu.regs.eax = 0xabcd_9876;
        runtime.cpu.regs.ebp = 0x5678_ffff;
        runtime.cpu.regs.esi = 0x6789_ffff;
        runtime.cpu.regs.edi = 0x789a_ffff;
        runtime.cpu.regs.ebx = 0x1234_5678;
        runtime.cpu.regs.set_sp(0xa0);
        throw(&mut runtime, copy, value).unwrap();
        assert_eq!(runtime.cpu.regs.eax, 0xabcd_0000 | u32::from(value));
        assert_eq!(runtime.cpu.regs.ebp, 0x5678_1111);
        assert_eq!(runtime.cpu.regs.esi, 0x6789_2222);
        assert_eq!(runtime.cpu.regs.edi, 0x789a_3333);
        assert_eq!(runtime.cpu.regs.ebx, 0x1234_5678);
        assert_eq!((runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), (0x10, 0x88));
        assert_eq!(
            runtime.win16.as_ref().unwrap().catch_records.records.len(),
            1
        );
    }
}

#[test]
fn repeated_catch_interns_roots_despite_changing_saved_registers_and_buffer() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    let second = buffer(&runtime, 0x40);
    for index in 0..100u16 {
        let destination = if index & 1 == 0 { raw } else { second };
        prepare(&mut runtime, destination);
        runtime.cpu.regs.set_bp(index);
        catch(&mut runtime, destination).unwrap();
    }
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.catch_records.records.len(), 1);
    assert_eq!(state.catch_records.next_token, 2);
    throw(&mut runtime, raw, 3).unwrap();
    assert_eq!(runtime.cpu.regs.bp(), 98);
    throw(&mut runtime, second, 4).unwrap();
    assert_eq!(runtime.cpu.regs.bp(), 99);
}

#[test]
fn ordinary_owned_context_restore_keeps_checkpoint_but_wrong_cpu_rejects() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    catch(&mut runtime, raw).unwrap();
    let context = runtime.cpu.capture_context();
    runtime.cpu.restore_context(&context).unwrap();
    throw(&mut runtime, raw, 7).unwrap();
    runtime.cpu = Cpu::new(runtime.cpu.regs.clone());
    let before = runtime.cpu.capture_context();
    assert!(throw(&mut runtime, raw, 8).is_err());
    assert!(runtime.cpu.capture_context() == before);
}

#[test]
fn equal_depth_different_callback_identity_rejects_without_unwinding_owners() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    let state = runtime.win16.as_mut().unwrap();
    state.callback_kinds.push(CallbackKind::Font);
    state.callback_frame_ids.push(CallbackFrameId(50));
    catch(&mut runtime, raw).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.callback_frame_ids[0] = CallbackFrameId(51);
    let before = runtime.cpu.capture_context();
    assert!(throw(&mut runtime, raw, 5).is_err());
    assert!(runtime.cpu.capture_context() == before);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.callback_frame_ids, [CallbackFrameId(51)]);
    assert_eq!(state.callback_kinds, [CallbackKind::Font]);
    assert!(state.catch_records.records.is_empty());
    prepare(&mut runtime, raw);
    catch(&mut runtime, raw).unwrap();
    let token = u32::from_le_bytes(read_buffer(&runtime, raw)[14..18].try_into().unwrap());
    assert_eq!(token, 2); // Retired identities never become valid again.
}

#[test]
fn nested_callback_cannot_throw_across_message_but_outer_record_survives() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    catch(&mut runtime, raw).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.callback_kinds.push(CallbackKind::Window);
    state.callback_frame_ids.push(CallbackFrameId(60));
    let before = runtime.cpu.capture_context();
    assert!(throw(&mut runtime, raw, 3).is_err());
    assert!(runtime.cpu.capture_context() == before);
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.catch_records.records.len(), 1);
    assert_eq!(state.callback_frame_ids.len(), 1);
    state.callback_frame_ids.pop();
    state.callback_kinds.pop();
    throw(&mut runtime, raw, 4).unwrap();
}

#[test]
fn guest_far_activations_retire_after_throw_without_reusing_anchor_identity() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    let state = runtime.win16.as_mut().unwrap();
    let cs = runtime.cpu.regs.cs;
    let ss = runtime.cpu.regs.ss;
    state.far_returns.push(FarCallResume {
        id: 1,
        selector: cs,
        offset: 0x30,
        stack: ss,
        frame_sp: 0xa0,
    });
    state.far_returns.push(FarCallResume {
        id: 2,
        selector: cs,
        offset: 0x10,
        stack: ss,
        frame_sp: 0x80,
    });
    catch(&mut runtime, raw).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.far_returns.len(), 1);
    state.far_returns.push(FarCallResume {
        id: 3,
        selector: cs,
        offset: 0x40,
        stack: ss,
        frame_sp: 0x70,
    });
    throw(&mut runtime, raw, 9).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.far_returns.len(), 1);
    assert_eq!(state.far_returns[0].id, 1);
    state.far_returns[0].id = 4;
    let before = runtime.cpu.capture_context();
    assert!(throw(&mut runtime, raw, 10).is_err());
    assert!(runtime.cpu.capture_context() == before);
}

#[test]
fn invalid_saved_selector_and_code_offset_are_atomic_failures() {
    for (word, value) in [(1usize, 0xffffu16), (0, 0xffff), (6, 0xffff)] {
        let mut runtime = fixture();
        let raw = buffer(&runtime, 0x20);
        prepare(&mut runtime, raw);
        catch(&mut runtime, raw).unwrap();
        let mut bytes = read_buffer(&runtime, raw);
        bytes[word * 2..word * 2 + 2].copy_from_slice(&value.to_le_bytes());
        write_buffer(&mut runtime, raw, &bytes);
        let before = runtime.cpu.capture_context();
        assert!(throw(&mut runtime, raw, 9).is_err());
        assert!(runtime.cpu.capture_context() == before);
        assert_eq!(read_buffer(&runtime, raw), bytes);
    }
}

#[test]
fn different_task_and_changed_backing_proof_reject_throw() {
    for change_task in [true, false] {
        let mut runtime = fixture();
        let raw = buffer(&runtime, 0x20);
        prepare(&mut runtime, raw);
        catch(&mut runtime, raw).unwrap();
        let state = runtime.win16.as_mut().unwrap();
        if change_task {
            state.tasks.create(OwnerId(500), None).unwrap();
            state.tasks.dispatch(OwnerId(500)).unwrap();
        } else {
            // A mismatched canonical allocation identity is never accepted even
            // when visible selector words and descriptors still match.
            state.catch_records.records[0].roots[0].backing =
                state.catch_records.records[0].roots[1].backing;
        }
        let before = runtime.cpu.capture_context();
        assert!(throw(&mut runtime, raw, 5).is_err());
        assert!(runtime.cpu.capture_context() == before);
    }
}

#[test]
fn catch_invalid_output_and_exhausted_tokens_never_publish_or_return() {
    for exhausted in [false, true] {
        let mut runtime = fixture();
        let raw = buffer(&runtime, if exhausted { 0x20 } else { 0xfff8 });
        prepare(&mut runtime, raw);
        if exhausted {
            runtime.win16.as_mut().unwrap().catch_records.next_token = u32::MAX;
        }
        let before = runtime.cpu.capture_context();
        assert!(catch(&mut runtime, raw).is_err());
        assert!(runtime.cpu.capture_context() == before);
        assert!(
            runtime
                .win16
                .as_ref()
                .unwrap()
                .catch_records
                .records
                .is_empty()
        );
    }
}

#[test]
fn catch_overlapping_return_frame_uses_prevalidated_original_destination() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x80);
    prepare(&mut runtime, raw);
    catch(&mut runtime, raw).unwrap();
    assert_eq!((runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), (0x10, 0x88));
    throw(&mut runtime, raw, 1).unwrap();
    assert_eq!((runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), (0x10, 0x88));
}

#[test]
fn far_identity_exhaustion_does_not_publish_observations() {
    let mut runtime = fixture();
    let registers = runtime.cpu.regs.clone();
    let state = runtime.win16.as_mut().unwrap();
    state.next_far_call_id = u64::MAX;
    assert!(
        state
            .observe_control_transfer(
                Some(x86_cpu::ControlTransfer::FarCall {
                    return_selector: registers.cs,
                    return_offset: 0x10,
                    stack_selector: registers.ss,
                }),
                (registers.ss, registers.sp()),
                &registers
            )
            .is_err()
    );
    assert!(state.far_returns.is_empty());
    assert_eq!(state.next_far_call_id, u64::MAX);
}

#[test]
fn freed_and_reused_selector_incarnation_does_not_revive_checkpoint() {
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    catch(&mut runtime, raw).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let reference = state
        .selectors
        .reference(Selector(runtime.cpu.regs.cs))
        .unwrap();
    let descriptor = state.selectors.describe(reference).unwrap();
    state.selectors.free_selector(reference).unwrap();
    let replacement = state
        .selectors
        .alloc_block(
            descriptor.base,
            descriptor.limit + 1,
            descriptor.rights,
            &runtime.memory,
        )
        .unwrap();
    assert_eq!(replacement.raw(), reference.raw());
    assert_ne!(replacement.generation(), reference.generation());
    let before = runtime.cpu.capture_context();
    assert!(throw(&mut runtime, raw, 2).is_err());
    assert!(runtime.cpu.capture_context() == before);
}

#[test]
fn saved_ds_low_bits_are_preserved_without_becoming_another_selector_identity() {
    let mut runtime = fixture();
    runtime.cpu.regs.ds |= 3;
    let ds = runtime.cpu.regs.ds;
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    catch(&mut runtime, raw).unwrap();
    runtime.cpu.regs.ds &= !7;
    throw(&mut runtime, raw, 2).unwrap();
    assert_eq!(runtime.cpu.regs.ds, ds);
}

#[test]
fn partial_atomic_provider_failure_preserves_cpu_and_leaves_no_published_token() {
    use guest_core::MemoryError;
    use guest_core::memory::MemoryStorage;
    use std::{cell::RefCell, rc::Rc};
    struct PartialStorage(Rc<RefCell<Vec<u8>>>);
    impl MemoryStorage for PartialStorage {
        fn len(&self) -> u32 {
            self.0.borrow().len() as u32
        }
        fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
            output
                .copy_from_slice(&self.0.borrow()[offset as usize..offset as usize + output.len()]);
            Ok(())
        }
        fn write(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
            self.0.borrow_mut()[offset as usize..offset as usize + input.len()]
                .copy_from_slice(input);
            Ok(())
        }
        fn atomic_update(
            &mut self,
            ranges: &[AtomicMemoryRange],
            value: &mut [u8],
            update: &mut dyn FnMut(&mut [u8]),
        ) -> Result<(), MemoryError> {
            assert_eq!(ranges.len(), 1);
            let offset = ranges[0].offset;
            self.read(offset, value)?;
            update(value);
            self.write(offset, &value[..4])?;
            Err(MemoryError::StorageAccess {
                address: offset,
                length: value.len(),
                transferred: 4,
                write: true,
                os_error: None,
            })
        }
    }
    let mut runtime = fixture();
    let raw = buffer(&runtime, 0x20);
    prepare(&mut runtime, raw);
    let mut bytes = vec![0; runtime.memory.len() as usize];
    runtime.memory.read(PhysAddr(0), &mut bytes).unwrap();
    runtime.memory =
        Memory::with_storage(Box::new(PartialStorage(Rc::new(RefCell::new(bytes))))).unwrap();
    let before = runtime.cpu.capture_context();
    assert!(catch(&mut runtime, raw).is_err());
    assert!(runtime.cpu.capture_context() == before);
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.catch_records.records.is_empty());
    assert_eq!(state.catch_records.next_token, 1);
    assert!(matches!(
        runtime.memory.storage_failure(),
        Some(MemoryError::StorageAccess {
            transferred: 4,
            write: true,
            ..
        })
    ));
}

#[test]
fn actual_far_calls_dispatch_catch_and_throw_then_execute_resumed_branch() {
    use super::super::{ImportBinding, test_support::NoHost};
    use win16_abi::{ExportLookupTarget, lookup_export};
    let mut runtime = fixture();
    let code = runtime.cpu.regs.cs;
    let state = runtime.win16.as_mut().unwrap();
    let gate = state.gate_selector.0;
    let catch_offset = (state.bindings.len() * 2) as u16;
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(55)).unwrap(),
    ));
    let throw_offset = (state.bindings.len() * 2) as u16;
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(56)).unwrap(),
    ));
    let mut instructions = vec![0x1e, 0x68, 0x20, 0x00, 0x9a]; // PUSH DS; PUSH 20h; CALL FAR Catch
    instructions.extend_from_slice(&catch_offset.to_le_bytes());
    instructions.extend_from_slice(&gate.to_le_bytes());
    instructions.extend_from_slice(&[0x83, 0xf8, 0, 0x75, 5, 0x9a]); // CMP AX,0; JNE done; CALL nested
    instructions.extend_from_slice(&0x30u16.to_le_bytes());
    instructions.extend_from_slice(&code.to_le_bytes());
    instructions.push(0x90); // done: NOP
    assert_eq!(instructions.len(), 20);
    instructions.resize(0x30, 0x90);
    instructions.extend_from_slice(&[0x1e, 0x68, 0x20, 0x00, 0x68, 0xff, 0xff, 0x9a]);
    instructions.extend_from_slice(&throw_offset.to_le_bytes());
    instructions.extend_from_slice(&gate.to_le_bytes());
    instructions.push(0xf4); // Throw must never fall through to HLT.
    let reference = state.selectors.reference(Selector(code)).unwrap();
    let base = state.selectors.describe(reference).unwrap().base;
    runtime.memory.write(base, &instructions).unwrap();
    let mut dispatches = 0;
    for _ in 0..30 {
        if runtime.cpu.regs.cs == code && runtime.cpu.regs.ip() == 20 {
            break;
        }
        let state = runtime.win16.as_mut().unwrap();
        if runtime.cpu.regs.cs == gate {
            state
                .dispatch(
                    &mut runtime.cpu,
                    &mut runtime.memory,
                    &mut runtime.dos,
                    &mut NoHost,
                    0,
                )
                .unwrap();
            dispatches += 1;
        } else {
            let before_stack = (runtime.cpu.regs.ss, runtime.cpu.regs.sp());
            let segments = crate::win16_loader::Win16Segments {
                selectors: &state.selectors,
                memory_len: runtime.memory.len(),
            };
            runtime
                .cpu
                .step_with_context(&mut runtime.memory, &mut guest_core::io::NoPorts, &segments)
                .unwrap();
            state
                .observe_control_transfer(
                    runtime.cpu.control_transfer(),
                    before_stack,
                    &runtime.cpu.regs,
                )
                .unwrap();
        }
    }
    assert_eq!(dispatches, 2);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp(),
            runtime.cpu.regs.ax()
        ),
        (code, 20, 0x80, 0xffff)
    );
    let state = runtime.win16.as_ref().unwrap();
    assert!(state.far_returns.is_empty());
    assert!(state.callback_frame_ids.is_empty());
    assert!(state.legacy_cpu_frames.is_empty());
    assert_eq!(state.catch_records.records.len(), 1);
}
