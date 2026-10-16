//! Firmware is an exact registered frame owner, never a general ROM alias.

use super::*;
use guest_core::{PhysAddr, memory::ROM_START};
use win16_abi::AccessRights;

fn fixture() -> (crate::Runtime, SelectorRef) {
    let mut runtime = crate::Runtime::load(
        &crate::win16_runtime::test_support::tiny_ne_executable(), &[], br"C:\ROMFRAME.NE",
    ).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let reference = state.selectors.alloc_block(
        PhysAddr(ROM_START), 1, AccessRights::code(), &runtime.memory,
    ).unwrap();
    state.real_mode_vector_aliases.insert((0xf000, 0), reference);
    runtime.cpu.regs.cs = reference.raw().0;
    runtime.cpu.regs.set_ip(0);
    (runtime, reference)
}

fn capture(runtime: &mut crate::Runtime) -> Win16LegacyCpuBindingOwner {
    match runtime.win16.as_mut().unwrap().capture_legacy_cpu_binding_owner(
        &runtime.cpu.regs, &mut runtime.dos, &mut runtime.memory,
    ) {
        Ok(owner) => owner,
        Err(error) => panic!("firmware owner capture failed: {}", error.cause),
    }
}

#[test]
fn firmware_rom_registered_owner_captures_revalidates_and_releases() {
    let (mut runtime, reference) = fixture();
    let mut owner = capture(&mut runtime);
    assert!(owner.owns_selector(reference));
    let state = runtime.win16.as_mut().unwrap();
    let binding = Win16LegacyCpuBinding::new(state, &runtime.memory, &owner);
    let saved = binding.capture(&runtime.cpu.regs).unwrap();
    let transfer = LegacyBindingTransfer {
        current: &saved, target: &saved,
        current_registers: &runtime.cpu.regs, target_registers: &runtime.cpu.regs,
        stack_pointer: LegacyStackPointerTarget::RegisterValue,
    };
    binding.revalidate(&saved, &saved, &transfer).unwrap();
    state.release_legacy_cpu_binding_owner(&mut owner, &mut runtime.dos, &mut runtime.memory).unwrap();
    assert!(!owner.owns_selector(reference));
    assert!(owner.roots.is_empty());
}

#[test]
fn firmware_rom_rejects_generic_retain_mapls_and_unregistered_alias() {
    let (mut runtime, reference) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    let identity = state.selector_backing_lease(reference, &mut runtime.dos, &mut runtime.memory)
        .unwrap().unwrap();
    assert!(matches!(identity, SelectorBackingIdentity::FirmwareRom { primary, size: 1, .. }
        if primary == reference));
    assert!(state.retain_selector_backing(reference, identity, PhysAddr(ROM_START), 1,
        &mut runtime.dos, &mut runtime.memory).unwrap().is_none());
    assert!(state.selector_backing_lease_for_range(PhysAddr(ROM_START), 1,
        &mut runtime.dos, &mut runtime.memory).unwrap().is_none());
    assert_eq!(state.map_ls(ROM_START, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
    let before = state.selectors.reserve_unbacked().unwrap();
    state.selectors.free_selector(before).unwrap();
    let lease_count = state.selector_backing_leases.len();
    assert_eq!(state.alloc_selector(reference.raw().0, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
    assert_eq!(state.alloc_cs_to_ds_alias(reference.raw().0, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
    assert_eq!(state.selector_backing_leases.len(), lease_count);
    let after = state.selectors.reserve_unbacked().unwrap();
    assert_eq!(after.raw(), before.raw(), "failed alias creation leaked a selector");
    state.selectors.free_selector(after).unwrap();
    let unregistered = state.selectors.alloc_block(PhysAddr(ROM_START), 1,
        AccessRights::code(), &runtime.memory).unwrap();
    assert!(state.selector_backing_lease(unregistered, &mut runtime.dos, &mut runtime.memory)
        .unwrap().is_none());
    assert!(state.retain_legacy_cpu_selector_backing(unregistered, identity, PhysAddr(ROM_START), 1,
        &mut runtime.dos, &mut runtime.memory).unwrap().is_none());
}

#[test]
fn firmware_rom_restore_rejects_changed_registration_descriptor_and_generation() {
    // Direct metadata changes model stale internal state. Guest APIs are
    // separately checked below and cannot mutate a live architectural root.
    for change in 0..6 {
        let (mut runtime, reference) = fixture();
        let mut owner = capture(&mut runtime);
        let state = runtime.win16.as_mut().unwrap();
        let proof = Win16LegacyCpuBinding::new(state, &runtime.memory, &owner)
            .capture(&runtime.cpu.regs).unwrap();
        match change {
            0 => { state.real_mode_vector_aliases.clear(); }
            1 => {
                state.real_mode_vector_aliases.clear();
                state.real_mode_vector_aliases.insert((0xf000, 1), reference);
            }
            2 => state.selectors.set_selector_base(reference, PhysAddr(ROM_START + 1), &runtime.memory).unwrap(),
            3 => state.selectors.set_selector_limit(reference, 1, &runtime.memory).unwrap(),
            4 => state.selectors.set_selector_access_rights(reference, 0x00f0, &runtime.memory).unwrap(),
            5 => {
                state.selectors.free_selector(reference).unwrap();
                let replacement = state.selectors.alloc_block(PhysAddr(ROM_START), 1,
                    AccessRights::code(), &runtime.memory).unwrap();
                assert_eq!(replacement.raw(), reference.raw());
                assert_ne!(replacement.generation(), reference.generation());
                state.real_mode_vector_aliases.insert((0xf000, 0), replacement);
            }
            _ => unreachable!(),
        }
        assert!(Win16LegacyCpuBinding::new(state, &runtime.memory, &owner)
            .validate_proof(&proof).is_err(), "change {change} revived the saved ROM root");
        state.release_legacy_cpu_binding_owner(&mut owner, &mut runtime.dos, &mut runtime.memory).unwrap();
    }
}

#[test]
fn firmware_rom_restore_rejects_foreign_memory_and_changed_a20_domain() {
    let (mut runtime, _) = fixture();
    let mut owner = capture(&mut runtime);
    let state = runtime.win16.as_mut().unwrap();
    let proof = Win16LegacyCpuBinding::new(state, &runtime.memory, &owner)
        .capture(&runtime.cpu.regs).unwrap();
    let foreign = Memory::new().unwrap();
    assert!(matches!(Win16LegacyCpuBinding::new(state, &foreign, &owner).validate_proof(&proof),
        Err(Win16LegacyCpuBindingError::MemoryDomainChanged)));
    runtime.memory.set_a20_enabled(false).unwrap();
    assert!(matches!(Win16LegacyCpuBinding::new(state, &runtime.memory, &owner).validate_proof(&proof),
        Err(Win16LegacyCpuBindingError::MemoryDomainChanged)));
    runtime.memory.set_a20_enabled(true).unwrap();
    assert!(matches!(Win16LegacyCpuBinding::new(state, &runtime.memory, &owner).validate_proof(&proof),
        Err(Win16LegacyCpuBindingError::MemoryDomainChanged)));
    state.release_legacy_cpu_binding_owner(&mut owner, &mut runtime.dos, &mut runtime.memory).unwrap();
}

#[test]
fn firmware_rom_live_frame_blocks_selector_mutation_until_release() {
    let (mut runtime, reference) = fixture();
    let state = runtime.win16.as_mut().unwrap();
    // Make the descriptor guest-mutable to ensure the frame guard, rather
    // than absence from the API allocation map, protects this exact root.
    state.api_allocated_selectors.insert(reference.raw().0, reference);
    let frame = state.capture_legacy_cpu_call_frame(&runtime.cpu, &mut runtime.dos, &mut runtime.memory).unwrap();
    assert!(state.legacy_cpu_frame_owns_selector(reference));
    let descriptor = state.selectors.describe(reference).unwrap();
    assert_eq!(state.free_selector(reference.raw().0, &mut runtime.dos, &mut runtime.memory).unwrap(), reference.raw().0);
    assert_eq!(state.set_selector_base(reference.raw().0, ROM_START + 1, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
    assert_eq!(state.set_selector_limit(reference.raw().0, 1, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
    assert_eq!(state.selectors.describe(reference).unwrap(), descriptor);
    assert!(state.release_process_views(&mut runtime.dos, &mut runtime.memory).is_err());
    assert!(state.legacy_cpu_frame_owns_selector(reference));
    assert_eq!(state.selectors.describe(reference).unwrap(), descriptor);
    state.release_legacy_cpu_frame(frame, &mut runtime.dos, &mut runtime.memory).unwrap();
    assert!(!state.legacy_cpu_frame_owns_selector(reference));
    assert_eq!(state.free_selector(reference.raw().0, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
}

#[test]
fn firmware_rom_partial_capture_releases_previously_acquired_root() {
    let (mut runtime, reference) = fixture();
    runtime.cpu.regs.ss = 0;
    let state = runtime.win16.as_mut().unwrap();
    let mut error = match state.capture_legacy_cpu_binding_owner(
        &runtime.cpu.regs, &mut runtime.dos, &mut runtime.memory,
    ) {
        Ok(_) => panic!("invalid stack unexpectedly captured"),
        Err(error) => error,
    };
    assert!(error.owner.owns_selector(reference));
    state.release_legacy_cpu_binding_owner(&mut error.owner, &mut runtime.dos, &mut runtime.memory).unwrap();
    assert!(error.owner.roots.is_empty());
    assert!(state.firmware_rom_identity_is_live(SelectorBackingIdentity::FirmwareRom {
        primary: reference, base: PhysAddr(ROM_START), size: 1,
    }, &runtime.memory));
}

#[test]
fn firmware_rom_capture_requires_exact_registered_descriptor_contract() {
    for change in 0..4 {
        let (mut runtime, reference) = fixture();
        let state = runtime.win16.as_mut().unwrap();
        match change {
            0 => { state.real_mode_vector_aliases.clear(); }
            1 => state.selectors.set_selector_base(reference, PhysAddr(ROM_START + 1), &runtime.memory).unwrap(),
            2 => state.selectors.set_selector_limit(reference, 1, &runtime.memory).unwrap(),
            // Executable but unreadable is not the registered firmware code contract.
            3 => state.selectors.set_selector_access_rights(reference, 0x00f8, &runtime.memory).unwrap(),
            _ => unreachable!(),
        }
        let mut error = match state.capture_legacy_cpu_binding_owner(
            &runtime.cpu.regs, &mut runtime.dos, &mut runtime.memory,
        ) {
            Ok(_) => panic!("changed firmware descriptor {change} acquired a root"),
            Err(error) => error,
        };
        assert!(matches!(error.cause, Win16LegacyCpuBindingError::MissingBacking { segment: 0 }));
        state.release_legacy_cpu_binding_owner(&mut error.owner, &mut runtime.dos, &mut runtime.memory).unwrap();
        assert!(error.owner.roots.is_empty());
    }
}
