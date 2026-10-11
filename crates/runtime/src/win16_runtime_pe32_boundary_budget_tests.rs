//! Real PE32 call-loop regression: service work has its own boundary charge.

use super::*;
use guest_core::{PhysAddr, Registers, arena::{PhysicalArenaMap, RegionKind}};
use crate::pe32::{Pe32CallCompletion, Pe32CallLeaseState};
use x86_cpu::{CpuError, SegmentAccess, SegmentFaultReason, SegmentResolver};

const IMAGE_BASE: u32 = 0x0040_0000;
const ENTRY_RVA: u32 = 0x1000;
const SERVICE_VALUE: u32 = 0x1234_5678;

fn assert_default_target_validation_preserves_execute_checks() {
    struct ExecuteOnlyResolver(Result<PhysAddr, CpuError>);
    impl SegmentResolver for ExecuteOnlyResolver {
        fn resolve(&self, _: u16, _: u32, _: bool) -> Result<PhysAddr, CpuError> {
            panic!("target validation bypassed execute permissions");
        }
        fn resolve_execute(&self, selector: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
            assert_eq!((selector, offset, address32), (0x18, 0x1234_5678, true));
            self.0.clone()
        }
    }
    for outcome in [
        Ok(PhysAddr(0x1234)),
        Err(CpuError::GeneralProtectionFault { error_code: 0x20, ip: 0x5678 }),
    ] {
        let resolver = ExecuteOnlyResolver(outcome.clone());
        assert_eq!(resolver.validate_near_code_target(0x18, 0x1234_5678), outcome.map(|_| ()));
    }
}

fn assert_gate_preserves_segment_checks() {
    use crate::pe32_call::{Pe32GuestExecutionEnvironment, Pe32GuestStackRange, Pe32SegmentAccess, Pe32SegmentMapping};
    for (execute, limit, reason) in [
        (false, 0xffff, Some(SegmentFaultReason::AccessDenied)),
        (true, 0x1fff, Some(SegmentFaultReason::Limit)),
        (true, 0xffff, None),
    ] {
        let environment = Pe32GuestExecutionEnvironment::new(
            vec![
                Pe32SegmentMapping::new(8, 0, limit, Pe32SegmentAccess::new(true, false, execute)),
                Pe32SegmentMapping::new(16, 0, 0xffff, Pe32SegmentAccess::new(true, true, false)),
                Pe32SegmentMapping::new(24, 0, 0xffff, Pe32SegmentAccess::new(true, false, true)),
            ],
            vec![Pe32GuestCodeRange::from_linear_range(0x1000..0x1100)],
            8, 16, 16, None, None, None,
            Pe32GuestStackRange::new(0x3000, 0x4000, 0x4000), 0x2000,
        );
        if let Some(reason) = reason {
            // Invalid environments cannot enter a frame; the narrow resolver
            // hook also rejects their exact gate when asked directly.
            assert!(environment.validate().is_err());
            assert_eq!(environment.resolver().validate_near_code_target(8, 0x2000), Err(CpuError::SegmentFault {
                selector: 8, offset: 0x2000, access: SegmentAccess::Execute, reason,
            }));
        } else {
            environment.validate().unwrap();
            assert!(environment.resolver().validate_near_code_target(8, 0x2000).is_ok());
            // Even an executable alias of the same linear address cannot
            // acquire another selector's continuation identity.
            assert_eq!(environment.resolver().validate_near_code_target(24, 0x2000), Err(CpuError::SegmentFault {
                selector: 24, offset: 0x2000, access: SegmentAccess::Execute, reason: SegmentFaultReason::AccessDenied,
            }));
        }
    }
}

// One bounded, parser-validated I386 DLL with a single executable section.
// Its entrypoint is PUSH value; CALL SetLastError; MOV EAX,1; RET 12.
fn boundary_dll(service_gate: u32) -> Vec<u8> {
    fn word(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn dword(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut bytes = vec![0; 0x400];
    bytes[..2].copy_from_slice(b"MZ");
    dword(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    word(&mut bytes, 0x84, 0x014c);
    word(&mut bytes, 0x86, 1);
    word(&mut bytes, 0x94, 0xe0);
    word(&mut bytes, 0x96, 0x2102); // executable, 32-bit, DLL
    let optional = 0x98;
    word(&mut bytes, optional, 0x010b);
    dword(&mut bytes, optional + 4, 0x200);
    dword(&mut bytes, optional + 16, ENTRY_RVA);
    dword(&mut bytes, optional + 20, ENTRY_RVA);
    dword(&mut bytes, optional + 28, IMAGE_BASE);
    dword(&mut bytes, optional + 32, 0x1000);
    dword(&mut bytes, optional + 36, 0x200);
    dword(&mut bytes, optional + 56, 0x2000);
    dword(&mut bytes, optional + 60, 0x200);
    word(&mut bytes, optional + 68, 3);
    dword(&mut bytes, optional + 92, 16);
    let section = optional + 0xe0;
    bytes[section..section + 5].copy_from_slice(b".text");
    dword(&mut bytes, section + 8, 0x200);
    dword(&mut bytes, section + 12, ENTRY_RVA);
    dword(&mut bytes, section + 16, 0x200);
    dword(&mut bytes, section + 20, 0x200);
    dword(&mut bytes, section + 36, 0x6000_0020);
    bytes[0x200] = 0x68; // PUSH imm32
    dword(&mut bytes, 0x201, SERVICE_VALUE);
    bytes[0x205] = 0xe8; // CALL rel32
    dword(&mut bytes, 0x206, service_gate.wrapping_sub(IMAGE_BASE + ENTRY_RVA + 10));
    bytes[0x20a] = 0xb8; // MOV EAX,1
    dword(&mut bytes, 0x20b, 1);
    bytes[0x20f..0x212].copy_from_slice(&[0xc2, 12, 0]); // stdcall DllMain
    bytes
}

#[test]
fn pe32_return_and_service_gates_preserve_boundary_budget() {
    assert_default_target_validation_preserves_execute_checks();
    assert_gate_preserves_segment_checks();
    // Two CPU boundaries reach the service gate. Its separate third charge
    // permits the LastError mutation, but no following instruction. At five,
    // MOV and RET have used the remaining budget; recognizing the checked
    // return must neither fetch its UD2 marker nor demand a sixth boundary.
    for limit in [2, 3, 5] {
        let mut memory = Memory::with_size(0x0080_0000).unwrap();
        memory.set_a20_enabled(true).unwrap();
        let mut map = PhysicalArenaMap::new(0x0080_0000).unwrap();
        let region = map.reserve(RegionKind::Pe32, PhysAddr(0x0020_0000), 0x0060_0000, 0x1000).unwrap();
        let (mut dispatcher, mut imports) = Pe32ThunkDispatcher::new(
            map.get(region).unwrap(), &mut memory, b"C:\\BOUNDARY.EXE",
        ).unwrap();
        let provider = imports.reserve_system_module(
            &crate::Win32ImportString::Ansi(b"KERNEL32.DLL".to_vec()),
        ).unwrap();
        let provider = imports.register_system_module(
            provider, crate::Win32HostModule::from_host_id(1),
            "C:\\Windows\\System32\\kernel32.dll".encode_utf16().collect(), 1, false,
        ).unwrap();
        let (resolved, _) = crate::win32_import_bridge::resolve_service_gate(
            &mut imports, provider, crate::Win32ImportSymbol::Name(b"SetLastError".to_vec()),
            &mut memory, |_| Ok(crate::Win32HostImportResult {
                value: crate::Win32HostImportValue::ResolvedExport(Some(
                    crate::Win32HostResolvedExport::from_host_id(1),
                )),
                last_error: None,
            }),
        ).unwrap();
        let (_, gate) = resolved.unwrap();
        assert_eq!(memory.map_physical(PhysAddr(gate.address), 2).unwrap(), &[0x0f, 0x0b]);
        let image = formats::parse_pe32(&boundary_dll(gate.address)).unwrap();
        let group = dispatcher.registry.begin_load_group().unwrap();
        let transaction = crate::pe32::prepare_unlinked_group_module(
            &mut dispatcher.registry, &mut dispatcher.arena, &mut memory,
            b"BOUNDARY.DLL", image, group,
        ).unwrap();
        assert_eq!(transaction.image_lease().base(), IMAGE_BASE);
        let module = transaction.module();
        let link = dispatcher.registry.prepare_group_link(group, module, &[]).unwrap();
        dispatcher.registry.commit_group_links(group, vec![link]).unwrap();
        dispatcher.modules.push(LoadedModule {
            transaction, handle: None, basename: b"BOUNDARY.DLL".to_vec(),
            path: b"C:\\BOUNDARY.DLL".to_vec(),
            executable_ranges: vec![Pe32GuestCodeRange::from_linear_range(
                u64::from(IMAGE_BASE + ENTRY_RVA)..u64::from(IMAGE_BASE + ENTRY_RVA + 0x200),
            )],
            pending_retirement: None, quarantined: false, image_released: false,
            system_dependencies: Vec::new(), group_member: None,
        });
        dispatcher.active_load_group = Some(ActiveLoadGroup {
            id: group, root: Some(module), members: vec![module], attach_order: Vec::new(),
            temporary_providers: Vec::new(), next_attach_sequence: 0, phase: LoadGroupPhase::Attaching,
        });
        let mut environment = environment::for_call(
            &dispatcher, &imports, &memory, dispatcher.default_stack_top().unwrap(), Some(module),
        ).unwrap();
        environment.validate().unwrap();
        let return_gate = environment.return_gate_offset;
        let resolver = environment.resolver();
        assert!(resolver.validate_near_code_target(8, return_gate).is_ok());
        assert!(resolver.validate_near_code_target(8, IMAGE_BASE + ENTRY_RVA).is_ok());
        assert!(resolver.validate_near_code_target(8, gate.address).is_ok());
        for (selector, offset) in [
            (8, return_gate - 1), (8, return_gate + 1), (16, return_gate),
            (0x20, return_gate), (8, IMAGE_BASE + 0x3000),
        ] {
            assert!(resolver.validate_near_code_target(selector, offset).is_err());
        }
        for offset in [return_gate, return_gate + 1] {
            assert_eq!(resolver.resolve_execute(8, offset, true), Err(CpuError::SegmentFault {
                selector: 8, offset, access: SegmentAccess::Execute, reason: SegmentFaultReason::AccessDenied,
            }));
        }
        // A service refresh changes executable modules, never gate identity or
        // fetch permissions. The real call below builds its own environment.
        environment.replace_executable_ranges(vec![Pe32GuestCodeRange::from_linear_range(
            u64::from(IMAGE_BASE + ENTRY_RVA)..u64::from(IMAGE_BASE + ENTRY_RVA + 0x200),
        )]).unwrap();
        assert!(environment.resolver().validate_near_code_target(8, return_gate).is_ok());
        assert!(environment.resolver().resolve_execute(8, return_gate, true).is_err());
        assert!(environment.resolver().validate_near_code_target(8, gate.address).is_err());
        let lease = dispatcher.registry.prepare_process_attach(module).unwrap().unwrap();
        let lease_id = lease.id();
        let mut cpu = Cpu::new(Registers::default());
        // CPU construction canonicalizes reserved EFLAGS bit 1. Compare the
        // restored state with the actual pre-call CPU, not its raw input DTO.
        let initial = cpu.regs.clone();
        let mut host = super::super::test_support::NoHost;
        imports.set_last_error(7);

        // Keep the outer shared budget alive to inspect actual dispatcher usage.
        let budget_owner = dispatcher.begin_budget(limit).unwrap();
        let result = dispatcher.execute_lease(
            &mut cpu, &mut memory, &mut imports, &mut host, lease, limit,
        );
        if limit == 5 {
            assert_eq!(result.unwrap(), Pe32CallCompletion::AttachAccepted);
        } else {
            assert_eq!(result.unwrap_err().kind(), Kind::ExecutionLimit);
        }
        assert_eq!(imports.last_error(), if limit == 2 { 7 } else { SERVICE_VALUE });
        assert_eq!(dispatcher.active_budget.unwrap().used, limit);
        assert_eq!(dispatcher.take_charged_boundaries(), limit);
        assert_eq!(dispatcher.registry.lease_state(lease_id), Some(Pe32CallLeaseState::Retired));
        assert!(dispatcher.active.is_empty());
        assert!(dispatcher.retained_frames.is_empty());
        assert_eq!(cpu.regs, initial);
        dispatcher.finish_budget(budget_owner);
        assert!(dispatcher.active_budget.is_none());
    }
}
