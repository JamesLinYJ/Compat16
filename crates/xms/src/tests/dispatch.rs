use super::support::*;
use crate::{
    handle_int2f, GuestFarPointer, MoveRequest, PreparedCallMismatch, PreparedXmsCall, XmsService,
};
use guest_core::{GuestHandle, GuestMemory, OwnerId, PhysAddr, Registers};

#[test]
fn int2f_checks_installation_and_returns_the_supplied_guest_entrypoint() {
    let entrypoint = GuestFarPointer {
        segment: 0xf000,
        offset: 0xfe20,
    };
    let mut regs = Registers {
        eax: 0xabcd_4300,
        ebx: 0x1234_5678,
        ecx: 0x2345_6789,
        edx: 0x3456_789a,
        es: 0x4567,
        ..Registers::default()
    };
    assert!(handle_int2f(&mut regs, entrypoint));
    assert_eq!(regs.eax, 0xabcd_4380);
    assert_eq!(regs.ebx, 0x1234_5678);
    assert_eq!(regs.ecx, 0x2345_6789);
    assert_eq!(regs.edx, 0x3456_789a);
    assert_eq!(regs.es, 0x4567);

    regs.eax = 0xface_4310;
    regs.ebx = 0xaaaa_bbbb;
    regs.es = 0xcccc;
    assert!(handle_int2f(&mut regs, entrypoint));
    assert_eq!(regs.eax, 0xface_4310);
    assert_eq!(regs.ebx, 0xaaaa_fe20);
    assert_eq!(regs.es, 0xf000);

    regs.set_ax(0x4301);
    let before_unhandled = regs.clone();
    assert!(!handle_int2f(&mut regs, entrypoint));
    assert_eq!(regs, before_unhandled);
}

#[test]
fn register_function_zero_returns_version_revision_and_physical_hma_presence() {
    let (mut service, mut memory) = fixture();
    let mut regs = Registers {
        eax: 0xcafe_00a5,
        ebx: 0xbabe_4321,
        edx: 0x9876_7654,
        esi: 0x1111_2222,
        ..Registers::default()
    };
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0x0200);
    assert_eq!(regs.bx(), 1);
    assert_eq!(regs.dx(), 1); // Fake memory includes the HMA range.
    assert_eq!(regs.eax >> 16, 0xcafe);
    assert_eq!(regs.ebx >> 16, 0xbabe);
    assert_eq!(regs.edx >> 16, 0x9876);
    assert_eq!(regs.esi, 0x1111_2222);
}

#[test]
fn register_dispatch_uses_exact_xms_words_errors_and_preserves_other_registers() {
    let config = crate::XmsConfig {
        arena_start: PhysAddr(0x0012_3400),
        arena_end: PhysAddr(0x0012_7400),
    };
    let mut service = XmsService::with_config(config).unwrap();
    let mut memory = TestMemory::new();

    // 09h takes DX=KiB and returns AX=1, DX=handle, BL=0.
    let mut regs = Registers {
        eax: 0xdead_0900,
        ebx: 0xabcd_12ef,
        ecx: 0x1234_5678,
        edx: 0x8765_0001,
        esi: 0x1111_2222,
        ..Registers::default()
    };
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.dx(), 1);
    assert_eq!(regs.bl(), 0);
    assert_eq!(regs.ebx >> 16, 0xabcd);
    assert_eq!(regs.ecx, 0x1234_5678);
    assert_eq!(regs.esi, 0x1111_2222);

    // 0Ch returns the complete physical address in DX:BX, not a host ptr.
    regs.set_ah(0x0c);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.dx(), 0x0012);
    assert_eq!(regs.bx(), 0x3400);

    // 0Eh splits lock count and free handle count across BH and BL.
    regs.set_ah(0x0e);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bh(), 1);
    assert_eq!(regs.bl(), 254);
    assert_eq!(regs.dx(), 1);

    // A locked block cannot be resized: AX=0 and BL=ABh.
    regs.set_ah(0x0f);
    regs.set_bx(2);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0xab);
    assert_eq!(service.handle_info(GuestHandle(1)).unwrap().size_kb, 1);

    // 0Dh unlocks; 0Fh takes BX=new size and DX=handle.
    regs.set_ah(0x0d);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    regs.set_ah(0x0f);
    regs.set_bx(2);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    assert_eq!(service.handle_info(GuestHandle(1)).unwrap().size_kb, 2);

    regs.set_ah(0x0a);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    regs.set_ah(0x0a);
    regs.set_dx(1);
    service.handle_call(OwnerId(9), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0xa2);
}

#[test]
fn register_move_uses_ds_si_descriptor_and_function_eight_returns_ax_dx_sizes() {
    let (mut service, mut memory) = fixture();
    let first = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    let middle = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    let _last = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    let source = PhysAddr(0x0002_0010);
    memory.write(source, &[0x11, 0x22, 0x33, 0x44]).unwrap();
    let descriptor = real_address(0x0040, 0x0080);
    let request = MoveRequest {
        length: 4,
        source_handle: 0,
        source_offset: far_pointer(0x2000, 0x0010),
        destination_handle: first.0,
        destination_offset: 0,
    };
    memory.write(descriptor, &request.encode()).unwrap();

    let mut regs = call_registers(0x0b);
    regs.ds = 0x0040;
    regs.set_si(0x0080);
    regs.edi = 0xfeed_cafe;
    service.handle_call(OwnerId(3), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    assert_eq!(regs.edi, 0xfeed_cafe);
    let mut moved = [0; 4];
    memory.read(PhysAddr(0x0011_0000), &mut moved).unwrap();
    assert_eq!(moved, [0x11, 0x22, 0x33, 0x44]);

    service.free(middle).unwrap();
    regs.set_ah(0x08);
    regs.set_ax(0x0800);
    regs.set_bx(0x4567);
    regs.set_dx(0x89ab);
    service.handle_call(OwnerId(3), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.dx(), 2);
    assert_eq!(regs.bl(), 0);

    let last = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    let final_block = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    assert_eq!(service.free_space().total_kb, 0);
    regs.set_ah(0x08);
    service.handle_call(OwnerId(3), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.dx(), 0);
    assert_eq!(regs.bl(), 0xa0);
    service.free(last).unwrap();
    service.free(final_block).unwrap();
}

#[test]
fn prepared_move_uses_typed_bus_descriptor_and_rejects_adapter_mismatches() {
    let (mut service, mut memory) = fixture();
    let handle = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    let source = PhysAddr(0x0002_0010);
    memory.write(source, &[0x71, 0x82, 0x93, 0xa4]).unwrap();
    let request = MoveRequest {
        length: 4,
        source_handle: 0,
        source_offset: far_pointer(0x2000, 0x0010),
        destination_handle: handle.0,
        destination_offset: 0,
    };

    // DS:SI is deliberately unrelated to the supplied request: production
    // code fetched and decoded that descriptor through Memory::bus first.
    let mut regs = call_registers(0x0b);
    regs.ds = 0xffff;
    regs.set_si(0x0010);
    assert_eq!(
        service.handle_prepared_call(
            OwnerId(3),
            &mut regs,
            &mut memory,
            PreparedXmsCall::Move(Ok(request)),
        ),
        Ok(())
    );
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    let mut copied = [0; 4];
    memory.read(PhysAddr(0x0011_0000), &mut copied).unwrap();
    assert_eq!(copied, [0x71, 0x82, 0x93, 0xa4]);

    regs.set_ah(0x0c);
    regs.set_dx(handle.0);
    service
        .handle_prepared_call(
            OwnerId(3),
            &mut regs,
            &mut memory,
            PreparedXmsCall::OtherFunction(0x0c),
        )
        .unwrap();
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.dx(), 0x0011);
    assert_eq!(regs.bx(), 0x0000);
    regs.set_ah(0x0d);
    regs.set_dx(handle.0);
    service
        .handle_prepared_call(
            OwnerId(3),
            &mut regs,
            &mut memory,
            PreparedXmsCall::OtherFunction(0x0d),
        )
        .unwrap();
    assert_eq!(regs.ax(), 1);

    regs.set_ah(0x0b);
    service
        .handle_prepared_call(
            OwnerId(3),
            &mut regs,
            &mut memory,
            PreparedXmsCall::Move(Err(crate::XmsError::Memory(
                guest_core::MemoryError::OutOfBounds {
                    address: 0x0010_0000,
                    length: MoveRequest::BYTE_LEN,
                },
            ))),
        )
        .unwrap();
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0xa7);

    let before_mismatch = regs.clone();
    assert_eq!(
        service.handle_prepared_call(
            OwnerId(3),
            &mut regs,
            &mut memory,
            PreparedXmsCall::OtherFunction(0x0b),
        ),
        Err(PreparedCallMismatch::MoveDescriptorRequired)
    );
    assert_eq!(regs, before_mismatch);
}
