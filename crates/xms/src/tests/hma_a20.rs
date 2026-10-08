use super::support::*;
use crate::{A20State, XmsError, XmsService, XMS_VERSION};
use guest_core::{GuestMemory, OwnerId, PhysAddr};

#[test]
fn hma_umb_and_a20_register_errors_are_explicit_and_exact() {
    let (mut service, mut memory) = fixture();
    service.set_hma_minimum_kb(1).unwrap();
    let mut regs = call_registers(0x01);
    regs.set_dx(1023);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x92);
    assert_eq!(service.hma_owner(), None);
    regs.set_ah(0x01);
    regs.set_dx(1024);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    assert_eq!(service.hma_owner(), Some(OwnerId(1)));
    regs.set_ah(0x01);
    regs.set_dx(0xffff);
    service.handle_call(OwnerId(2), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x91);
    regs.set_ah(0x02);
    service.handle_call(OwnerId(2), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x93);
    regs.set_ah(0x02);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    assert_eq!(service.hma_owner(), None);

    regs.set_ah(0x05);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    regs.set_ah(0x04);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x94);
    assert!(service.a20_state().enabled);
    regs.set_ah(0x06);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 1);
    assert_eq!(regs.bl(), 0);
    assert!(!service.a20_state().enabled);
    regs.set_ah(0x06);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x82);
    regs.set_ah(0x07);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0);

    regs.set_ah(0x10);
    regs.set_dx(0xffff);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.dx(), 0xffff);
    assert_eq!(regs.bl(), 0x80);
    regs.set_ah(0x11);
    regs.set_dx(0x1234);
    service.handle_call(OwnerId(1), &mut regs, &mut memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.dx(), 0x1234);
    assert_eq!(regs.bl(), 0x80);
}

#[test]
fn a20_global_and_local_counts_keep_the_desired_line_state() {
    let (mut service, _memory) = fixture();
    assert_eq!(
        service.disable_local_a20(),
        Err(XmsError::A20CounterUnderflow)
    );
    service.enable_local_a20().unwrap();
    assert_eq!(service.set_global_a20(true).unwrap().enabled, true);
    assert_eq!(
        service.set_global_a20(false),
        Err(XmsError::A20StillEnabled)
    );
    assert_eq!(service.a20_state().enabled, true);
    assert_eq!(service.disable_local_a20(), Ok(A20State::default()));
}

#[test]
fn hma_threshold_and_missing_physical_hma_return_specified_errors() {
    let (mut service, mut memory) = fixture();
    let hma_base = PhysAddr(0x0010_0000);
    memory.write(hma_base, &[0x5a, 0xa5]).unwrap();
    service.set_hma_minimum_kb(48).unwrap();
    assert_eq!(service.hma_minimum_kb(), 48);
    assert_eq!(
        service.set_hma_minimum_kb(64),
        Err(XmsError::InvalidConfiguration)
    );
    assert_eq!(
        service.request_hma(OwnerId(1), 48 * 1024 - 1, &memory),
        Err(XmsError::HmaMinimumNotMet)
    );
    assert_eq!(XmsError::HmaMinimumNotMet.error_code(), 0x92);
    assert_eq!(service.request_hma(OwnerId(1), 48 * 1024, &memory), Ok(()));
    assert_eq!(service.hma_owner(), Some(OwnerId(1)));
    let block = service.allocate(OwnerId(1), 1, &mut memory).unwrap();
    let block_base = service.lock(block).unwrap();
    assert_eq!(block_base, PhysAddr(0x0011_0000));
    service.unlock(block).unwrap();
    let mut hma_bytes = [0; 2];
    memory.read(hma_base, &mut hma_bytes).unwrap();
    assert_eq!(hma_bytes, [0x5a, 0xa5]);
    assert_eq!(service.cleanup_owner(OwnerId(1)), 1);
    assert_eq!(service.hma_owner(), None);

    let mut short_memory = TestMemory::with_len(0x0010_0000);
    let mut regs = call_registers(0x00);
    service.handle_call(OwnerId(1), &mut regs, &mut short_memory);
    assert_eq!(regs.ax(), 0x0200);
    assert_eq!(regs.dx(), 0);
    regs.set_ah(0x01);
    regs.set_dx(0xffff);
    service.handle_call(OwnerId(1), &mut regs, &mut short_memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x90);
    regs.set_ah(0x02);
    service.handle_call(OwnerId(1), &mut regs, &mut short_memory);
    assert_eq!(regs.ax(), 0);
    assert_eq!(regs.bl(), 0x90);
}

#[test]
fn version_and_unimplemented_memory_regions_are_reported_honestly() {
    let mut service = XmsService::new();
    assert_eq!(service.version(), XMS_VERSION);
    assert_eq!(XMS_VERSION.highest_function, 0x0f);
    assert!(service.capabilities().hma);
    assert!(!service.capabilities().umb);
    assert_eq!(
        service.request_umb(1),
        Err(XmsError::UnsupportedFunction(0x10))
    );
    assert_eq!(
        service.release_umb(0x1234),
        Err(XmsError::UnsupportedFunction(0x11))
    );
    assert_eq!(service.request_umb(1).unwrap_err().error_code(), 0x80);
    assert_eq!(service.release_umb(0x1234).unwrap_err().error_code(), 0x80);
}
