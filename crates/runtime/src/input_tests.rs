use super::{
    INTERRUPT_FLAG, MouseInputBridge, RETURN_OFFSET, RETURN_SEGMENT,
    install_mouse_return_stub,
};
use devices::mouse::{
    EVENT_LEFT_PRESS, EVENT_LEFT_RELEASE, EVENT_MOVEMENT, MouseInput,
};
use guest_core::memory::Memory;
use guest_core::{GuestMemory, MemoryError, Registers, real_address};

#[test]
fn callback_is_a_checked_far_call_and_restores_registers_after_guest_return() {
    let mut bridge = MouseInputBridge::new();
    let mut regs = Registers {
        eax: 0xaaaa_1111,
        ebx: 0xbbbb_2222,
        ecx: 0xcccc_3333,
        edx: 0xdddd_4444,
        esp: 0xeeee_8000,
        esi: 0x1111_5555,
        edi: 0x2222_6666,
        eip: 0x7777_1234,
        eflags: 0x0202,
        cs: 0x2345,
        ds: 0x3456,
        es: 0x4567,
        ss: 0x5000,
        fs: 0x5678,
        gs: 0x6789,
        ..Registers::default()
    };
    let saved = regs.clone();
    bridge.pending_callbacks.push_back(devices::mouse::GuestCallbackRequest {
        entry: devices::mouse::GuestFarPointer { segment: 0x4000, offset: 0x0100 },
        event_mask: EVENT_MOVEMENT,
        buttons: 1,
        x: 20,
        y: 30,
        motion_x: -2,
        motion_y: 3,
    });
    let mut memory = Memory::new().unwrap();
    install_mouse_return_stub(&mut memory).unwrap();

    assert!(bridge.start_callback_if_enabled(&mut regs, &mut memory.bus()).unwrap());
    assert_eq!((regs.cs, regs.eip), (0x4000, 0x0100));
    assert_eq!((regs.ax(), regs.bx(), regs.cx(), regs.dx()), (EVENT_MOVEMENT, 1, 20, 30));
    assert_eq!((regs.si(), regs.di()), ((-2_i16) as u16, 3));
    assert_eq!(regs.sp(), saved.sp().wrapping_sub(4));
    assert_eq!(memory.read_u16(real_address(regs.ss, regs.sp())).unwrap(), RETURN_OFFSET);
    assert_eq!(memory.read_u16(real_address(regs.ss, regs.sp().wrapping_add(2))).unwrap(), RETURN_SEGMENT);

    // Model a guest RETF to the sentinel and an independent guest-memory
    // write. The bridge restores CPU registers only, not guest memory.
    memory.write_u8(real_address(0x2000, 0x0010), 0xa5).unwrap();
    regs.cs = RETURN_SEGMENT;
    regs.set_ip(RETURN_OFFSET);
    regs.set_sp(saved.sp());
    assert!(bridge.restore_returned_callback(&mut regs));
    assert_eq!(regs, saved);
    assert_eq!(memory.read_u8(real_address(0x2000, 0x0010)).unwrap(), 0xa5);
    assert_eq!(bridge.pending_len(), 0);
}

#[test]
fn callback_waits_for_if_and_stack_fault_does_not_commit_registers() {
    let mut bridge = MouseInputBridge::new();
    bridge.pending_callbacks.push_back(devices::mouse::GuestCallbackRequest {
        entry: devices::mouse::GuestFarPointer { segment: 0x4000, offset: 0x0100 },
        ..devices::mouse::GuestCallbackRequest::default()
    });
    let mut regs = Registers { cs: 0x1000, ss: 0x2000, ..Registers::default() };
    let saved = regs.clone();
    let mut memory = Memory::new().unwrap();
    assert!(!bridge.start_callback_if_enabled(&mut regs, &mut memory.bus()).unwrap());
    assert_eq!(regs, saved);
    assert_eq!(bridge.pending_len(), 1);

    regs.eflags |= INTERRUPT_FLAG;
    regs.set_sp(0);
    let before_fault = regs.clone();
    // Stack validation fails before any guest stack byte or register changes.
    let mut faulting = RejectStackWrites;
    assert!(bridge.start_callback_if_enabled(&mut regs, &mut faulting).is_err());
    assert_eq!(regs, before_fault);
    assert_eq!(bridge.pending_len(), 1);
}

#[test]
fn queued_mouse_moves_coalesce_without_dropping_button_transitions() {
    let mut bridge = MouseInputBridge::new();
    let mut devices = devices::BiosDevices::new();
    devices.mouse.set_present(true);
    devices.mouse.install_callback(
        0x4000,
        0x0100,
        EVENT_MOVEMENT | EVENT_LEFT_PRESS | EVENT_LEFT_RELEASE,
    );

    bridge.queue_input(&mut devices, MouseInput { x: 8, y: 8, buttons: 0 }).unwrap();
    bridge.queue_input(&mut devices, MouseInput { x: 16, y: 16, buttons: 0 }).unwrap();
    bridge.queue_input(&mut devices, MouseInput { x: 16, y: 16, buttons: 1 }).unwrap();
    bridge.queue_input(&mut devices, MouseInput { x: 24, y: 24, buttons: 1 }).unwrap();
    bridge.queue_input(&mut devices, MouseInput { x: 24, y: 24, buttons: 0 }).unwrap();
    bridge.queue_input(&mut devices, MouseInput { x: 32, y: 32, buttons: 0 }).unwrap();

    assert_eq!(bridge.pending_len(), 5);
    let movement = bridge.pending_callbacks[0];
    assert_eq!(movement.event_mask, EVENT_MOVEMENT);
    assert_eq!((movement.buttons, movement.x, movement.y), (0, 16, 16));
    assert_eq!((movement.motion_x, movement.motion_y), (16, 16));
    assert_eq!(bridge.pending_callbacks[1].event_mask, EVENT_LEFT_PRESS);
    assert_eq!(bridge.pending_callbacks[2].event_mask, EVENT_MOVEMENT);
    assert_eq!(bridge.pending_callbacks[3].event_mask, EVENT_LEFT_RELEASE);
    assert_eq!(bridge.pending_callbacks[4].event_mask, EVENT_MOVEMENT);
}

struct RejectStackWrites;

impl GuestMemory for RejectStackWrites {
    fn len(&self) -> u32 { 0x10_0000 }
    fn read(&self, _address: guest_core::PhysAddr, _bytes: &mut [u8]) -> Result<(), MemoryError> {
        Ok(())
    }
    fn write(&mut self, _address: guest_core::PhysAddr, _bytes: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::ReadOnly { address: 0x1_fffc, length: 1 })
    }
    fn validate_write(&self, _address: guest_core::PhysAddr, _length: usize) -> Result<(), MemoryError> {
        Err(MemoryError::ReadOnly { address: 0x1_fffc, length: 1 })
    }
}
