use crate::keyboard::KeyStroke;
use crate::keyboard::BiosKeyboard;
use crate::mouse::{GuestFarPointer, MouseDevice, MouseInput, MouseState};
use crate::rtc::{unix_seconds_to_datetime, RtcState, BIOS_TICKS_PER_DAY};
use crate::video;
use crate::video::{TextCell, VideoDevice, TEXT_COLS};
use crate::{BiosDevices, DeviceAction, DeviceError, VGA_TEXT_MEMORY};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Memory(Vec<u8>);
impl GuestMemory for Memory {
    fn len(&self) -> u32 { self.0.len() as u32 }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = address.0 as usize;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let src = self.0.get(start..end).ok_or(MemoryError::OutOfBounds { address: address.0, length: bytes.len() })?;
        bytes.copy_from_slice(src);
        Ok(())
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = address.0 as usize;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let dst = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds { address: address.0, length: bytes.len() })?;
        dst.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn initialization_populates_bda_and_color_text_memory() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    assert_eq!(u16::from_le_bytes([memory.0[0x410], memory.0[0x411]]), 0x0020);
    assert_eq!(u16::from_le_bytes([memory.0[0x413], memory.0[0x414]]), 640);
    assert_eq!(memory.0[0x449], 3);
    assert_eq!(u16::from_le_bytes([memory.0[0x463], memory.0[0x464]]), 0x03d4);
    assert_eq!(u16::from_le_bytes([memory.0[0x44c], memory.0[0x44d]]), 0x1000);
    assert_eq!(&memory.0[0xb8000..0xb8002], b" \x07");
}

#[test]
fn int11_reports_color_80_column_equipment_word() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    let mut regs = Registers::default();
    devices.dispatch_interrupt(0x11, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 0x0020);
}

#[test]
fn int10_updates_guest_memory_and_requests_render() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    let mut regs = Registers::default();
    regs.set_ah(0x0e);
    regs.set_al(b'X');
    let outcome = devices.dispatch_interrupt(0x10, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(&memory.0[0xb8000..0xb8002], b"X\x07");
    assert!(matches!(outcome.actions.as_slice(), [DeviceAction::RenderText(_)]));
}

#[test]
fn direct_text_aperture_writes_can_become_render_actions() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    memory.write(PhysAddr(VGA_TEXT_MEMORY), b"Z\x1f").unwrap();
    let action = devices.refresh_video_action(&memory).unwrap().unwrap();
    let DeviceAction::RenderText(snapshot) = action else { panic!("expected text render action"); };
    assert_eq!(snapshot.cells[0], video::TextCell { character: b'Z', attribute: 0x1f });
    assert!(devices.refresh_video_action(&memory).unwrap().is_none());
}

#[test]
fn empty_blocking_keyboard_read_requests_input_without_faking_a_key() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    let mut regs = Registers::default();
    regs.set_ah(0);
    regs.set_al(0x55);
    let outcome = devices.dispatch_interrupt(0x16, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.al(), 0x55);
    assert_eq!(outcome.actions, vec![DeviceAction::AwaitKeyboard]);
}

#[test]
fn unsupported_int15_service_returns_guest_failure_without_stopping_dispatch() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    let mut regs = Registers::default();
    regs.set_ah(0x87);
    devices.dispatch_interrupt(0x15, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ah(), 0x86);
    assert!(regs.carry());
}

#[test]
fn device_errors_display_interrupt_function_detail_and_nested_memory_cause() {
    assert_eq!(
        DeviceError::UnsupportedInterrupt { interrupt: 0x15, function: 0x0087 }.to_string(),
        "unsupported BIOS interrupt INT 15h function 0087h"
    );
    assert_eq!(
        DeviceError::InvalidRequest {
            interrupt: 0x10,
            function: 0x0000,
            detail: "unsupported video mode",
        }
        .to_string(),
        "invalid BIOS request for INT 10h function 0000h: unsupported video mode"
    );

    let nested = DeviceError::Memory(MemoryError::OutOfBounds { address: 0xb8000, length: 2 })
        .to_string();
    assert!(nested.starts_with("BIOS device memory access failed: guest memory range"));
    assert!(nested.contains("0x000B8000"));
    assert!(!nested.contains("Memory("));
}

#[test]
fn int1a_date_is_bcd_and_uses_the_supplied_clock() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    let mut regs = Registers::default();
    regs.set_ah(0x04);
    // 2000-02-29 23:59:59 UTC.
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 951_868_799).unwrap();
    assert_eq!(((regs.ecx >> 8) as u8, regs.ecx as u8), (0x20, 0x00));
    assert_eq!(((regs.edx >> 8) as u8, regs.edx as u8), (0x02, 0x29));
    assert!(!regs.carry());
}

#[test]
fn int1a_ticks_and_rollover_mirror_and_acknowledge_bda_state() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    let before_midnight = devices.update_clock(&mut memory, 86_399).unwrap();
    assert!(before_midnight.ticks > 0);
    let mut regs = Registers::default();
    regs.set_ah(0);
    devices.dispatch_interrupt(0x1a, &mut regs, &mut memory, 86_400).unwrap();
    assert_eq!(regs.al(), 1);
    assert_eq!(regs.cx(), 0);
    assert_eq!(regs.dx(), 0);
    assert_eq!(memory.0[0x470], 0);
    assert_eq!(u32::from_le_bytes(memory.0[0x46c..0x470].try_into().unwrap()), 0);
}

#[test]
fn int16_peek_sets_zero_flag_and_keeps_the_key_queued() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.initialize(&mut memory).unwrap();
    assert!(devices.push_key(KeyStroke { ascii: b'K', scan: 0x25 }));
    let mut regs = Registers::default();
    regs.set_ah(0x01);
    devices.dispatch_interrupt(0x16, &mut regs, &mut memory, 0).unwrap();
    assert_eq!((regs.al(), regs.ah()), (b'K', 0x25));
    assert_eq!(regs.eflags & (1 << 6), 0);
    assert_eq!(devices.keyboard.len(), 1);
}

#[test]
fn keyboard_ring_holds_fifteen_keys_and_peek_does_not_consume() {
    let mut keyboard = BiosKeyboard::new();
    for index in 0..15 { assert!(keyboard.push(KeyStroke { ascii: index, scan: 0x20 })); }
    assert!(!keyboard.push(KeyStroke { ascii: 0xff, scan: 0 }));
    assert_eq!(keyboard.len(), 15);
    assert_eq!(keyboard.peek().unwrap().ascii, 0);
    assert_eq!(keyboard.pop().unwrap().ascii, 0);
    assert_eq!(keyboard.pop().unwrap().ascii, 1);
}

#[test]
fn keyboard_queue_indices_match_bda_ring_offsets() {
    let mut keyboard = BiosKeyboard::new();
    let mut memory = Memory(vec![0; 0x100000]);
    assert!(keyboard.push(KeyStroke { ascii: b'A', scan: 0x1e }));
    keyboard.sync_bda(&mut memory).unwrap();
    assert_eq!(u16::from_le_bytes([memory.0[0x41a], memory.0[0x41b]]), 0x001e);
    assert_eq!(u16::from_le_bytes([memory.0[0x41c], memory.0[0x41d]]), 0x0020);
    assert_eq!(u16::from_le_bytes([memory.0[0x41e], memory.0[0x41f]]), 0x1e41);
}

#[test]
fn mouse_tracks_clamped_state_motion_and_press_release_counts() {
    let mut mouse = MouseDevice::new();
    mouse.set_present(true);
    mouse.inject(MouseInput { x: 20, y: 30, buttons: 1 });
    assert_eq!(mouse.state(), MouseState { x: 20, y: 30, buttons: 1 });
    assert_eq!(mouse.take_button_data(0, false), Some((1, 1, 20, 30)));
    mouse.inject(MouseInput { x: 2000, y: -5, buttons: 0 });
    assert_eq!(mouse.state(), MouseState { x: 639, y: 0, buttons: 0 });
    assert_eq!(mouse.take_button_data(0, true), Some((0, 1, 639, 0)));
    assert_ne!(mouse.take_motion(), (0, 0));
    assert_eq!(mouse.take_motion(), (0, 0));
}

#[test]
fn mouse_callback_is_a_guest_far_call_with_explicit_register_arguments() {
    let mut mouse = MouseDevice::new();
    mouse.set_present(true);
    mouse.install_callback(0x1234, 0x5678, 0x0002);
    let call = mouse.inject(MouseInput { x: 12, y: 34, buttons: 1 }).unwrap();
    assert_eq!(call.entry, GuestFarPointer { segment: 0x1234, offset: 0x5678 });
    let regs = call.callback_registers();
    assert_eq!((regs.cs, regs.ip(), regs.ax(), regs.bx(), regs.cx(), regs.dx()), (0x1234, 0x5678, 2, 1, 12, 34));
}

#[test]
fn mouse_reset_reports_absent_without_a_host_input_source() {
    let mut mouse = MouseDevice::new();
    mouse.reset();
    assert!(!mouse.present());
}

#[test]
fn mouse_presence_is_explicit_and_text_cursor_uses_default_inversion_masks() {
    let mut mouse = MouseDevice::new();
    assert!(mouse.inject(MouseInput { x: 80, y: 40, buttons: 1 }).is_none());
    assert!(!mouse.present());
    assert_eq!(mouse.state(), MouseState::default());

    mouse.set_present(true);
    assert!(mouse.text_cursor().is_none());
    mouse.show_cursor();
    mouse.inject(MouseInput { x: 80, y: 40, buttons: 1 });
    assert_eq!(mouse.text_cursor(), Some((80, 40, 0x77ff, 0x7700)));
}

#[test]
fn int33_mouse_state_save_restore_roundtrips_state_with_checked_far_buffers() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.mouse.set_present(true);
    devices.mouse.show_cursor();
    devices.mouse.set_x_range(10, 100);
    devices.mouse.set_y_range(10, 100);
    devices.mouse.set_position(32, 40);
    devices.mouse.set_mickey_ratio(4, 6);
    devices.mouse.set_text_cursor_masks(0x1234, 0x5678);
    devices.mouse.install_callback(0x1234, 0x5678, crate::mouse::EVENT_MOVEMENT);
    devices.mouse.inject(MouseInput { x: 36, y: 48, buttons: 1 });

    let mut regs = Registers::default();
    regs.set_ax(0x0015);
    devices.dispatch_interrupt(0x33, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.bx(), 98);

    regs.set_ax(0x0016);
    regs.es = 0x2000;
    regs.set_dx(0x0100);
    regs.set_bx(0xa55a); // The documented Microsoft call uses ES:DX, not BX.
    devices.dispatch_interrupt(0x33, &mut regs, &mut memory, 0).unwrap();
    let buffer = 0x20100;
    assert_eq!(&memory.0[buffer..buffer + 4], b"NTMS");

    devices.mouse.set_position(80, 90);
    devices.mouse.set_text_cursor_masks(0xaaaa, 0x5555);
    devices.mouse.hide_cursor();
    let _ = devices.mouse.take_button_data(0, false);
    let mut restore = Registers::default();
    restore.set_ax(0x0017);
    restore.set_bx(0xcccc);
    restore.es = 0x2000;
    restore.set_dx(0x0100);
    devices.dispatch_interrupt(0x33, &mut restore, &mut memory, 0).unwrap();

    assert_eq!(devices.mouse.state(), MouseState { x: 36, y: 48, buttons: 1 });
    assert_eq!(devices.mouse.text_cursor(), Some((36, 48, 0x1234, 0x5678)));
    assert_eq!(devices.mouse.inject(MouseInput { x: 37, y: 48, buttons: 1 }).unwrap().entry,
        GuestFarPointer { segment: 0x1234, offset: 0x5678 });

    let mut press = Registers::default();
    press.set_ax(0x0005);
    press.set_bx(0);
    devices.dispatch_interrupt(0x33, &mut press, &mut memory, 0).unwrap();
    assert_eq!((press.ax(), press.bx(), press.cx(), press.dx()), (1, 1, 36, 48));
    let mut motion = Registers::default();
    motion.set_ax(0x000b);
    devices.dispatch_interrupt(0x33, &mut motion, &mut memory, 0).unwrap();
    assert_eq!((motion.cx() as i16, motion.dx() as i16), (2, 6));

    // Corrupt opaque state is ignored atomically; guest memory faults remain typed.
    memory.0[buffer] = b'X';
    devices.mouse.set_position(50, 50);
    let mut bad_restore = restore.clone();
    devices.dispatch_interrupt(0x33, &mut bad_restore, &mut memory, 0).unwrap();
    assert_eq!(devices.mouse.state().x, 50);

    let mut bad_memory = Registers::default();
    bad_memory.set_ax(0x0016);
    bad_memory.es = 0xffff;
    bad_memory.set_dx(0xffff);
    assert!(matches!(devices.dispatch_interrupt(0x33, &mut bad_memory, &mut memory, 0),
        Err(DeviceError::Memory(MemoryError::OutOfBounds { .. }))));
}

#[test]
fn int33_function_24_reports_unavailable_hardware_metadata_without_inventing_it() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.mouse.set_present(true);
    devices.mouse.show_cursor();
    let mut text_cursor = Registers::default();
    text_cursor.set_ax(0x000a);
    text_cursor.set_bx(0);
    text_cursor.set_cx(0x1234);
    text_cursor.set_dx(0x5678);
    devices.dispatch_interrupt(0x33, &mut text_cursor, &mut memory, 0).unwrap();
    assert_eq!(devices.mouse.text_cursor(), Some((0, 0, 0x1234, 0x5678)));

    let mut hardware_cursor = Registers::default();
    hardware_cursor.set_ax(0x000a);
    hardware_cursor.set_bx(1);
    hardware_cursor.set_cx(2);
    hardware_cursor.set_dx(12);
    devices.dispatch_interrupt(0x33, &mut hardware_cursor, &mut memory, 0).unwrap();
    assert_eq!(devices.mouse.text_cursor(), Some((0, 0, 0x77ff, 0x7700)));

    let mut regs = Registers::default();
    regs.set_ax(0x0024);
    regs.set_bx(0);
    devices.dispatch_interrupt(0x33, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs.ax(), 0xffff);
    assert_eq!((regs.bx(), regs.cx(), regs.dx()), (0, 0, 0));
}

#[test]
fn int33_unknown_function_is_a_register_preserving_iret_noop() {
    let mut memory = Memory(vec![0x5a; 0x100000]);
    let mut devices = BiosDevices::new();
    devices.mouse.set_present(true);
    let mut regs = Registers::default();
    regs.set_ax(0x7ffe);
    regs.set_bx(0x1234);
    regs.set_cx(0x5678);
    regs.set_dx(0x9abc);
    regs.es = 0x2000;
    let unchanged = regs.clone();
    let outcome = devices.dispatch_interrupt(0x33, &mut regs, &mut memory, 0).unwrap();
    assert_eq!(regs, unchanged);
    assert!(outcome.actions.is_empty());
    assert!(memory.0.iter().all(|byte| *byte == 0x5a));
}

#[test]
fn rtc_converts_epoch_and_leap_day_without_host_locale() {
    assert_eq!(unix_seconds_to_datetime(0), crate::rtc::DateTime { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
    assert_eq!(unix_seconds_to_datetime(951_868_799), crate::rtc::DateTime { year: 2000, month: 2, day: 29, hour: 23, minute: 59, second: 59 });
    assert_eq!(unix_seconds_to_datetime(-1), crate::rtc::DateTime { year: 1969, month: 12, day: 31, hour: 23, minute: 59, second: 59 });
}

#[test]
fn rtc_ticks_are_bounded_and_midnight_rollover_is_acknowledged() {
    let mut rtc = RtcState::new();
    let before_midnight = rtc.observe(86_399);
    assert!(u64::from(before_midnight.ticks) < BIOS_TICKS_PER_DAY);
    assert_eq!(rtc.observe(86_400).midnight_rollovers, 1);
    rtc.acknowledge_midnight();
    assert_eq!(rtc.observe(86_401).midnight_rollovers, 0);
}

#[test]
fn video_scroll_preserves_rectangle_and_fills_vacated_cells() {
    let mut video = VideoDevice::new();
    video.put_cell(1, 0, b'A', 0x1f);
    video.put_cell(1, 1, b'B', 0x2e);
    video.scroll(0, 1, 1, 1, 1, 0x4f, false);
    let cells = video.snapshot().cells;
    assert_eq!(cells[1], TextCell { character: b'B', attribute: 0x2e });
    assert_eq!(cells[TEXT_COLS + 1], TextCell { character: b' ', attribute: 0x4f });
    assert_eq!(cells[0], TextCell::default());
}

#[test]
fn video_direct_guest_writes_are_reflected_in_snapshot() {
    let mut memory = Memory(vec![0; 0x100000]);
    let mut video = VideoDevice::new();
    memory.write(PhysAddr(VGA_TEXT_MEMORY), &[b'Q', 0x1e]).unwrap();
    video.refresh_from_guest(&memory).unwrap();
    assert_eq!(video.snapshot().cells[0], TextCell { character: b'Q', attribute: 0x1e });
}
