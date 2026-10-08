use super::*;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

struct Memory(Vec<u8>);

impl Memory {
    fn new() -> Self { Self(vec![0; 0x10_0000]) }

    fn put(&mut self, address: usize, bytes: &[u8]) {
        self.0[address..address + bytes.len()].copy_from_slice(bytes);
    }
}

impl GuestMemory for Memory {
    fn len(&self) -> u32 { self.0.len() as u32 }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let source = self.0.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let target = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        target.copy_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn hidden_page_text_services_use_its_cursor_and_ah13_coordinates() {
    let mut video = VideoDevice::new();
    let mut memory = Memory::new();
    let crtc_before = {
        let vga = video.vga().borrow();
        [vga.crtc[0x0c], vga.crtc[0x0d], vga.crtc[0x0e], vga.crtc[0x0f]]
    };

    let mut regs = Registers::default();
    regs.set_ax(0x0200);
    regs.set_bh(1);
    regs.set_dx(0x0304);
    video.dispatch_int10(&mut regs, &mut memory).unwrap();

    regs.set_ax(0x0941);
    regs.set_bx(0x011e);
    regs.set_cx(1);
    video.dispatch_int10(&mut regs, &mut memory).unwrap();
    let page_one = 0xb8000 + 0x1000;
    let cursor_cell = 3 * TEXT_COLS + 4;
    assert_eq!(&memory.0[page_one + cursor_cell * 2..page_one + cursor_cell * 2 + 2], b"A\x1e");

    memory.put(0x300, b"Z\x4e");
    regs.set_ax(0x1302);
    regs.set_bx(0x0107);
    regs.set_cx(1);
    regs.set_dx(0x0206);
    regs.es = 0;
    regs.set_bp(0x300);
    video.dispatch_int10(&mut regs, &mut memory).unwrap();
    let ah13_cell = 2 * TEXT_COLS + 6;
    assert_eq!(&memory.0[page_one + ah13_cell * 2..page_one + ah13_cell * 2 + 2], b"Z\x4e");
    assert_eq!(video.cursor_for_page(1), Some((4, 3)));
    let vga = video.vga().borrow();
    assert_eq!([vga.crtc[0x0c], vga.crtc[0x0d], vga.crtc[0x0e], vga.crtc[0x0f]], crtc_before);
}

#[test]
fn cursor_shape_keeps_bios_cursor_disable_bit() {
    let mut video = VideoDevice::new();
    video.set_cursor_shape(0x26, 0x0e);
    let start = video.vga().borrow().crtc[0x0a];
    assert_eq!(start & 0x3f, 0x26);

    video.set_cursor_shape(0x06, 0x0e);
    assert_eq!(video.vga().borrow().crtc[0x0a] & 0x20, 0);
}

#[test]
fn text_refresh_and_sync_wrap_at_the_end_of_the_32k_aperture() {
    let mut video = VideoDevice::new();
    let mut memory = Memory::new();
    memory.put(0xbfffe, b"A\x1e");
    memory.put(0xb8000, b"B\x2f");
    memory.put(0xc0000, b"ROM!");
    {
        let mut state = video.vga().borrow_mut();
        state.crtc[0x0c] = 0x3f;
        state.crtc[0x0d] = 0xff;
    }

    video.refresh_from_guest(&memory).unwrap();
    let cells = video.snapshot().cells;
    assert_eq!(cells[0], TextCell { character: b'A', attribute: 0x1e });
    assert_eq!(cells[1], TextCell { character: b'B', attribute: 0x2f });

    video.put_cell(0, 0, b'X', 0x1f);
    video.sync_to_guest(&mut memory).unwrap();
    assert_eq!(&memory.0[0xbfffe..0xc0000], b"X\x1f");
    assert_eq!(&memory.0[0xb8000..0xb8002], b"B\x2f");
    assert_eq!(&memory.0[0xc0000..0xc0004], b"ROM!");
}

#[test]
fn scroll_clips_bottom_and_right_to_the_active_text_geometry() {
    let mut video = VideoDevice::new();
    video.put_cell(0, 1, b'A', 0x07);
    video.scroll(0, 0, u8::MAX, u8::MAX, 1, 0x07, false);

    assert_eq!(video.snapshot().cells[0].character, b'A');
    assert_eq!(video.snapshot().cells[TEXT_COLS * TEXT_ROWS - 1].character, b' ');
}
