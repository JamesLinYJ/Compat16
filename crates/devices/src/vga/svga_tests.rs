use super::{SVGA_BANK_BYTES, VGA_VRAM_BYTES, VIDEO_MEMORY_BYTES, VgaDevice, VgaState, svga};

#[test]
fn supported_vbe_modes_report_packed_pixel_metadata() {
    assert_eq!(svga::SUPPORTED_MODES, [0x101, 0x103, 0x105, 0x111, 0x114, 0x117]);
    let expected = [
        (0x101, 640, 480, 8, 1),
        (0x103, 800, 600, 8, 1),
        (0x105, 1024, 768, 8, 1),
        (0x111, 640, 480, 16, 2),
        (0x114, 800, 600, 16, 2),
        (0x117, 1024, 768, 16, 2),
    ];

    for (mode, width, height, bits_per_pixel, bytes_per_pixel) in expected {
        let info = svga::mode_info(mode).unwrap();
        assert_eq!(info.mode, mode);
        assert_eq!(info.width, width);
        assert_eq!(info.height, height);
        assert_eq!(info.bits_per_pixel, bits_per_pixel);
        assert_eq!(info.bytes_per_pixel, bytes_per_pixel);
        assert_eq!(info.default_stride, width);
        assert_eq!(info.memory_bytes as usize, VIDEO_MEMORY_BYTES);
    }
    assert!(svga::mode_info(0x102).is_none());
    assert_eq!(VGA_VRAM_BYTES, 256 * 1024);
    assert_eq!(VIDEO_MEMORY_BYTES, 4 * 1024 * 1024);
    assert_eq!(VgaState::new().vram.len(), VIDEO_MEMORY_BYTES);
}

#[test]
fn svga_mode_set_is_atomic_and_clear_flag_controls_all_memory() {
    let mut state = VgaState::new();
    state.vram[0] = 0xa5;
    state.vram[VIDEO_MEMORY_BYTES - 1] = 0x5a;

    assert!(state.set_svga_mode(0x101, false));
    assert_eq!(state.bios_mode, 0xff);
    assert!(state.svga.as_ref().unwrap().preserve_memory);
    assert_eq!(state.vram[0], 0xa5);
    assert_eq!(state.vram[VIDEO_MEMORY_BYTES - 1], 0x5a);

    let old_mode = state.bios_mode;
    let old_svga = state.svga.clone();
    let old_generation = state.generation;
    let old_sample = state.vram[VIDEO_MEMORY_BYTES - 1];
    assert!(!state.set_svga_mode(0x102, true));
    assert_eq!(state.bios_mode, old_mode);
    assert_eq!(state.svga, old_svga);
    assert_eq!(state.generation, old_generation);
    assert_eq!(state.vram[VIDEO_MEMORY_BYTES - 1], old_sample);

    assert!(state.set_svga_mode(0x111, true));
    assert!(!state.svga.as_ref().unwrap().preserve_memory);
    assert!(state.vram.iter().all(|byte| *byte == 0));
}

#[test]
fn legacy_mode_restores_vga_decode_and_clears_only_legacy_storage() {
    let mut state = VgaState::new();
    assert!(state.set_svga_mode(0x101, true));
    state.vram[0x30000] = 0x6b;
    state.vram[3] = 0xcc;

    assert!(state.set_mode(0x03, true));
    assert!(state.svga.is_none());
    assert_eq!(state.bios_mode, 0x03);
    assert_eq!(state.vram[0], b' ');
    assert_eq!(state.vram[3], 0xcc);
    assert_eq!(state.vram[0x30000], 0x6b);
}

#[test]
fn a000_window_uses_selected_svga_bank_and_b000_is_disconnected() {
    let mut state = VgaState::new();
    assert!(state.set_svga_mode(0x101, true));
    assert!(state.set_svga_bank(63));
    let bank_start = 63 * SVGA_BANK_BYTES;
    state.aperture_write_byte(0x2345, 0xa5);
    assert_eq!(state.vram[bank_start + 0x2345], 0xa5);
    assert_eq!(state.aperture_read(0x2345), 0xa5);
    assert!(!state.set_svga_bank(64));
    assert_eq!(state.svga.as_ref().unwrap().bank, 63);

    // Reprogram GC6 to make the whole A0000-BFFFF range visible to legacy VGA.
    // Active VBE mode must still disconnect B0000-BFFFF from both decoders.
    state.graphics[6] &= !0x0c;
    let generation = state.generation;
    assert_eq!(state.aperture_read(0x1_0000), 0xff);
    state.aperture_write_byte(0x1_0000, 0x5a);
    assert_eq!(state.vram[bank_start + 0x2345], 0xa5);
    assert_eq!(state.vram[0x1_0000], 0);
    assert_eq!(state.generation, generation);
}

#[test]
fn stride_and_display_origin_reject_invalid_changes_without_partial_updates() {
    let mut state = VgaState::new();
    assert!(state.set_svga_mode(0x101, true));
    assert_eq!(state.set_svga_stride(700), Some((700, 700, 5991)));
    assert!(state.set_svga_display_start(60, 1));

    let old = state.svga.clone();
    assert!(!state.set_svga_display_start(61, 1));
    assert_eq!(state.svga, old);
    assert_eq!(state.set_svga_stride(699), None);
    assert_eq!(state.svga, old);

    let (_, pixels, max_lines) = state.set_svga_stride(800).unwrap();
    assert_eq!(pixels, 800);
    assert_eq!(max_lines, (VIDEO_MEMORY_BYTES / 800) as u16);
    assert_eq!(state.svga.as_ref().unwrap().display_x, 60);
    assert!(state.set_svga_display_start(160, 1));
    assert!(state.svga.as_ref().unwrap().is_valid());
}

#[test]
fn graphics_frame_uses_shared_bank_memory_stride_origin_and_pixel_formats() {
    let device = VgaDevice::new();
    {
        let mut state = device.borrow_mut();
        assert!(state.set_svga_mode(0x101, true));
        assert!(state.set_svga_stride(650).is_some());
        assert!(state.set_svga_display_start(1, 1));
        state.palette[5] = [63, 32, 0];
        assert!(state.set_svga_bank(0));
        state.aperture_write_byte(0, 5);
        state.vram[651] = 5;
    }
    let frame = device.graphics_frame().unwrap();
    assert_eq!((frame.width, frame.height), (640, 480));
    assert_eq!(frame.pixels[0], 0x00ff_8200);

    {
        let mut state = device.borrow_mut();
        assert!(state.set_svga_mode(0x111, true));
        state.vram[..2].copy_from_slice(&0xf800u16.to_le_bytes());
    }
    let frame = device.graphics_frame().unwrap();
    assert_eq!((frame.width, frame.height), (640, 480));
    assert_eq!(frame.pixels[0], 0x00ff_0000);
}
