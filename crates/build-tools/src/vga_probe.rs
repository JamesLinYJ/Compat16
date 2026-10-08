use crate::probe::{build_error, CodeBuilder, ProbeBuildError};

pub const VGA_PROBE_FILE_NAME: &str = "VGAPROOF.TXT";
pub const VGA_PROBE_FILE_CONTENTS: &[u8] = b"vga-probe:v3\r\n";

const ORIGIN: u16 = 0x0100;

/// Assemble a visible-runtime COM fixture. Its checks use guest BIOS calls,
/// the mapped VGA aperture, and ordinary guest port instructions; the proof
/// file is written only after each graphics check succeeds.
pub fn vga_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let mut code = CodeBuilder::default();
    code.emit(&[0x0e, 0x1f]); // push cs / pop ds

    // Optional hardware/API probes must return to the guest. These checks
    // also exercise status FLAGS through the registered firmware's IRET.
    code.emit(&[0xba, 0xe0, 0x56, 0xec, 0x3c, 0xff]); // unconnected IN AL,DX
    check_equal(&mut code, "unconnected_port_ok", 14);
    code.emit(&[0xb8, 0xfe, 0x4f, 0xcd, 0x10, 0x3d, 0x4f, 0x01]);
    check_equal(&mut code, "vbe_unknown_service_ok", 15); // unknown 4Fh service: AX=014fh
    code.emit(&[0xb8, 0x00, 0xc0, 0xcd, 0x15]); // unsupported BIOS config query
    branch_or_fail(&mut code, 0x72, "bios_failure_carry_ok", 16);
    code.emit(&[0x80, 0xfc, 0x86]); // cmp ah,86h: unsupported system service
    check_equal(&mut code, "bios_failure_status_ok", 17);
    code.emit(&[0xb8, 0x00, 0xfe, 0xcd, 0x21]); // unsupported DOS function
    branch_or_fail(&mut code, 0x72, "dos_failure_carry_ok", 18);
    code.emit(&[0x3d, 0x01, 0x00]); // AX=1: invalid DOS function
    check_equal(&mut code, "dos_failure_status_ok", 19);

    // The mapped DOS C: volume reports Windows-backed space through AH=36h.
    code.emit(&[0xb2, 0x03, 0xb4, 0x36, 0xcd, 0x21, 0x3d, 0xff, 0xff]);
    branch_or_fail(&mut code, 0x75, "dos_space_available", 100);
    code.emit(&[0x81, 0xf9, 0x00, 0x02]); // cmp cx,512
    check_equal(&mut code, "dos_space_sector_size", 101);
    code.emit(&[0x39, 0xd3]); // cmp bx,dx: available clusters <= total
    branch_or_fail(&mut code, 0x76, "dos_space_counts", 102);
    code.emit(&[0xb2, 0x01, 0xb4, 0x36, 0xcd, 0x21, 0x3d, 0xff, 0xff]);
    check_equal(&mut code, "unmapped_dos_drive_absent", 103);

    // Enter VGA mode 13h and verify the standard VGA/analog DCC result.
    code.emit(&[0xb8, 0x13, 0x00, 0xcd, 0x10]); // mov ax,0013h; int 10h
    code.emit(&[0xb8, 0x00, 0x1a, 0xcd, 0x10]); // mov ax,1a00h; int 10h
    code.emit(&[0x3c, 0x1a]); // cmp al,1ah
    check_equal(&mut code, "dcc_present_ok", 1);
    code.emit(&[0x80, 0xfb, 0x08]); // cmp bl,08h (VGA, analog color)
    check_equal(&mut code, "dcc_vga_analog_ok", 2);

    // Paint the mode-13 framebuffer through ES:A0000 using REP STOSB.
    code.emit(&[0xb8, 0x00, 0xa0, 0x8e, 0xc0]); // mov ax,a000h; mov es,ax
    code.emit(&[0x31, 0xff]); // xor di,di
    code.emit(&[0xb9, 0x00, 0xfa]); // mov cx,64000
    code.emit(&[0xb0, 0x1d, 0xfc, 0xf3, 0xaa]); // mov al,1dh; cld; rep stosb
    code.emit(&[0x31, 0xff, 0x26, 0x8a, 0x05, 0x3c, 0x1d]); // read ES:[0000]
    check_equal(&mut code, "framebuffer_first_byte_ok", 3);
    code.emit(&[0xbf, 0xff, 0xf9, 0x26, 0x8a, 0x05, 0x3c, 0x1d]); // read ES:[f9ff]
    check_equal(&mut code, "framebuffer_last_byte_ok", 4);

    // Keep the written frame visible across multiple 4096-instruction
    // scheduler render intervals before exercising the BIOS pixel calls.
    code.emit(&[0xb9, 0x00, 0x10]); // mov cx,4096
    code.mark("render_delay");
    code.emit(&[0x90]); // nop
    code.branch(0xe2, "render_delay"); // loop render_delay

    // BIOS AH=0Ch writes and AH=0Dh reads pixel (100,100) in mode 13h.
    code.emit(&[0xb8, 0x2e, 0x0c, 0xbb, 0x00, 0x00]); // AX=0c2eh, page 0
    code.emit(&[0xb9, 100, 0x00, 0xba, 100, 0x00, 0xcd, 0x10]);
    code.emit(&[0xb8, 0x00, 0x0d, 0xbb, 0x00, 0x00]); // AX=0d00h, page 0
    code.emit(&[0xb9, 100, 0x00, 0xba, 100, 0x00, 0xcd, 0x10]);
    code.emit(&[0x3c, 0x2e]); // cmp al,2eh
    check_equal(&mut code, "mode13_pixel_ok", 5);

    // Program and read back one RGB triplet through the VGA DAC ports.
    code.emit(&[0xba, 0xc8, 0x03, 0xb0, 0x05, 0xee]); // DX=3c8h; OUT index 5
    code.emit(&[0xba, 0xc9, 0x03]); // DX=3c9h
    code.emit(&[0xb0, 0x12, 0xee, 0xb0, 0x23, 0xee, 0xb0, 0x34, 0xee]);
    code.emit(&[0xba, 0xc7, 0x03, 0xb0, 0x05, 0xee]); // set DAC read index
    code.emit(&[0xba, 0xc9, 0x03, 0xec, 0x3c, 0x12]); // read red, compare
    check_equal(&mut code, "dac_red_ok", 6);
    code.emit(&[0xec, 0x3c, 0x23]); // read green, compare
    check_equal(&mut code, "dac_green_ok", 7);
    code.emit(&[0xec, 0x3c, 0x34]); // read blue, compare
    check_equal(&mut code, "dac_blue_ok", 8);

    // Exercise the BIOS planar-pixel path in mode 12h and verify its readback.
    code.emit(&[0xb8, 0x12, 0x00, 0xcd, 0x10]); // mov ax,0012h; int 10h
    code.emit(&[0xb8, 0x0b, 0x0c, 0xbb, 0x00, 0x00]); // AX=0c0bh, page 0
    code.emit(&[0xb9, 123, 0x00, 0xba, 77, 0x00, 0xcd, 0x10]);
    code.emit(&[0xb8, 0x00, 0x0d, 0xbb, 0x00, 0x00]); // AX=0d00h, page 0
    code.emit(&[0xb9, 123, 0x00, 0xba, 77, 0x00, 0xcd, 0x10]);
    code.emit(&[0x3c, 0x0b]); // cmp al,0bh
    check_equal(&mut code, "mode12_pixel_ok", 9);

    code.emit(&[0xb9, 0x00, 0x10]); // allow planar scanout to reach the host
    code.mark("planar_render_delay");
    code.emit(&[0x90]);
    code.branch(0xe2, "planar_render_delay");

    // VBE 1.2 discovery and mode information use real ES:DI output blocks.
    code.emit(&[0x8c, 0xc8, 0x8e, 0xc0]); // mov ax,cs; mov es,ax
    code.emit(&[0xb8, 0x00, 0x4f, 0xbf]); // VBE 4F00h, ES:DI -> VbeInfoBlock
    code.emit_offset(ORIGIN, "vbe_info_buffer")?;
    code.emit(&[0xcd, 0x10]);
    check_vbe_ax(&mut code, "vbe_info_call_ok", 20);
    emit_si(&mut code, "vbe_info_buffer")?;
    check_word_at_si(&mut code, 0, 0x4556, "vbe_signature_ve_ok", 21); // "VE"
    check_word_at_si(&mut code, 2, 0x4153, "vbe_signature_sa_ok", 22); // "SA"
    check_word_at_si(&mut code, 4, 0x0102, "vbe_version_102_ok", 23);
    check_word_at_si(&mut code, 18, 64, "vbe_memory_size_ok", 91); // 64 x 64 KiB = 4 MiB

    emit_vbe_mode_info(&mut code, 0x0101, "mode101_info_buffer", "mode101_info_call_ok", 24)?;
    emit_si(&mut code, "mode101_info_buffer")?;
    check_word_at_si(&mut code, 0, 0x001b, "mode101_attributes_ok", 25);
    check_byte_at_si(&mut code, 2, 0x07, "mode101_window_a_ok", 26);
    check_byte_at_si(&mut code, 3, 0, "mode101_window_b_ok", 27);
    check_word_at_si(&mut code, 4, 64, "mode101_granularity_ok", 28);
    check_word_at_si(&mut code, 6, 64, "mode101_window_size_ok", 29);
    check_word_at_si(&mut code, 8, 0xa000, "mode101_window_segment_ok", 30);
    check_byte_at_si(&mut code, 24, 1, "mode101_planes_ok", 31);
    check_byte_at_si(&mut code, 25, 8, "mode101_bpp_ok", 32);
    check_byte_at_si(&mut code, 26, 1, "mode101_banks_ok", 84);
    check_byte_at_si(&mut code, 27, 4, "mode101_memory_model_ok", 33);
    check_byte_at_si(&mut code, 28, 0, "mode101_bank_size_ok", 85);
    check_word_at_si(&mut code, 16, 640, "mode101_stride_ok", 34);
    check_word_at_si(&mut code, 18, 640, "mode101_width_ok", 35);
    check_word_at_si(&mut code, 20, 480, "mode101_height_ok", 36);
    check_byte_at_si(&mut code, 29, 12, "mode101_image_pages_ok", 89);

    emit_vbe_mode_set(&mut code, 0x0101, "mode101_set_ok", 37);
    emit_vbe_mode_query(&mut code, 0x0101, "mode101_query_ax_ok", "mode101_query_bx_ok", 38, 39);

    // VBE 4F05 set/get bank uses 64 KiB granularity. Readbacks across banks
    // prove that bank 4 addresses memory beyond the first 256 KiB of VRAM.
    emit_vbe_bank_set(&mut code, 0, "bank0_set_ok", 40);
    emit_vbe_bank_query(&mut code, 0, "bank0_get_ax_ok", "bank0_get_dx_ok", 41, 42);
    emit_bank_byte_write_read(&mut code, 0x13, "bank0_memory_ok", 43);

    emit_vbe_bank_set(&mut code, 1, "bank1_set_ok", 44);
    emit_bank_byte_write_read(&mut code, 0x27, "bank1_memory_ok", 45);
    emit_vbe_bank_query(&mut code, 1, "bank1_get_ax_ok", "bank1_get_dx_ok", 46, 47);

    emit_vbe_bank_set(&mut code, 4, "bank4_set_ok", 48);
    emit_bank_byte_write_read(&mut code, 0x5a, "bank4_memory_ok", 49);
    emit_vbe_bank_query(&mut code, 4, "bank4_get_ax_ok", "bank4_get_dx_ok", 50, 51);
    emit_vbe_bank_set(&mut code, 1, "bank1_restore_ok", 52);
    emit_bank_byte_read(&mut code, 0x27, "bank1_retained_ok", 53);
    emit_vbe_bank_set(&mut code, 0, "bank0_restore_ok", 54);
    emit_bank_byte_read(&mut code, 0x13, "bank0_retained_ok", 55);

    // Leave mode 101 visible long enough for multiple render intervals.
    emit_render_delay(&mut code, "mode101_render_delay");

    emit_vbe_mode_info(&mut code, 0x0111, "mode111_info_buffer", "mode111_info_call_ok", 56)?;
    emit_si(&mut code, "mode111_info_buffer")?;
    check_word_at_si(&mut code, 0, 0x001b, "mode111_attributes_ok", 57);
    check_word_at_si(&mut code, 4, 64, "mode111_granularity_ok", 58);
    check_word_at_si(&mut code, 6, 64, "mode111_window_size_ok", 59);
    check_word_at_si(&mut code, 8, 0xa000, "mode111_window_segment_ok", 60);
    check_word_at_si(&mut code, 16, 1280, "mode111_stride_ok", 61);
    check_word_at_si(&mut code, 18, 640, "mode111_width_ok", 62);
    check_word_at_si(&mut code, 20, 480, "mode111_height_ok", 63);
    check_byte_at_si(&mut code, 24, 1, "mode111_planes_ok", 64);
    check_byte_at_si(&mut code, 25, 16, "mode111_bpp_ok", 65);
    check_byte_at_si(&mut code, 27, 6, "mode111_memory_model_ok", 66);
    check_byte_at_si(&mut code, 2, 0x07, "mode111_window_a_ok", 86);
    check_byte_at_si(&mut code, 26, 1, "mode111_banks_ok", 87);
    check_byte_at_si(&mut code, 28, 0, "mode111_bank_size_ok", 88);
    check_byte_at_si(&mut code, 29, 5, "mode111_image_pages_ok", 90);
    check_byte_at_si(&mut code, 31, 5, "mode111_red_size_ok", 67);
    check_byte_at_si(&mut code, 32, 11, "mode111_red_position_ok", 68);
    check_byte_at_si(&mut code, 33, 6, "mode111_green_size_ok", 69);
    check_byte_at_si(&mut code, 34, 5, "mode111_green_position_ok", 70);
    check_byte_at_si(&mut code, 35, 5, "mode111_blue_size_ok", 71);
    check_byte_at_si(&mut code, 36, 0, "mode111_blue_position_ok", 72);

    emit_vbe_mode_set(&mut code, 0x0111, "mode111_set_ok", 73);
    emit_vbe_mode_query(&mut code, 0x0111, "mode111_query_ax_ok", "mode111_query_bx_ok", 74, 75);
    emit_vbe_bank_set(&mut code, 0, "mode111_bank0_set_ok", 76);
    emit_vbe_bank_query(&mut code, 0, "mode111_bank0_get_ax_ok", "mode111_bank0_get_dx_ok", 77, 78);

    // A red RGB565 band makes the direct-color mode visible and reads the
    // first and last words in its mapped 64 KiB window back through ES:A000.
    code.emit(&[0xb8, 0x00, 0xa0, 0x8e, 0xc0, 0x31, 0xff]); // ES=A000, DI=0
    code.emit(&[0xb8, 0x00, 0xf8, 0xb9, 0x00, 0x80, 0xfc, 0xf3, 0xab]); // REP STOSW 8000h RGB565 red pixels
    code.emit(&[0x31, 0xff, 0x26, 0x8b, 0x05, 0x3d, 0x00, 0xf8]);
    check_equal(&mut code, "mode111_first_pixel_ok", 79);
    code.emit(&[0xbf, 0xfe, 0xff, 0x26, 0x8b, 0x05, 0x3d, 0x00, 0xf8]);
    check_equal(&mut code, "mode111_last_pixel_ok", 80);
    emit_render_delay(&mut code, "mode111_render_delay");

    emit_vbe_mode_set(&mut code, 0x0003, "vbe_text_mode_set_ok", 81);
    emit_vbe_mode_query(&mut code, 0x0003, "vbe_text_mode_query_ax_ok", "vbe_text_mode_query_bx_ok", 82, 83);

    // Restore text mode before reporting success through DOS file services.
    code.emit(&[0xb8, 0x03, 0x00, 0xcd, 0x10]); // mov ax,0003h; int 10h
    code.emit(&[0x0e, 0x1f]); // reestablish DS=CS for DOS filename/data pointers
    code.emit_address(ORIGIN, "proof_filename")?;
    code.emit(&[0x31, 0xc9, 0xb4, 0x3c, 0xcd, 0x21]); // create/truncate file
    branch_or_fail(&mut code, 0x73, "proof_open", 10); // jnc proof_open
    code.mark("proof_open");
    code.emit(&[0x89, 0xc3]); // mov bx,ax (file handle)
    code.emit_address(ORIGIN, "proof_contents")?;
    code.emit(&[0xb9]);
    code.emit_word(u16::try_from(VGA_PROBE_FILE_CONTENTS.len()).map_err(|_| {
        build_error("VGA proof contents do not fit the DOS write byte count")
    })?);
    code.emit(&[0xb4, 0x40, 0xcd, 0x21]); // write BX/CX bytes from DS:DX
    branch_or_fail(&mut code, 0x73, "proof_written", 11); // jnc proof_written
    code.mark("proof_written");
    code.emit(&[0x3d]); // cmp ax, expected byte count
    code.emit_word(VGA_PROBE_FILE_CONTENTS.len() as u16);
    code.branch(0x74, "proof_count_ok"); // je proof_count_ok
    set_failure(&mut code, 12);
    code.mark("proof_count_ok");
    code.emit(&[0xb4, 0x3e, 0xcd, 0x21]); // close BX
    branch_or_fail(&mut code, 0x73, "proof_closed", 13); // jnc proof_closed
    code.mark("proof_closed");
    code.emit(&[0xb8, 0x00, 0x4c, 0xcd, 0x21]); // exit 0

    code.mark("fail");
    code.emit(&[0x53, 0xb8, 0x03, 0x00, 0xcd, 0x10, 0x5b]); // restore text, keep status
    code.emit(&[0xb8, 0x00, 0x4c, 0x88, 0xd8, 0xcd, 0x21]); // exit with BL status

    code.mark("vbe_info_buffer");
    code.emit(&[0; 512]);
    code.mark("mode101_info_buffer");
    code.emit(&[0; 256]);
    code.mark("mode111_info_buffer");
    code.emit(&[0; 256]);
    code.mark("proof_filename");
    code.emit(VGA_PROBE_FILE_NAME.as_bytes());
    code.emit(&[0]);
    code.mark("proof_contents");
    code.emit(VGA_PROBE_FILE_CONTENTS);

    let image = code.finish(ORIGIN)?;
    if image.len() > 0xff00 {
        return Err(build_error("VGA COM probe exceeds the DOS COM image limit"));
    }
    Ok(image)
}

fn check_equal(code: &mut CodeBuilder, passed: &'static str, failure_status: u8) {
    code.branch(0x74, passed); // je passed
    set_failure(code, failure_status);
    code.mark(passed);
}

fn check_vbe_ax(code: &mut CodeBuilder, passed: &'static str, failure_status: u8) {
    code.emit(&[0x3d, 0x4f, 0x00]); // VBE success is AX=004Fh
    check_equal(code, passed, failure_status);
}

fn emit_si(code: &mut CodeBuilder, label: &'static str) -> Result<(), ProbeBuildError> {
    code.emit(&[0xbe]); // mov si, label
    code.emit_offset(ORIGIN, label)
}

fn check_word_at_si(
    code: &mut CodeBuilder,
    displacement: u8,
    expected: u16,
    passed: &'static str,
    failure_status: u8,
) {
    if displacement == 0 {
        code.emit(&[0x8b, 0x04]); // mov ax,[si]
    } else {
        code.emit(&[0x8b, 0x44, displacement]); // mov ax,[si+disp8]
    }
    code.emit(&[0x3d]);
    code.emit_word(expected);
    check_equal(code, passed, failure_status);
}

fn check_byte_at_si(
    code: &mut CodeBuilder,
    displacement: u8,
    expected: u8,
    passed: &'static str,
    failure_status: u8,
) {
    if displacement == 0 {
        code.emit(&[0x8a, 0x04]); // mov al,[si]
    } else {
        code.emit(&[0x8a, 0x44, displacement]); // mov al,[si+disp8]
    }
    code.emit(&[0x3c, expected]);
    check_equal(code, passed, failure_status);
}

fn emit_vbe_mode_info(
    code: &mut CodeBuilder,
    mode: u16,
    buffer: &'static str,
    passed: &'static str,
    failure_status: u8,
) -> Result<(), ProbeBuildError> {
    code.emit(&[0x8c, 0xc8, 0x8e, 0xc0]); // ES=CS
    code.emit(&[0xb8, 0x01, 0x4f, 0xb9]); // AX=4F01h, CX=mode
    code.emit_word(mode);
    code.emit(&[0xbf]);
    code.emit_offset(ORIGIN, buffer)?;
    code.emit(&[0xcd, 0x10]);
    check_vbe_ax(code, passed, failure_status);
    Ok(())
}

fn emit_vbe_mode_set(
    code: &mut CodeBuilder,
    mode: u16,
    passed: &'static str,
    failure_status: u8,
) {
    code.emit(&[0xb8, 0x02, 0x4f, 0xbb]); // AX=4F02h, BX=mode
    code.emit_word(mode);
    code.emit(&[0xcd, 0x10]);
    check_vbe_ax(code, passed, failure_status);
}

fn emit_vbe_mode_query(
    code: &mut CodeBuilder,
    expected_mode: u16,
    ax_passed: &'static str,
    bx_passed: &'static str,
    ax_failure: u8,
    bx_failure: u8,
) {
    code.emit(&[0xb8, 0x03, 0x4f, 0xcd, 0x10]); // AX=4F03h
    check_vbe_ax(code, ax_passed, ax_failure);
    code.emit(&[0x81, 0xfb]); // cmp bx,mode
    code.emit_word(expected_mode);
    check_equal(code, bx_passed, bx_failure);
}

fn emit_vbe_bank_set(
    code: &mut CodeBuilder,
    bank: u16,
    passed: &'static str,
    failure_status: u8,
) {
    code.emit(&[0xb8, 0x05, 0x4f, 0xbb, 0x00, 0x00, 0xba]); // set window A bank
    code.emit_word(bank);
    code.emit(&[0xcd, 0x10]);
    check_vbe_ax(code, passed, failure_status);
}

fn emit_vbe_bank_query(
    code: &mut CodeBuilder,
    expected_bank: u16,
    ax_passed: &'static str,
    dx_passed: &'static str,
    ax_failure: u8,
    dx_failure: u8,
) {
    code.emit(&[0xb8, 0x05, 0x4f, 0xbb, 0x00, 0x01, 0xcd, 0x10]); // get window A bank
    check_vbe_ax(code, ax_passed, ax_failure);
    code.emit(&[0x81, 0xfa]); // cmp dx,bank
    code.emit_word(expected_bank);
    check_equal(code, dx_passed, dx_failure);
}

fn emit_bank_byte_write_read(
    code: &mut CodeBuilder,
    value: u8,
    passed: &'static str,
    failure_status: u8,
) {
    code.emit(&[0xb8, 0x00, 0xa0, 0x8e, 0xc0, 0x31, 0xff, 0xb0, value]);
    code.emit(&[0x26, 0x88, 0x05, 0x26, 0x8a, 0x05, 0x3c, value]);
    check_equal(code, passed, failure_status);
}

fn emit_bank_byte_read(
    code: &mut CodeBuilder,
    value: u8,
    passed: &'static str,
    failure_status: u8,
) {
    code.emit(&[0xb8, 0x00, 0xa0, 0x8e, 0xc0, 0x31, 0xff]);
    code.emit(&[0x26, 0x8a, 0x05, 0x3c, value]);
    check_equal(code, passed, failure_status);
}

fn emit_render_delay(code: &mut CodeBuilder, label: &'static str) {
    code.emit(&[0xb9, 0x00, 0x10]); // 4096 iterations, two instructions each
    code.mark(label);
    code.emit(&[0x90]);
    code.branch(0xe2, label);
}

fn branch_or_fail(code: &mut CodeBuilder, success_opcode: u8, passed: &'static str, status: u8) {
    code.branch(success_opcode, passed);
    set_failure(code, status);
    code.mark(passed);
}

fn set_failure(code: &mut CodeBuilder, status: u8) {
    code.emit(&[0xb3, status]); // mov bl, nonzero stage-specific exit status
    code.jump_near("fail");
}

#[cfg(test)]
mod tests;
