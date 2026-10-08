use super::{vga_probe_bytes, VGA_PROBE_FILE_CONTENTS, VGA_PROBE_FILE_NAME};

#[test]
fn com_fixture_contains_guest_vga_and_vbe_checks() {
    let image = vga_probe_bytes().expect("VGA COM fixture assembles");
    assert!(image.len() < 0xff00);
    assert!(image.starts_with(&[0x0e, 0x1f])); // push cs / pop ds
    assert!(image
        .windows(8)
        .any(|bytes| bytes == &[0xb8, 0xfe, 0x4f, 0xcd, 0x10, 0x3d, 0x4f, 0x01]));
    assert!(image
        .windows(5)
        .any(|bytes| bytes == &[0xb8, 0x13, 0x00, 0xcd, 0x10]));
    assert!(image
        .windows(5)
        .any(|bytes| bytes == &[0xb8, 0x00, 0x1a, 0xcd, 0x10]));
    assert!(image
        .windows(5)
        .any(|bytes| bytes == &[0xb8, 0x00, 0xa0, 0x8e, 0xc0]));
    assert!(image.windows(2).any(|bytes| bytes == &[0xf3, 0xaa]));
    assert!(image.windows(2).any(|bytes| bytes == &[0xf3, 0xab]));
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0xba, 0xc8, 0x03, 0xb0, 0x05, 0xee]));
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0xba, 0xc7, 0x03, 0xb0, 0x05, 0xee]));
    assert!(image
        .windows(5)
        .any(|bytes| bytes == &[0xb8, 0x12, 0x00, 0xcd, 0x10]));
    assert!(image
        .windows(7)
        .any(|bytes| bytes == &[0x31, 0xff, 0x26, 0x8a, 0x05, 0x3c, 0x1d]));
    assert!(image
        .windows(4)
        .any(|bytes| bytes == &[0xb8, 0x00, 0x4f, 0xbf])); // 4F00, ES:DI buffer
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0xb8, 0x01, 0x4f, 0xb9, 0x01, 0x01])); // mode 101 info
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0xb8, 0x01, 0x4f, 0xb9, 0x11, 0x01])); // mode 111 info
    assert!(image
        .windows(11)
        .any(|bytes| bytes == &[0xb8, 0x05, 0x4f, 0xbb, 0x00, 0x00, 0xba, 0x04, 0x00, 0xcd, 0x10]));
    assert!(image
        .windows(8)
        .any(|bytes| bytes == &[0xb8, 0x05, 0x4f, 0xbb, 0x00, 0x01, 0xcd, 0x10]));
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0x26, 0x88, 0x05, 0x26, 0x8a, 0x05]));
}

#[test]
fn fixture_checks_vbe_12_mode_info_and_uses_distinct_failure_codes() {
    let image = vga_probe_bytes().expect("VGA COM fixture assembles");
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0x8b, 0x44, 0x04, 0x3d, 0x02, 0x01])); // VBE version 0102h
    assert_eq!(
        image
            .windows(5)
            .filter(|bytes| *bytes == &[0x8b, 0x04, 0x3d, 0x1b, 0x00])
            .count(),
        2
    ); // supported, information, color, graphics; no TTY claim
    assert_eq!(
        image
            .windows(5)
            .filter(|bytes| *bytes == &[0x8a, 0x44, 0x02, 0x3c, 0x07])
            .count(),
        2
    ); // window A exists, relocatable, readable, writable
    assert_eq!(
        image
            .windows(5)
            .filter(|bytes| *bytes == &[0x8a, 0x44, 0x1a, 0x3c, 0x01])
            .count(),
        2
    ); // one scanline bank in each packed-pixel/direct-color mode
    assert_eq!(
        image
            .windows(5)
            .filter(|bytes| *bytes == &[0x8a, 0x44, 0x1c, 0x3c, 0x00])
            .count(),
        2
    ); // BankSize is zero for packed-pixel modes
    assert!(image
        .windows(6)
        .any(|bytes| bytes == &[0x8b, 0x44, 0x12, 0x3d, 0x40, 0x00])); // 4F00 reports 64 KiB units
    assert!(image
        .windows(5)
        .any(|bytes| bytes == &[0x8a, 0x44, 0x1d, 0x3c, 12])); // mode 101 image pages minus one
    assert!(image
        .windows(5)
        .any(|bytes| bytes == &[0x8a, 0x44, 0x1d, 0x3c, 5])); // mode 111 image pages minus one
    assert!(image
        .windows(2)
        .any(|bytes| bytes == &[0xb3, 0x01]));
    assert!(image
        .windows(2)
        .any(|bytes| bytes == &[0xb3, 0x0d]));
    assert!(image
        .windows(2)
        .any(|bytes| bytes == &[0xb3, 0x53])); // final VBE mode query has a unique status
    assert!(image
        .windows(2)
        .any(|bytes| bytes == &[0xb3, 0x5b])); // 4F00 memory-size check has a unique status
}

#[test]
fn versioned_proof_is_written_only_after_vbe_mode_restore() {
    let image = vga_probe_bytes().expect("VGA COM fixture assembles");
    let mut filename = VGA_PROBE_FILE_NAME.as_bytes().to_vec();
    filename.push(0);
    assert!(image
        .windows(filename.len())
        .any(|bytes| bytes == filename.as_slice()));
    assert!(image
        .windows(VGA_PROBE_FILE_CONTENTS.len())
        .any(|bytes| bytes == VGA_PROBE_FILE_CONTENTS));
    assert!(image
        .windows(4)
        .any(|bytes| bytes == &[0xb8, 0x00, 0x4c, 0xcd])); // DOS exit service

    let mode_101 = image
        .windows(8)
        .position(|bytes| bytes == &[0xb8, 0x02, 0x4f, 0xbb, 0x01, 0x01, 0xcd, 0x10])
        .expect("mode 101 set");
    let bank_4 = image
        .windows(11)
        .position(|bytes| bytes == &[0xb8, 0x05, 0x4f, 0xbb, 0x00, 0x00, 0xba, 0x04, 0x00, 0xcd, 0x10])
        .expect("bank 4 set");
    let mode_111 = image
        .windows(8)
        .position(|bytes| bytes == &[0xb8, 0x02, 0x4f, 0xbb, 0x11, 0x01, 0xcd, 0x10])
        .expect("mode 111 set");
    let vbe_text_restore = image
        .windows(8)
        .position(|bytes| bytes == &[0xb8, 0x02, 0x4f, 0xbb, 0x03, 0x00, 0xcd, 0x10])
        .expect("VBE standard text-mode restore");
    let bios_text_restore = image
        .windows(5)
        .position(|bytes| bytes == &[0xb8, 0x03, 0x00, 0xcd, 0x10])
        .expect("final BIOS text-mode restore");
    let file_create = image
        .windows(6)
        .position(|bytes| bytes == &[0x31, 0xc9, 0xb4, 0x3c, 0xcd, 0x21])
        .expect("DOS proof-file create");

    assert!(mode_101 < bank_4);
    assert!(bank_4 < mode_111);
    assert!(mode_111 < vbe_text_restore);
    assert!(vbe_text_restore < bios_text_restore);
    assert!(bios_text_restore < file_create);
}
