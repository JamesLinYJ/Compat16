use super::{dos_probe_bytes, probe_file_contents, probe_file_name, ProbeFormat};

#[test]
fn com_probe_uses_dos_file_services_and_carries_the_expected_proof() {
    let image = dos_probe_bytes(ProbeFormat::Com).expect("COM probe assembles");
    assert!(image.len() < 0xff00);
    assert!(image.windows(2).any(|window| window == &[0xcd, 0x21]));
    let mut filename = probe_file_name().as_bytes().to_vec();
    filename.push(0);
    assert!(image
        .windows(filename.len())
        .any(|window| window == filename.as_slice()));
    assert!(image
        .windows(probe_file_contents().len())
        .any(|window| window == probe_file_contents()));
}

#[test]
fn mz_probe_has_one_segment_relocation_and_the_same_dos_proof() {
    let image = dos_probe_bytes(ProbeFormat::Mz).expect("MZ probe assembles");
    assert_eq!(&image[..2], b"MZ");
    assert_eq!(u16::from_le_bytes([image[6], image[7]]), 1);
    assert_eq!(u16::from_le_bytes([image[24], image[25]]), 0x1c);
    assert_eq!(u16::from_le_bytes([image[28], image[29]]), 1);
    assert!(image
        .windows(probe_file_contents().len())
        .any(|window| window == probe_file_contents()));
}
