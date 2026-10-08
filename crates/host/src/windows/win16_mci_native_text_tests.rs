use super::{guest_output_from_wide, guest_output_projection, wide_capacity};
use crate::windows::guest_text::GuestTextCodec;

#[test]
fn mci_wide_output_respects_guest_multibyte_capacity_and_nul() {
    let codec = GuestTextCodec::new(932).expect("Windows Japanese code page is available");
    let text = [0x3042, 0]; // HIRAGANA LETTER A

    assert_eq!(wide_capacity(Some(3)).unwrap(), 3);
    assert_eq!(
        guest_output_from_wide(codec, &text, Some(3)).unwrap(),
        [0x82, 0xa0, 0]
    );
    assert_eq!(
        guest_output_from_wide(codec, &text, Some(2)).unwrap(),
        [0, 0]
    );
    assert!(guest_output_projection(codec, &text, Some(2)).unwrap().1);
    assert!(!guest_output_projection(codec, &text, Some(3)).unwrap().1);
}
