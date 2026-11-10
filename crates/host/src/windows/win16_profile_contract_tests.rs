//! Windows checks for the Win16 profile integer and string results.
//! Paths are host temporary files, never guest addresses.

use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicU32, Ordering};

use super::{private_int_wide, private_string_wide, private_write_wide};
use crate::windows::guest_text::GuestTextCodec;
use windows_sys::Win32::Globalization::CP_UTF8;

fn codec() -> GuestTextCodec {
    GuestTextCodec::new(CP_UTF8).expect("Windows provides UTF-8 code-page conversion")
}

struct TempIni {
    path: std::path::PathBuf,
    wide: Vec<u16>,
}

impl TempIni {
    fn create(label: &str, body: Option<&str>) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "compat16-profile-{}-{}-{label}.ini",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        if let Some(body) = body {
            std::fs::write(&path, body).expect("write profile fixture");
        }
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        Self { path, wide }
    }
}

impl Drop for TempIni {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

const PROFILE: &str = "\
[App]\r\n\
empty=\r\n\
negative=-4\r\n\
prefix=102abc\r\n\
word=40000\r\n\
huge=70000\r\n\
zero=0\r\n\
octal=010\r\n\
hex=0x10\r\n\
text=ABCDEF\r\n";

#[test]
fn missing_file_and_absent_names_return_the_default_word() {
    let file = TempIni::create("missing", None);
    let codec = codec();
    assert_eq!(
        private_int_wide(codec, Some(b"App"), Some(b"Key"), 7, &file.wide).unwrap(),
        7
    );
    assert_eq!(
        private_int_wide(codec, Some(b"App"), Some(b"Key"), -1, &file.wide).unwrap(),
        0xffff
    );
    assert_eq!(
        private_int_wide(codec, None, Some(b"Key"), 4, &file.wide).unwrap(),
        4
    );
    assert_eq!(
        private_int_wide(codec, Some(b"App"), None, 4, &file.wide).unwrap(),
        4
    );
}

#[test]
fn stored_profile_integers_follow_the_win16_word_contract() {
    let file = TempIni::create("integers", Some(PROFILE));
    let codec = codec();
    let read =
        |key: &[u8]| private_int_wide(codec, Some(b"App"), Some(key), 9, &file.wide).unwrap();
    assert_eq!(read(b"empty"), 0);
    assert_eq!(read(b"negative"), 0);
    assert_eq!(read(b"prefix"), 102);
    assert_eq!(read(b"word"), 40_000);
    assert_eq!(read(b"huge"), 65_535);
    assert_eq!(read(b"zero"), 0);
    assert_eq!(read(b"octal"), 10);
    assert_eq!(read(b"hex"), 0);
    assert_eq!(read(b"missing"), 9);
}

#[test]
fn string_capacity_covers_zero_one_truncation_and_the_default() {
    let file = TempIni::create("strings", Some(PROFILE));
    let codec = codec();
    let read = |capacity: u32| {
        private_string_wide(
            codec,
            Some(b"App"),
            Some(b"text"),
            Some(b"fallback"),
            &file.wide,
            capacity,
        )
        .unwrap()
    };

    let empty = read(0);
    assert_eq!(empty.copied, 0);
    assert!(empty.buffer.is_empty());

    let one = read(1);
    assert_eq!(one.copied, 0);
    assert_eq!(one.buffer, [0]);

    let clipped = read(4);
    assert_eq!(clipped.copied, 3);
    assert_eq!(&clipped.buffer[..4], b"ABC\0");

    let exact = read(7);
    assert_eq!(exact.copied, 6);
    assert_eq!(&exact.buffer[..7], b"ABCDEF\0");

    let missing = TempIni::create("string-missing", None);
    let fallback = private_string_wide(
        codec,
        Some(b"App"),
        Some(b"text"),
        Some(b"fallback"),
        &missing.wide,
        16,
    )
    .unwrap();
    assert_eq!(fallback.copied, 8);
    assert_eq!(&fallback.buffer[..9], b"fallback\0");
}

#[test]
fn null_key_lists_names_and_a_write_round_trips() {
    let file = TempIni::create("names", Some("[App]\r\nempty=1\r\ntext=ABCDEF\r\n"));
    let codec = codec();
    let names = private_string_wide(codec, Some(b"App"), None, None, &file.wide, 64).unwrap();
    assert_eq!(names.copied, 11);
    assert_eq!(&names.buffer[..12], b"empty\0text\0\0");

    let created = TempIni::create("write", None);
    assert!(
        private_write_wide(
            codec,
            Some(b"App"),
            Some(b"Count"),
            Some(b"40000"),
            &created.wide
        )
        .unwrap()
    );
    assert_eq!(
        private_int_wide(codec, Some(b"App"), Some(b"Count"), 1, &created.wide).unwrap(),
        40_000
    );
    let stored = private_string_wide(
        codec,
        Some(b"App"),
        Some(b"Count"),
        Some(b"no"),
        &created.wide,
        8,
    )
    .unwrap();
    assert_eq!(stored.copied, 5);
    assert_eq!(&stored.buffer[..6], b"40000\0");
}
