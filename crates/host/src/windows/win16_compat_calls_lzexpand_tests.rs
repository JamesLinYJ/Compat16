use super::{
    OFSTRUCT_BYTES, close, copy, decode_ofstruct, encode_ofstruct, guest_wide_z, init,
    is_action_only_style, is_lz_read_style, open_file, read, seek,
};
use crate::windows::guest_text::GuestTextCodec;
use crate::windows::win16::{Win16Files, Win16NativeFile};
use runtime::{Win16HostLzInit, Win16HostLzRead};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Globalization::GetOEMCP;
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OF_CREATE, OF_DELETE, OF_EXIST, OF_PARSE, OF_READ, OF_READWRITE, OF_SHARE_DENY_NONE, OF_WRITE,
    OPEN_EXISTING,
};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[test]
fn lzopenfile_modes_preserve_plain_hfile_write_path() {
    assert!(is_lz_read_style((OF_READ | OF_SHARE_DENY_NONE) as i32));
    assert!(!is_lz_read_style(OF_WRITE as i32));
    assert!(!is_lz_read_style(OF_READWRITE as i32));
    assert!(!is_lz_read_style((OF_READ | OF_CREATE) as i32));
    assert!(!is_lz_read_style((OF_READ | OF_DELETE) as i32));
    assert!(!is_lz_read_style((OF_READ | OF_EXIST) as i32));
    assert!(!is_lz_read_style((OF_READ | OF_PARSE) as i32));
    assert!(is_action_only_style(OF_DELETE as i32));
    assert!(is_action_only_style(OF_EXIST as i32));
    assert!(is_action_only_style(OF_PARSE as i32));
}

#[test]
fn lz_paths_decode_with_the_fixed_guest_page() {
    let codec = GuestTextCodec::new(1252).expect("Windows-1252 is installed");
    let path = guest_wide_z(codec, b"C:\\apps\\caf\xe9.txt", "test path")
        .expect("convert path")
        .expect("no embedded NUL");
    assert_eq!(
        path,
        "C:\\apps\\café.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>()
    );
}

#[test]
fn malformed_utf8_lz_path_returns_guest_handle_error() {
    let codec = GuestTextCodec::new(65001).expect("UTF-8 code page is installed");
    let mut files = Win16Files::new();
    let previous = vec![0; OFSTRUCT_BYTES];
    let result = open_file(&mut files, codec, &[0xFF], OF_READ as u16, previous.clone())
        .expect("invalid guest path is a Win16 failure result");
    assert_eq!(result.result, -1);
    assert!(result.file.is_none());
    assert_eq!(result.ofstruct, previous);
}

#[test]
fn ofstruct_reopen_path_uses_oem_field_and_guest_page_on_return() {
    let codec = GuestTextCodec::new(1252).expect("Windows-1252 is installed");
    let mut guest = vec![0_u8; OFSTRUCT_BYTES];
    guest[0] = 0x80;
    guest[1] = 1;
    guest[2..4].copy_from_slice(&0x1234_u16.to_le_bytes());
    guest[4..6].copy_from_slice(&0x5678_u16.to_le_bytes());
    guest[6..8].copy_from_slice(&0x9abc_u16.to_le_bytes());
    guest[8..8 + b"C:\\TEMP\\FILE.DAT".len()].copy_from_slice(b"C:\\TEMP\\FILE.DAT");

    let native = decode_ofstruct(&guest, codec, true).expect("decode OFSTRUCT");
    let native_path: Vec<u8> = native.szPathName.iter().map(|byte| *byte as u8).collect();
    assert_eq!(
        &native_path[..b"C:\\TEMP\\FILE.DAT".len()],
        b"C:\\TEMP\\FILE.DAT"
    );

    let mut returned = vec![0xA5_u8; OFSTRUCT_BYTES];
    encode_ofstruct(codec, &native, &mut returned).expect("encode OFSTRUCT");
    assert_eq!(&returned[..8], &guest[..8]);
    assert_eq!(
        &returned[8..8 + b"C:\\TEMP\\FILE.DAT".len()],
        b"C:\\TEMP\\FILE.DAT"
    );
    assert_eq!(returned[8 + b"C:\\TEMP\\FILE.DAT".len()], 0);
}

#[test]
fn ofstruct_reopen_transcodes_guest_path_through_oem_field() {
    let codec = GuestTextCodec::new(1252).expect("Windows-1252 is installed");
    let guest_path = b"C:\\TEMP\\caf\xe9.dat";
    let wide = codec.to_wide(guest_path).expect("decode guest path");
    let oem_codec =
        GuestTextCodec::new(unsafe { GetOEMCP() }).expect("Windows reports a valid OEM code page");
    let expected = oem_codec
        .from_wide_bounded(&wide, 127)
        .expect("encode OEM OFSTRUCT path");
    let mut guest = vec![0_u8; OFSTRUCT_BYTES];
    guest[8..8 + guest_path.len()].copy_from_slice(guest_path);

    let decoded = decode_ofstruct(&guest, codec, true);
    if expected.truncated || expected.used_default_char == Some(true) {
        assert!(
            decoded.is_err(),
            "unrepresentable guest pathname must not be replaced in OEM OFSTRUCT"
        );
        return;
    }
    let native = decoded.expect("guest path fits the OEM OFSTRUCT field");
    let native_path: Vec<u8> = native.szPathName.iter().map(|byte| *byte as u8).collect();
    assert_eq!(
        &native_path[..expected.bytes.len()],
        expected.bytes.as_slice()
    );

    let mut returned = vec![0_u8; OFSTRUCT_BYTES];
    encode_ofstruct(codec, &native, &mut returned).expect("return path to guest page");
    assert_eq!(&returned[8..8 + guest_path.len()], guest_path);
}

#[test]
fn createfile_handles_bridge_through_lzinit_copy_and_close() {
    const SZDD: &[u8] = &[
        b'S', b'Z', b'D', b'D', 0x88, 0xf0, 0x27, 0x33, b'A', b'x', 4, 0, 0, 0, 0x0f, b'D', b'A',
        b'T', b'A',
    ];
    let cases: [(&str, &[u8], &[u8]); 2] = [
        (
            "ordinary",
            b"plain CreateFileW input",
            b"plain CreateFileW input",
        ),
        ("szdd", SZDD, b"DATA"),
    ];
    let mut cleanup = TemporaryPaths(Vec::new());

    for (label, source_bytes, expected) in cases {
        let id = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("lz-file-{label}-{}-{id}", std::process::id());
        let source_path = std::env::temp_dir().join(format!("{prefix}-source.bin"));
        let destination_path = std::env::temp_dir().join(format!("{prefix}-copy.bin"));
        std::fs::write(&source_path, source_bytes).expect("write temporary LZ source");
        cleanup
            .0
            .extend([source_path.clone(), destination_path.clone()]);

        let mut files = Win16Files::new();
        let source_handle = open_native(&source_path, GENERIC_READ, OPEN_EXISTING);
        let source = files
            .retain_native(Win16NativeFile::NativeHandle(source_handle))
            .expect("retain source HANDLE")
            .expect("source token");
        let destination_handle = open_native(
            &destination_path,
            GENERIC_READ | GENERIC_WRITE,
            CREATE_ALWAYS,
        );
        let destination = files
            .retain_native(Win16NativeFile::NativeHandle(destination_handle))
            .expect("retain destination HANDLE")
            .expect("destination token");

        let stream = match init(&mut files, source, true).expect("LZInit bridge") {
            Win16HostLzInit::File(stream) => stream,
            Win16HostLzInit::Error(error) => panic!("LZInit failed with {error}"),
        };
        let source_closed = close(&mut files, source).expect("close original source HANDLE");
        assert!(source_closed.closed);
        assert_eq!(source_closed.consumed_source, None);

        let prefix = match read(&files, stream, 3)
            .expect("read duplicated LZ source")
            .expect("LZ source read result")
        {
            Win16HostLzRead::Bytes(bytes) => bytes,
            Win16HostLzRead::Error(error) => panic!("duplicated LZ read failed with {error}"),
        };
        assert_eq!(prefix.as_slice(), &expected[..3]);
        assert_eq!(
            seek(&files, stream, 0, 0).expect("seek duplicated LZ source"),
            Some(0)
        );

        let copied = copy(&files, stream, destination)
            .expect("LZCopy bridge")
            .expect("native copy result");
        assert!(copied >= 0, "LZCopy failed with {copied}");
        let copied_bytes = std::fs::read(&destination_path).expect("read copied file");
        assert_eq!(copied_bytes.as_slice(), expected);

        let closed = close(&mut files, stream).expect("close LZ stream");
        assert!(closed.closed);
        assert_eq!(closed.consumed_source, None);
        assert!(
            close(&mut files, destination)
                .expect("close destination")
                .closed
        );
    }
}

fn open_native(path: &Path, access: u32, disposition: u32) -> HANDLE {
    let path_z: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: `path_z` is an owned NUL-terminated UTF-16 path and the API
    // returns a new owned file HANDLE for the requested access.
    let handle = unsafe {
        CreateFileW(
            path_z.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    assert!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "CreateFileW failed for a temporary LZ test file"
    );
    handle
}

struct TemporaryPaths(Vec<PathBuf>);

impl Drop for TemporaryPaths {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}
