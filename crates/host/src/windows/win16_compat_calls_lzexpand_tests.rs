use super::{
    close, copy, init, is_action_only_style, is_lz_read_style, read, seek,
};
use crate::windows::guest_text::GuestTextCodec;
use crate::windows::win16::{Win16Files, Win16NativeFile};
use runtime::{Win16HostLzInit, Win16HostLzRead};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
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
    let path = codec.to_wide_z(b"C:\\apps\\caf\xe9.txt")
        .expect("convert path");
    assert_eq!(
        path,
        "C:\\apps\\café.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>()
    );
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
