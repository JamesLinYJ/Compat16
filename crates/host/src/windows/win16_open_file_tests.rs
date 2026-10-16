//! Native OpenFile timestamp and temporary-handle ownership checks.

use super::*;
use std::fs::{File, FileTimes, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, FILETIME};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

const SEED_SECONDS: u64 = 1_087_302_896;
// WINDOWS.H names 0x0400 OF_SEARCH; reopening uses its OF_VERIFY meaning.
const OF_SEARCH: u16 = OF_VERIFY;

/// These native timestamp fixtures predate the typed pathname boundary.
/// Prepare its task-resolved capability input before invoking the host; file
/// opening, timestamp verification and handle ownership still run in production.
fn open(
    files: &mut Win16Files, codec: GuestTextCodec, path: &[u8],
    style: u16, ofstruct: Vec<u8>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    let path = if style & OF_REOPEN != 0 {
        let saved = &ofstruct[8..];
        let Some(end) = saved.iter().position(|&byte| byte == 0).filter(|&end| end != 0)
            else { return Ok(failed(ofstruct, ERROR_INVALID_NAME)); };
        &saved[..end]
    } else { path };
    let wide = codec.to_wide_z(path)?;
    let text = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
    let mut filesystem = fixture_filesystem();
    let mut owner = runtime::Win16KernelFileSystemState::new();
    let id = guest_core::OwnerId(1);
    owner.seed_owner(id, runtime::Win16CanonicalPath {
        drive: filesystem.drive,
        components: filesystem.current_directory.components().map(|part|
            part.as_os_str().to_str().unwrap().to_owned()).collect(),
    })?;
    // Native fixture filenames identify real files, independently of virtual
    // DOS aliases; the timestamp tests do not assert the alias codec.
    let guest_path = owner.resolve_kernel_path_text(id, &text, false)?;
    let search = (style & 0x9100 == 0 && !text.contains(['\\', '/', ':']))
        .then_some(text.as_str());
    super::open(&mut filesystem, files, codec, &guest_path, search, style, ofstruct)
}

fn fixture_filesystem() -> crate::filesystem::Filesystem {
    crate::filesystem::Filesystem::new_native_directory(&std::env::temp_dir(), 65001).unwrap()
}

struct TestFile(PathBuf);

impl TestFile {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("c16of-{}-{stamp:x}-{id}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let result = Self(directory.join("STAMP.DAT"));
        std::fs::write(&result.0, b"original file bytes").unwrap();
        let file = OpenOptions::new().write(true).open(&result.0).unwrap();
        file.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(SEED_SECONDS)))
            .unwrap();
        drop(file);
        result
    }

    fn path(&self) -> Vec<u8> { self.0.to_str().unwrap().as_bytes().to_vec() }

    fn snapshot(&self, files: &mut Win16Files) -> Vec<u8> {
        let opened = open(files, codec(), &self.path(), 0, vec![0xcc; OFSTRUCT_BYTES]).unwrap();
        assert_eq!(opened.result, 0);
        assert!(files.close(opened.file.unwrap()).unwrap().closed);
        opened.ofstruct
    }

    fn assert_unowned(&self) {
        // A leaked temporary native handle (including read/share-compatible
        // handles) would prevent a new exclusively shared open.
        let file = OpenOptions::new().read(true).write(true).share_mode(0).open(&self.0).unwrap();
        drop(file);
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn codec() -> GuestTextCodec { GuestTextCodec::new(65001).unwrap() }

fn expected_stamp() -> [u8; 4] {
    // This oracle checks the OFSTRUCT field order under the existing DOS
    // conversion policy, not equivalence to historical WOW rounding/DST.
    let ticks = 116_444_736_000_000_000 + SEED_SECONDS * 10_000_000;
    let (time, date) = crate::filesystem::dos_write_time_from_ticks(ticks).unwrap();
    let mut bytes = [0; 4];
    bytes[..2].copy_from_slice(&date.to_le_bytes());
    bytes[2..].copy_from_slice(&time.to_le_bytes());
    bytes
}

#[test]
fn open_file_initial_open_captures_dos_date_then_time() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let saved = file.snapshot(&mut files);
    assert_eq!(&saved[4..8], &expected_stamp());
    assert_eq!(&saved[2..4], &[0, 0]);
    assert_eq!(saved.len(), OFSTRUCT_BYTES);
    file.assert_unowned();
}

#[test]
fn open_file_search_without_reopen_does_not_verify_uninitialized_stamp() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let opened = open(&mut files, codec(), &file.path(), OF_SEARCH, vec![0xff; OFSTRUCT_BYTES]).unwrap();
    assert_eq!(opened.result, 0);
    assert_eq!(&opened.ofstruct[4..8], &expected_stamp());
    assert!(files.close(opened.file.unwrap()).unwrap().closed);
}

#[test]
fn open_file_verified_reopen_preserves_saved_header_and_path() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let mut saved = file.snapshot(&mut files);
    saved[..4].copy_from_slice(&[0x35, 0xa7, 0x34, 0x12]);
    let opened = open(&mut files, codec(), b"ignored filename", OF_REOPEN | OF_VERIFY, saved.clone()).unwrap();
    assert_eq!(opened.result, 0);
    assert_eq!(opened.ofstruct, saved);
    assert!(files.close(opened.file.unwrap()).unwrap().closed);
    file.assert_unowned();
}

#[test]
fn open_file_verify_checks_date_and_time_independently_without_refresh() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let original = file.snapshot(&mut files);
    for offset in [4, 6] {
        let mut saved = original.clone();
        saved[offset] ^= 1;
        saved[2..4].copy_from_slice(&0x1234_u16.to_le_bytes());
        let opened = open(&mut files, codec(), b"", OF_REOPEN | OF_VERIFY, saved.clone()).unwrap();
        assert_eq!(opened.result, -1);
        assert!(opened.file.is_none());
        saved[2..4].fill(0);
        assert_eq!(opened.ofstruct, saved);
        assert_eq!(std::fs::read(&file.0).unwrap(), b"original file bytes");
        file.assert_unowned();
    }
}

#[test]
fn open_file_unverified_reopen_refreshes_only_the_timestamp() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let mut saved = file.snapshot(&mut files);
    saved[4..8].fill(0xee);
    saved[2..4].copy_from_slice(&0x1234_u16.to_le_bytes());
    let opened = open(&mut files, codec(), b"", OF_REOPEN, saved.clone()).unwrap();
    saved[4..8].copy_from_slice(&expected_stamp());
    assert_eq!(opened.ofstruct, saved);
    assert!(files.close(opened.file.unwrap()).unwrap().closed);
}

#[test]
fn open_file_exist_captures_and_verifies_without_retaining_a_handle() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let initial = open(&mut files, codec(), &file.path(), OF_EXIST, vec![0xcc; OFSTRUCT_BYTES]).unwrap();
    assert_eq!(initial.result, 1);
    assert!(initial.file.is_none());
    assert_eq!(&initial.ofstruct[4..8], &expected_stamp());
    file.assert_unowned();
    let matched = open(&mut files, codec(), b"", OF_REOPEN | OF_VERIFY | OF_EXIST, initial.ofstruct.clone()).unwrap();
    assert_eq!(matched.result, 1);
    assert!(matched.file.is_none());
    file.assert_unowned();
    let mut stale = initial.ofstruct;
    stale[6] ^= 1;
    let failed = open(&mut files, codec(), b"", OF_REOPEN | OF_VERIFY | OF_EXIST, stale).unwrap();
    assert_eq!(failed.result, -1);
    assert!(failed.file.is_none());
    file.assert_unowned();
}

#[test]
fn open_file_verified_delete_checks_before_removing_the_file() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let saved = file.snapshot(&mut files);
    let mut stale = saved.clone();
    stale[4] ^= 1;
    let failed = open(&mut files, codec(), b"", OF_REOPEN | OF_VERIFY | OF_DELETE, stale.clone()).unwrap();
    assert_eq!(failed.result, -1);
    assert!(failed.file.is_none());
    assert_eq!(failed.ofstruct, stale);
    assert_eq!(std::fs::read(&file.0).unwrap(), b"original file bytes");
    file.assert_unowned();
    let removed = open(&mut files, codec(), b"", OF_REOPEN | OF_VERIFY | OF_DELETE, saved).unwrap();
    assert_eq!(removed.result, 0); // Existing non-owning adapter success value.
    assert!(removed.file.is_none());
    assert!(!file.0.exists());
}

#[test]
fn open_file_create_precedes_verify_and_can_truncate_before_mismatch() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let mut saved = file.snapshot(&mut files);
    // An impossible packed date guarantees mismatch regardless of when the
    // native filesystem publishes the truncate's last-write-time update.
    saved[4..6].copy_from_slice(&0xffff_u16.to_le_bytes());
    let failed = open(&mut files, codec(), b"", OF_REOPEN | OF_CREATE | OF_VERIFY, saved.clone()).unwrap();
    assert_eq!(failed.result, -1);
    assert!(failed.file.is_none());
    assert_eq!(failed.ofstruct, saved);
    assert_eq!(std::fs::metadata(&file.0).unwrap().len(), 0);
    file.assert_unowned();
}

#[test]
fn open_file_reopen_precedes_parse_but_initial_parse_does_not_open() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let parsed = open(&mut files, codec(), &file.path(), OF_PARSE, vec![0xcc; OFSTRUCT_BYTES]).unwrap();
    assert_eq!(parsed.result, 0);
    assert!(parsed.file.is_none());
    assert_eq!(&parsed.ofstruct[4..8], &[0xcc; 4]);
    let saved = file.snapshot(&mut files);
    let reopened = open(&mut files, codec(), b"", OF_REOPEN | OF_PARSE | OF_VERIFY, saved.clone()).unwrap();
    assert!(files.close(reopened.file.unwrap()).unwrap().closed);
    let mut stale = saved;
    stale[6] ^= 1;
    let failed = open(&mut files, codec(), b"", OF_REOPEN | OF_PARSE | OF_VERIFY, stale).unwrap();
    assert_eq!(failed.result, -1);
    assert!(failed.file.is_none());
}

#[test]
fn open_file_reopen_rejects_empty_and_unterminated_paths_boundedly() {
    let mut files = Win16Files::new();
    for path_fill in [0, b'x'] {
        let mut saved = vec![0xcc; OFSTRUCT_BYTES];
        saved[8..].fill(path_fill);
        let failed = open(&mut files, codec(), b"NUL", OF_REOPEN | OF_VERIFY, saved.clone()).unwrap();
        assert_eq!(failed.result, -1);
        assert!(failed.file.is_none());
        saved[2..4].copy_from_slice(&(ERROR_INVALID_NAME as u16).to_le_bytes());
        assert_eq!(failed.ofstruct, saved);
    }
}

#[test]
fn open_file_reopen_open_failure_preserves_timestamp_and_does_not_search() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let mut saved = file.snapshot(&mut files);
    std::fs::remove_file(&file.0).unwrap();
    let failed = open(&mut files, codec(), b"NUL", OF_REOPEN | OF_VERIFY, saved.clone()).unwrap();
    assert_eq!(failed.result, -1);
    assert!(failed.file.is_none());
    saved[2..4].copy_from_slice(&(ERROR_FILE_NOT_FOUND as u16).to_le_bytes());
    assert_eq!(failed.ofstruct, saved);
}

#[test]
fn open_file_timestamp_query_keeps_write_only_and_exclusive_open_contracts() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    for access in [0, 1, 2] {
        let opened = open(&mut files, codec(), &file.path(), 0x10 | access, vec![0; OFSTRUCT_BYTES]).unwrap();
        assert_eq!(opened.result, 0);
        assert_eq!(&opened.ofstruct[4..8], &expected_stamp());
        assert!(File::open(&file.0).is_err()); // Original exclusive handle remains live.
        assert!(files.close(opened.file.unwrap()).unwrap().closed);
        file.assert_unowned();
    }
}

#[test]
fn open_file_timestamp_failure_closes_temporary_handle_before_delete() {
    let file = TestFile::new();
    let mut files = Win16Files::new();
    let mut saved = file.snapshot(&mut files);
    let handle: OwnedHandle = OpenOptions::new().read(true).share_mode(0).open(&file.0).unwrap().into();
    let mut filesystem = fixture_filesystem();
    let canonical = std::fs::canonicalize(&file.0).unwrap();
    let path = canonical.strip_prefix(&filesystem.canonical_root).unwrap();
    let failed = finish_open(&mut filesystem, &mut files, path, OF_REOPEN | OF_VERIFY | OF_DELETE,
        saved.clone(), handle, GENERIC_READ, Err(ERROR_ACCESS_DENIED)).unwrap();
    assert_eq!(failed.result, -1);
    assert!(failed.file.is_none());
    saved[2..4].copy_from_slice(&(ERROR_ACCESS_DENIED as u16).to_le_bytes());
    assert_eq!(failed.ofstruct, saved);
    assert_eq!(std::fs::read(&file.0).unwrap(), b"original file bytes");
    file.assert_unowned();
}

#[test]
fn open_file_character_device_uses_current_dos_time_and_stays_openable() {
    let mut files = Win16Files::new();
    let before = current_stamp();
    let opened = open(&mut files, codec(), b"NUL", 0, vec![0; OFSTRUCT_BYTES]).unwrap();
    let after = current_stamp();
    assert_eq!(opened.result, 0);
    let observed = u32::from(u16::from_le_bytes(opened.ofstruct[4..6].try_into().unwrap())) << 16
        | u32::from(u16::from_le_bytes(opened.ofstruct[6..8].try_into().unwrap()));
    assert!([before >> 16, after >> 16].contains(&(observed >> 16)));
    let time = observed as u16;
    assert!(time >> 11 < 24 && (time >> 5) & 63 < 60 && time & 31 < 30);
    // Local time can move backward at a DST transition or clock correction.
    // Only assert ordering when the sampled endpoints themselves are ordered.
    if before <= after { assert!(before <= observed && observed <= after); }
    assert!(files.close(opened.file.unwrap()).unwrap().closed);
    let reopened = open(&mut files, codec(), b"", OF_REOPEN, opened.ofstruct).unwrap();
    assert_eq!(reopened.result, 0);
    assert!(files.close(reopened.file.unwrap()).unwrap().closed);
}

fn current_stamp() -> u32 {
    let mut now = FILETIME::default();
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    let ticks = (u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime);
    let (time, date) = crate::filesystem::dos_write_time_from_ticks(ticks).unwrap();
    (u32::from(date) << 16) | u32::from(time)
}
