//! Modify only a unique, preflighted HKCU child; verify stored type/data survive.
use super::{image, native::run_with_engine};
use std::ptr::{null, null_mut};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, RegCloseKey, RegCreateKeyW, RegDeleteTreeW, RegOpenKeyW,
    RegQueryValueExW, RegQueryValueW, RegSetValueExW,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this HKEY is owned by the guard and is closed only here.
        unsafe { RegCloseKey(self.0) };
    }
}
struct Fixture(Vec<u16>);
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: RegDeleteTreeW reads a caller-owned subkey name, or null for the key itself.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.0.as_ptr()) };
    }
}
fn absent(name: &[u16]) {
    let mut key = null_mut();
    // SAFETY: RegOpenKeyW reads a caller-owned subkey name and writes a caller-owned HKEY.
    let status =
        // SAFETY: this HKEY is owned by the guard and is closed only here.
        unsafe { RegOpenKeyW(HKEY_CURRENT_USER, name.as_ptr(), &mut key) };
    if status == 0 {
        // SAFETY: this HKEY is owned by the guard and is closed only here.
        unsafe { RegCloseKey(key) };
    }
    assert_eq!(status, 2, "unique test key must be absent");
}
fn open(parent: HKEY, name: &str, create: bool) -> Key {
    let mut key = null_mut();
    let name = wide(name);
    // SAFETY: `RegCreateKeyW`, `RegOpenKeyW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let status =
        // SAFETY: `RegCreateKeyW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
        if create {
            RegCreateKeyW(parent, name.as_ptr(), &mut key)
        } else {
            RegOpenKeyW(parent, name.as_ptr(), &mut key)
        }
    };
    assert_eq!(status, 0);
    Key(key)
}
fn verify(engine: &str, module: u16) {
    let directory = tempfile::tempdir().unwrap();
    let path = format!(
        "Compat16Test.{}",
        directory.path().file_name().unwrap().to_str().unwrap()
    );
    assert!(!path.contains(['\\', '/', '\0']));
    let name = wide(&path);
    absent(&name);
    let fixture = Fixture(name);
    let parent = open(HKEY_CURRENT_USER, &path, true);
    let text = "前%SystemRoot%\\尾%Compat16MissingVariable%";
    let values = [
        ("Expand", 2, text, true),
        ("Empty", 2, "", false),
        ("NoExplicitNul", 2, "前", false),
        ("Plain", 1, "Keep", true),
        ("Binary", 3, "Binary", true),
    ];
    let mut originals = Vec::new();
    for (name, kind, text, terminated) in values {
        let key = open(parent.0, name, true);
        let mut units = text.encode_utf16().collect::<Vec<_>>();
        if terminated {
            units.push(0);
        }
        let bytes = units
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            // SAFETY: RegSetValueExW reads a caller-owned value that stays live for the call.
            unsafe { RegSetValueExW(key.0, null(), 0, kind, bytes.as_ptr(), bytes.len() as u32) },
            0
        );
        if kind == 2 {
            let mut count = 0;
            assert_eq!(
                // SAFETY: `RegQueryValueW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                unsafe { RegQueryValueW(key.0, null(), null_mut(), &mut count) },
                13
            );
        }
        // RegSetValueExW may add a terminator to a nonempty string even when
        // the supplied count omitted it. Compare the actual stored bytes.
        let mut stored = vec![0; bytes.len() + 2];
        let mut stored_count = stored.len() as u32;
        let mut stored_kind = 0;
        assert_eq!(
            // SAFETY: RegQueryValueExW writes into caller-owned buffers of the capacities passed with them.
            unsafe {
                RegQueryValueExW(
                    key.0,
                    null(),
                    null(),
                    &mut stored_kind,
                    stored.as_mut_ptr(),
                    &mut stored_count,
                )
            },
            0
        );
        assert_eq!(stored_kind, kind);
        stored.truncate(stored_count as usize);
        originals.push((name, kind, stored));
    }
    drop(open(parent.0, "Absent", true));
    drop(parent);
    let program = directory.path().join("REGEXPAND.EXE");
    std::fs::write(&program, image::registry_expand_program(&path, module)).unwrap();
    run_with_engine(&program, 936, engine);
    let parent = open(HKEY_CURRENT_USER, &path, false);
    for (name, kind, original) in originals {
        let key = open(parent.0, name, false);
        let mut actual = vec![0; original.len() + 2];
        let mut count = actual.len() as u32;
        let mut actual_kind = 0;
        assert_eq!(
            // SAFETY: RegQueryValueExW writes into caller-owned buffers of the capacities passed with them.
            unsafe {
                RegQueryValueExW(
                    key.0,
                    null(),
                    null(),
                    &mut actual_kind,
                    actual.as_mut_ptr(),
                    &mut count,
                )
            },
            0
        );
        actual.truncate(count as usize);
        assert_eq!((actual_kind, actual), (kind, original));
    }
    drop(parent);
    assert_eq!(
        // SAFETY: RegDeleteTreeW reads a caller-owned subkey name, or null for the key itself.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, fixture.0.as_ptr()) },
        0
    );
    absent(&fixture.0);
}
#[test]
fn registry_native_jit_shell_reads_expandable_text() {
    verify("jit", 2);
}
#[test]
fn registry_native_interpreter_shell_reads_expandable_text() {
    verify("interpreter", 2);
}
#[test]
fn registry_native_jit_kernel_preserves_expandable_type_error() {
    verify("jit", 1);
}
#[test]
fn registry_native_interpreter_kernel_preserves_expandable_type_error() {
    verify("interpreter", 1);
}
