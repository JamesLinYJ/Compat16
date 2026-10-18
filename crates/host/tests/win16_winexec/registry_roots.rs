//! The guest reads an owned HKCU Classes fixture through the shared HKCR view.
use super::{image, native::run_with_engine};
use std::ptr::null_mut;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, RegCloseKey, RegCreateKeyW, RegDeleteTreeW,
    RegOpenKeyW, RegSetValueW,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn absent(root: HKEY, name: &[u16]) {
    let mut key = null_mut();
    let status = unsafe { RegOpenKeyW(root, name.as_ptr(), &mut key) };
    if status == 0 {
        unsafe { RegCloseKey(key) };
    }
    assert_eq!(
        status, 2,
        "fixture must not pre-exist or remain after cleanup"
    );
}

struct Fixture {
    path: Vec<u16>,
    name: Vec<u16>,
}
impl Fixture {
    fn cleanup(&self) {
        let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr()) };
        assert_eq!(
            status, 0,
            "remove only the fixture's unique HKCU Classes child"
        );
        absent(HKEY_CURRENT_USER, &self.path);
        absent(HKEY_CLASSES_ROOT, &self.name);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr()) };
    }
}

fn verify(engine: &str) {
    let directory = tempfile::tempdir().unwrap();
    let name = format!(
        "Compat16Test.{}",
        directory.path().file_name().unwrap().to_str().unwrap()
    );
    assert!(!name.contains(['\\', '/', '\0']));
    let path = wide(&format!("Software\\Classes\\{name}"));
    let child = wide(&name);
    absent(HKEY_CURRENT_USER, &path);
    absent(HKEY_CLASSES_ROOT, &child);
    absent(HKEY_CLASSES_ROOT, &wide(&format!(".classes\\{name}")));
    // Install cleanup only after all pre-existing-key checks passed.
    let fixture = Fixture { path, name: child };
    let mut parent = null_mut();
    let status = unsafe {
        RegOpenKeyW(
            HKEY_CURRENT_USER,
            wide("Software\\Classes").as_ptr(),
            &mut parent,
        )
    };
    assert_eq!(status, 0, "shared Classes parent must already exist");
    let mut key = null_mut();
    let status = unsafe { RegCreateKeyW(parent, fixture.name.as_ptr(), &mut key) };
    let closed_parent = unsafe { RegCloseKey(parent) };
    assert_eq!(status, 0, "create only the unique HKCU fixture");
    assert_eq!(closed_parent, 0);
    let value = wide("RootText");
    let status = unsafe { RegSetValueW(key, std::ptr::null(), 1, value.as_ptr(), 0) };
    let closed = unsafe { RegCloseKey(key) };
    assert_eq!(status, 0);
    assert_eq!(closed, 0);
    let program = directory.path().join("REGROOTS.EXE");
    std::fs::write(&program, image::registry_roots_program(&name)).unwrap();
    let result = std::panic::catch_unwind(|| run_with_engine(&program, 936, engine));
    fixture.cleanup();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn registry_native_jit_keeps_legacy_roots_out_of_kernel_thunks() {
    verify("jit");
}
#[test]
fn registry_native_interpreter_keeps_legacy_roots_out_of_kernel_thunks() {
    verify("interpreter");
}
