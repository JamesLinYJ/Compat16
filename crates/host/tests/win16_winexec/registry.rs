use super::{image, native::run_with_engine};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, RegCloseKey, RegDeleteTreeW, RegOpenKeyW,
};

struct TestKey(Vec<u16>);
impl TestKey {
    fn assert_absent(&self) {
        let mut opened = std::ptr::null_mut();
        let status = unsafe { RegOpenKeyW(HKEY_CURRENT_USER, self.0.as_ptr(), &mut opened) };
        if status == 0 {
            unsafe { RegCloseKey(opened) };
        }
        assert_eq!(status, 2, "unique fixture key must be absent");
    }
    fn cleanup(&self) {
        let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.0.as_ptr()) };
        assert!(status == 0 || status == 2, "fixture key cleanup: {status}");
        self.assert_absent();
    }
}
impl Drop for TestKey {
    fn drop(&mut self) {
        // Only this fixture's unique direct child of HKCU can be removed.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.0.as_ptr()) };
    }
}
fn verify(engine: &str) {
    let root = tempfile::tempdir().unwrap();
    let path = format!(
        "Compat16Test.{}",
        root.path().file_name().unwrap().to_str().unwrap()
    );
    assert!(!path.contains(['\\', '/', '\0']));
    // Check before installing the cleanup guard; never delete a pre-existing key.
    let wide: Vec<_> = path.encode_utf16().chain([0]).collect();
    let mut opened = std::ptr::null_mut();
    let status = unsafe { RegOpenKeyW(HKEY_CURRENT_USER, wide.as_ptr(), &mut opened) };
    if status == 0 {
        unsafe { RegCloseKey(opened) };
    }
    assert_eq!(status, 2, "fixture key already exists or cannot be checked");
    let cleanup = TestKey(wide);
    let program = root.path().join("REGTEXT.EXE");
    std::fs::write(&program, image::registry_program(&path)).unwrap();
    run_with_engine(&program, 936, engine);
    cleanup.cleanup();
}
#[test]
fn registry_native_jit_preserves_strings_and_win31_statuses() {
    verify("jit");
}
#[test]
fn registry_native_interpreter_preserves_strings_and_win31_statuses() {
    verify("interpreter");
}
