//! A unique HKCU Classes child reproduces backward scanning of the merged root.
use super::{image, native::run_with_engine};
use sha2::{Digest, Sha256};
use std::ptr::{null, null_mut};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, RegCloseKey, RegCreateKeyW, RegDeleteTreeW,
    RegEnumKeyExW, RegOpenKeyW, RegQueryValueW, RegSetValueW,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
struct Fixture {
    path: Vec<u16>,
    name: Vec<u16>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr()) };
    }
}
fn absent(root: HKEY, path: &[u16]) {
    let mut key = null_mut();
    let status = unsafe { RegOpenKeyW(root, path.as_ptr(), &mut key) };
    if status == 0 {
        unsafe { RegCloseKey(key) };
    }
    assert_eq!(status, 2, "unique fixture must be absent");
}

fn index_of(name: &[u16]) -> u32 {
    let mut found = None;
    let mut index = 0_u32;
    loop {
        let mut buffer = [0_u16; 256];
        let mut length = buffer.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                HKEY_CLASSES_ROOT,
                index,
                buffer.as_mut_ptr(),
                &mut length,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status == 259 {
            break;
        }
        assert_eq!(status, 0);
        if &buffer[..length as usize] == name {
            assert!(found.replace(index).is_none());
        }
        index = index.checked_add(1).unwrap();
    }
    // Drain the enumeration even after finding the fixture. The harness must
    // not leave its own native thread positioned before a backward seek.
    found.expect("HKCU fixture must be visible through the actual merged HKCR")
}

fn verify(engine: &str, module: u16) {
    let directory = tempfile::tempdir().unwrap();
    // This unrepresentable component sorts late without modifying any
    // pre-existing key. Its unique suffix and both roots are preflighted.
    let name = format!(
        "\u{ffff}Compat16Test.{}",
        directory.path().file_name().unwrap().to_str().unwrap()
    );
    let path = wide(&format!("Software\\Classes\\{name}"));
    let native_name = wide(&name);
    absent(HKEY_CURRENT_USER, &path);
    absent(HKEY_CLASSES_ROOT, &native_name);
    let fixture = Fixture {
        path,
        name: native_name,
    };
    let mut native = null_mut();
    assert_eq!(
        unsafe { RegCreateKeyW(HKEY_CURRENT_USER, fixture.path.as_ptr(), &mut native) },
        0
    );
    let native = Key(native);
    assert_eq!(
        unsafe { RegSetValueW(native.0, null(), 1, wide("Cursor").as_ptr(), 0) },
        0
    );
    let index = index_of(&fixture.name[..fixture.name.len() - 1]);
    let mut digest = Sha256::new();
    digest.update(b"Compat16.RegistryName.v1\0");
    for unit in &fixture.name[..fixture.name.len() - 1] {
        digest.update(unit.to_le_bytes());
    }
    let token = format!(
        "~C16~{}",
        digest.finalize()[..16]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    );
    let program = directory.path().join("REGCURSOR.EXE");
    std::fs::write(
        &program,
        image::registry_cursor_program(module, index, &token),
    )
    .unwrap();
    run_with_engine(&program, 936, engine);
    let mut value = [0_u16; 16];
    let mut count = std::mem::size_of_val(&value) as i32;
    assert_eq!(
        unsafe { RegQueryValueW(native.0, null(), value.as_mut_ptr(), &mut count) },
        0
    );
    assert_eq!(&value[..count as usize / 2], wide("Cursor"));
    drop(native);
    assert_eq!(
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, fixture.path.as_ptr()) },
        0
    );
    absent(HKEY_CURRENT_USER, &fixture.path);
    absent(HKEY_CLASSES_ROOT, &fixture.name);
}

#[test]
fn registry_native_jit_shell_preserves_root_cursor() {
    verify("jit", 2);
}
#[test]
fn registry_native_interpreter_shell_preserves_root_cursor() {
    verify("interpreter", 2);
}
#[test]
fn registry_native_jit_kernel_preserves_root_cursor() {
    verify("jit", 1);
}
#[test]
fn registry_native_interpreter_kernel_preserves_root_cursor() {
    verify("interpreter", 1);
}
