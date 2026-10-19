//! Only unique, preflighted HKCU Classes fixtures are modified by these tests.
use super::{image, native::run_with_engine};
use sha2::{Digest, Sha256};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Globalization::MultiByteToWideChar;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, RegCloseKey, RegCreateKeyW, RegDeleteTreeW,
    RegEnumKeyExW, RegOpenKeyW, RegQueryValueW, RegSetValueW,
};

const UNICODE: &str = "\u{6}Compat16🧪";
const NESTED: &str = "Nested🚀";

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

fn absent(root: HKEY, name: &[u16]) {
    let mut key = null_mut();
    // SAFETY: RegOpenKeyW reads a caller-owned subkey name and writes a caller-owned HKEY.
    let status =
        // SAFETY: this HKEY is owned by the guard and is closed only here.
        unsafe { RegOpenKeyW(root, name.as_ptr(), &mut key) };
    if status == 0 {
        // SAFETY: this HKEY is owned by the guard and is closed only here.
        unsafe { RegCloseKey(key) };
    }
    assert_eq!(status, 2, "fixture key must be absent");
}

struct Fixture {
    path: Vec<u16>,
    name: Vec<u16>,
}
impl Fixture {
    fn cleanup(&self) {
        // SAFETY: RegDeleteTreeW reads a caller-owned subkey name, or null for the key itself.
        let status =
            // SAFETY: `RegDeleteTreeW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr()) };
        assert_eq!(
            status, 0,
            "remove only this fixture's unique HKCU Classes child"
        );
        absent(HKEY_CURRENT_USER, &self.path);
        absent(HKEY_CLASSES_ROOT, &self.name);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: RegDeleteTreeW reads a caller-owned subkey name, or null for the key itself.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr()) };
    }
}

fn create(root: HKEY, name: &str, value: &str) -> Key {
    let mut key = null_mut();
    assert_eq!(
        // SAFETY: `RegCreateKeyW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { RegCreateKeyW(root, wide(name).as_ptr(), &mut key) },
        0
    );
    let key = Key(key);
    assert_eq!(
        // SAFETY: `RegSetValueW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { RegSetValueW(key.0, null(), 1, wide(value).as_ptr(), 0) },
        0
    );
    key
}

fn children(root: HKEY) -> Vec<Vec<u16>> {
    let mut result = Vec::new();
    for index in 0..16 {
        let mut name = [0_u16; 256];
        let mut length = name.len() as u32;
        // SAFETY: RegEnumKeyExW writes into caller-owned name buffers of the capacities passed with them.
        let status =
            // SAFETY: `RegEnumKeyExW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
            RegEnumKeyExW(
                root,
                index,
                name.as_mut_ptr(),
                &mut length,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status == 259 {
            return result;
        }
        assert_eq!(status, 0);
        result.push(name[..length as usize].to_vec());
    }
    panic!("unexpected number of fixture children");
}

fn value(root: HKEY, name: &[u16]) -> String {
    let mut path = name.to_vec();
    path.push(0);
    let mut output = [0_u16; 64];
    let mut count = std::mem::size_of_val(&output) as i32;
    assert_eq!(
        // SAFETY: `RegQueryValueW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { RegQueryValueW(root, path.as_ptr(), output.as_mut_ptr(), &mut count) },
        0
    );
    assert!(count > 0 && count % 2 == 0);
    String::from_utf16(&output[..count as usize / 2 - 1]).unwrap()
}

fn verify(engine: &str, module: u16) {
    let directory = tempfile::tempdir().unwrap();
    let name = format!(
        "Compat16Test.{}",
        directory.path().file_name().unwrap().to_str().unwrap()
    );
    assert!(!name.contains(['\\', '/', '\0']));
    let path = wide(&format!("Software\\Classes\\{name}"));
    absent(HKEY_CURRENT_USER, &path);
    absent(HKEY_CLASSES_ROOT, &wide(&name));
    let fixture = Fixture {
        path,
        name: wide(&name),
    };
    let mut parent = null_mut();
    assert_eq!(
        // SAFETY: RegOpenKeyW reads a caller-owned subkey name and writes a caller-owned HKEY.
        unsafe {
            RegOpenKeyW(
                HKEY_CURRENT_USER,
                wide("Software\\Classes").as_ptr(),
                &mut parent,
            )
        },
        0
    );
    let parent = Key(parent);
    let key = create(parent.0, &name, "Fixture");
    let unicode = create(key.0, UNICODE, "Unicode");
    // A GBK trail byte of 0x5c belongs to this character, not a separator.
    let mut dbcs_wide = [0_u16; 2];
    assert_eq!(
        // SAFETY: MultiByteToWideChar reads a caller-owned byte span and writes a caller-owned UTF-16 buffer.
        unsafe { MultiByteToWideChar(936, 0, b"\x81\x5c".as_ptr(), 2, dbcs_wide.as_mut_ptr(), 2) },
        1
    );
    assert_ne!(dbcs_wide[0], 0x5c);
    let dbcs_name = String::from_utf16(&dbcs_wide[..1]).unwrap();
    let dbcs = create(unicode.0, &dbcs_name, "Dbcs");
    drop(create(dbcs.0, NESTED, "Nested"));
    // This real, representable key spells the token of the Unicode sibling.
    // Enumerating it must yield its own alias and preserve both identities.
    let mut digest = Sha256::new();
    digest.update(b"Compat16.RegistryName.v1\0");
    for unit in UNICODE.encode_utf16() {
        digest.update(unit.to_le_bytes());
    }
    let token = format!(
        "~C16~{}",
        digest.finalize()[..16]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    );
    let literal = create(key.0, &token, "Literal");
    drop(create(literal.0, "Other", "Other"));
    drop(literal);
    let before = children(key.0);
    assert_eq!(before.len(), 2);
    let unicode_name: Vec<_> = UNICODE.encode_utf16().collect();
    let unicode_index = before
        .iter()
        .position(|name| name == &unicode_name)
        .unwrap();
    let values: Vec<_> = before.iter().map(|name| value(key.0, name)).collect();
    let program = directory.path().join("REGALIAS.EXE");
    std::fs::write(
        &program,
        image::registry_aliases_program(
            &name,
            module,
            [values[0].as_bytes(), values[1].as_bytes()],
            unicode_index,
        ),
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| {
        run_with_engine(&program, 936, engine);
        // Native inspection proves guest writes reached the original keys,
        // and that alias paths did not create extra physical registry keys.
        for (index, name) in before.iter().enumerate() {
            assert_eq!(value(key.0, name), format!("Updated{index}"));
        }
        assert_eq!(children(key.0).len(), 2);
        assert_eq!(children(unicode.0), vec![dbcs_wide[..1].to_vec()]);
        assert!(
            children(dbcs.0).is_empty(),
            "guest deleted the original nested Unicode key"
        );
        absent(key.0, &wide("~C16~00000000000000000000000000000000"));
        absent(dbcs.0, &wide(NESTED));
    });
    drop(dbcs);
    drop(unicode);
    drop(key);
    drop(parent);
    fixture.cleanup();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn registry_native_jit_shell_round_trips_unicode_aliases() {
    verify("jit", 2);
}
#[test]
fn registry_native_interpreter_shell_round_trips_unicode_aliases() {
    verify("interpreter", 2);
}
#[test]
fn registry_native_jit_kernel_round_trips_unicode_aliases() {
    verify("jit", 1);
}
#[test]
fn registry_native_interpreter_kernel_round_trips_unicode_aliases() {
    verify("interpreter", 1);
}
