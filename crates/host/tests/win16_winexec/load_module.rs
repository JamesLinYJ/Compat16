//! Noninteractive LoadModule/FreeModule calls made by actual NE programs.

use super::{image, native::run};

fn setup(parent: Vec<u8>) -> tempfile::TempDir {
    formats::parse_ne(&parent).expect("valid NE module-loader caller");
    let root = tempfile::tempdir().unwrap();
    for directory in ["APP", "WORK/BIN"] {
        std::fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    std::fs::write(root.path().join("APP/PARENT.EXE"), parent).unwrap();
    root
}

fn verify_program(page: u32, name: &str, environment: Option<&[u8]>, tail: &[u8]) {
    let guest_name = format!("BIN\\{name}");
    let guest_name = if guest_name.is_ascii() {
        guest_name.into_bytes()
    } else {
        host_services::windows::encode(&guest_name, page).unwrap()
    };
    let root = setup(image::module_parent(image::ModuleLaunch {
        name: &guest_name,
        tail,
        show: 3,
        environment,
        expected_error: None,
    }));
    std::fs::write(
        root.path().join("WORK/BIN").join(name),
        image::child_after_release(),
    )
    .unwrap();
    run(&root.path().join("APP/PARENT.EXE"), page);
    let output = std::fs::read(root.path().join("WORK/CHILD.OUT")).unwrap();
    assert_eq!(output.len(), 54);
    assert_eq!(usize::from(output[0]), tail.len());
    assert_eq!(&output[1..1 + tail.len()], tail);
    assert_eq!(output[1 + tail.len()], 0);
    let expected = environment.unwrap_or(image::ENVIRONMENT);
    assert_eq!(&output[32..32 + expected.len()], expected);
    assert_eq!(u16::from_le_bytes([output[52], output[53]]), 3);
    assert_eq!(
        std::fs::read(root.path().join("WORK/ALIVE.OUT")).unwrap(),
        b"A"
    );
    let result = std::fs::read(root.path().join("WORK/RESULT.OUT")).unwrap();
    assert_eq!(result.len(), 4);
    assert!(u16::from_le_bytes([result[0], result[1]]) > 32);
    assert_eq!(u16::from_le_bytes([result[2], result[3]]), 1);
    let path = std::fs::read(root.path().join("WORK/MODULE.OUT")).unwrap();
    assert!(!path.is_empty());
    assert!(!path.contains(&0));
    // This is a Win16 ANSI path. The public host encode/decode helpers above
    // target DOS pages (437/936), so use Windows for the 1252/936 readback.
    use windows_sys::Win32::Globalization::{MB_ERR_INVALID_CHARS, MultiByteToWideChar};
    let length = i32::try_from(path.len()).unwrap();
    let needed = unsafe {
        MultiByteToWideChar(
            page,
            MB_ERR_INVALID_CHARS,
            path.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
        )
    };
    assert!(
        needed > 0,
        "decode ANSI module filename: {}",
        std::io::Error::last_os_error()
    );
    let mut wide = vec![0; needed as usize];
    let written = unsafe {
        MultiByteToWideChar(
            page,
            MB_ERR_INVALID_CHARS,
            path.as_ptr(),
            length,
            wide.as_mut_ptr(),
            needed,
        )
    };
    assert_eq!(written, needed);
    let path = String::from_utf16(&wide).unwrap();
    assert_eq!(
        std::path::Path::new(&path).canonicalize().unwrap(),
        root.path()
            .join("WORK/BIN")
            .join(name)
            .canonicalize()
            .unwrap()
    );
}

#[test]
fn parameter_block_preserves_raw_tail_inherited_environment_and_child_lifetime() {
    verify_program(1252, "Child App.exe", None, b"  \"a b\"  z");
}

#[test]
fn explicit_environment_is_copied_before_its_parent_allocation_is_freed() {
    verify_program(
        1252,
        "CHILD.EXE",
        Some(b"C16=child\0PATH=BIN\0\0"),
        b"  \"a b\"  z",
    );
}

#[test]
fn an_explicit_empty_environment_does_not_fall_back_to_the_parent() {
    verify_program(1252, "CHILD.EXE", Some(b"\0\0"), b"a\0b");
}

#[test]
fn dbcs_module_filename_keeps_its_exact_program_identity() {
    verify_program(936, "孩子 app.exe", None, b"  \"a b\"  z");
}

#[test]
fn dll_references_initialize_once_and_call_wep_only_after_the_final_release() {
    let root = setup(image::module_library_parent());
    std::fs::write(root.path().join("WORK/BIN/LIB.DLL"), image::library()).unwrap();
    run(&root.path().join("APP/PARENT.EXE"), 1252);
    assert_eq!(
        std::fs::read(root.path().join("WORK/INIT.OUT")).unwrap(),
        1_u16.to_le_bytes()
    );
    assert_eq!(
        std::fs::read(root.path().join("WORK/WEP.OUT")).unwrap(),
        b"W"
    );
}

#[test]
fn module_launch_failures_return_real_loader_errors() {
    for (name, expected) in [("MISSING.EXE", 2), ("BAD.EXE", 11), ("FAILAPP.EXE", 0)] {
        let root = setup(image::module_parent(image::ModuleLaunch {
            name: format!("BIN\\{name}").as_bytes(),
            tail: b"",
            show: 0,
            environment: None,
            expected_error: Some(expected),
        }));
        if name == "BAD.EXE" {
            let mut bytes = image::child();
            bytes.truncate(0x82);
            std::fs::write(root.path().join("WORK/BIN/BAD.EXE"), bytes).unwrap();
        } else if name == "FAILAPP.EXE" {
            std::fs::write(
                root.path().join("WORK/BIN/FAILAPP.EXE"),
                image::failing_app(),
            )
            .unwrap();
            std::fs::write(root.path().join("WORK/BIN/FAIL.DLL"), image::failing_dll()).unwrap();
        }
        run(&root.path().join("APP/PARENT.EXE"), 1252);
        let result = std::fs::read(root.path().join("WORK/RESULT.OUT")).unwrap();
        assert_eq!(
            u16::from_le_bytes([result[0], result[1]]),
            expected,
            "{name}"
        );
        assert!(!root.path().join("WORK/CHILD.OUT").exists());
    }
}
