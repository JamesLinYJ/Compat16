use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, protected: bool, page: u32) {
    let root = tempfile::tempdir().unwrap();
    let decode = |raw: &[u8]| {
        text_codec::decode(raw, text_codec::CodePage::try_from(page).unwrap()).unwrap()
    };
    let directories = if protected {
        &["INT", "GATE"][..]
    } else {
        &["INT"][..]
    };
    for name in directories {
        let dir = root.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        for (letter, contents) in [(b'A', b"one".as_slice()), (b'B', b"three")] {
            let mut raw = if page == 936 {
                b"\x81\\".to_vec()
            } else {
                vec![0x81]
            };
            raw.push(letter);
            raw.extend_from_slice(b".OLD");
            std::fs::write(dir.join(decode(&raw)), contents).unwrap();
        }
        for (name, contents) in [
            ("DEL1.TMP", "normal"),
            ("DEL2.TMP", "readonly"),
            ("COLL1.OLD", "first"),
            ("COLL2.OLD", "second"),
            ("LOCK.TMP", "locked"),
        ] {
            std::fs::write(dir.join(name), contents).unwrap();
        }
        let ro = dir.join("DEL2.TMP");
        let mut permissions = std::fs::metadata(&ro).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(ro, permissions).unwrap();
        std::fs::create_dir(dir.join("DIROLD")).unwrap();
    }
    let program = root.path().join(if protected {
        "FCBMUT.EXE"
    } else {
        "FCBMUT.COM"
    });
    std::fs::write(
        &program,
        image::fcb_mutation_program(protected, page == 936),
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| {
        run_with_dos_code_page(&program, page, engine);
        for name in directories {
            let dir = root.path().join(name);
            let first = dir.join("COLL1.OLD");
            let second = dir.join("COLL2.OLD");
            assert_ne!(first.exists(), second.exists());
            assert_eq!(
                std::fs::read(dir.join("SAME.NEW")).unwrap(),
                if first.exists() {
                    b"second".as_slice()
                } else {
                    b"first"
                }
            );
            assert_eq!(
                std::fs::read(if first.exists() { first } else { second }).unwrap(),
                if dir.join("COLL1.OLD").exists() {
                    b"first".as_slice()
                } else {
                    b"second"
                }
            );
            assert!(!dir.join("DIROLD").exists());
            assert!(dir.join("DIRNEW").is_dir());
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 3);
        }
    });
    if let Err(error) = result {
        eprintln!("retained FCB mutation fixture: {}", root.keep().display());
        std::panic::resume_unwind(error);
    }
}
#[test]
fn fcb_mutation_native_jit_real_cp437() {
    verify("jit", false, 437);
}
#[test]
fn fcb_mutation_native_interpreter_real_cp437() {
    verify("interpreter", false, 437);
}
#[test]
fn fcb_mutation_native_jit_real_cp936() {
    verify("jit", false, 936);
}
#[test]
fn fcb_mutation_native_interpreter_real_cp936() {
    verify("interpreter", false, 936);
}
#[test]
fn fcb_mutation_native_jit_protected_cp437() {
    verify("jit", true, 437);
}
#[test]
fn fcb_mutation_native_interpreter_protected_cp437() {
    verify("interpreter", true, 437);
}
#[test]
fn fcb_mutation_native_jit_protected_cp936() {
    verify("jit", true, 936);
}
#[test]
fn fcb_mutation_native_interpreter_protected_cp936() {
    verify("interpreter", true, 936);
}
