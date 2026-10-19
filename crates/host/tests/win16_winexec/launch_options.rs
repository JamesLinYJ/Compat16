//! Execute the public CLI contract and inspect bytes written by actual guests.
use super::{image, native::run_with_launch_options};

fn verify(engine: &str, win16: bool) {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("APP");
    let work = root.path().join("WORK");
    std::fs::create_dir(&app).unwrap();
    std::fs::create_dir(&work).unwrap();
    let program = app.join(if win16 { "TAIL.EXE" } else { "TAIL.COM" });
    std::fs::write(
        &program,
        if win16 {
            image::child()
        } else {
            image::command_tail_com()
        },
    )
    .unwrap();
    let tail = " /A  \"café\" \"\" ";
    run_with_launch_options(&program, 1252, engine, tail, &work);
    assert!(
        !app.join("CHILD.OUT").exists(),
        "program directory incorrectly replaced explicit cwd"
    );
    let output = std::fs::read(work.join("CHILD.OUT")).unwrap();
    let expected = if win16 {
        b"  /A  \"caf\xe9\" \"\" ".as_slice()
    } else {
        b"  /A  \"caf\x82\" \"\" ".as_slice()
    };
    assert_eq!(usize::from(output[0]), expected.len());
    assert_eq!(
        &output[1..1 + expected.len()],
        expected,
        "quotes, spaces or ANSI/OEM encoding changed"
    );
}

#[test]
fn launcher_native_jit_win16_ansi_tail_and_explicit_directory() {
    verify("jit", true);
}
#[test]
fn launcher_native_interpreter_win16_ansi_tail_and_explicit_directory() {
    verify("interpreter", true);
}
#[test]
fn launcher_native_jit_dos_oem_tail_and_explicit_directory() {
    verify("jit", false);
}
#[test]
fn launcher_native_interpreter_dos_oem_tail_and_explicit_directory() {
    verify("interpreter", false);
}
