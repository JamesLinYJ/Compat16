use super::{image, native::run_with_input};
use std::{
    fs::{File, OpenOptions},
    process::Stdio,
};

const BYTES: &[u8] = b"A\0BC\r\n";

enum Input {
    Null,
    EmptyFile,
    DataFile,
    WriteOnlyNull,
}

fn verify(engine: &str, input: Input) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("STDIN.COM");
    let (stream, expected) = match input {
        Input::Null => (Stdio::null(), Ok(&[][..])),
        Input::EmptyFile | Input::DataFile => {
            let bytes = if matches!(input, Input::EmptyFile) {
                &[][..]
            } else {
                BYTES
            };
            let path = root.path().join("INPUT.DAT");
            std::fs::write(&path, bytes).unwrap();
            (Stdio::from(File::open(&path).unwrap()), Ok(bytes))
        }
        Input::WriteOnlyNull => (
            Stdio::from(OpenOptions::new().write(true).open("NUL").unwrap()),
            Err(5),
        ),
    };
    std::fs::write(&program, image::stdin_com(expected)).unwrap();
    run_with_input(&program, 437, engine, stream);
}

#[test]
fn stdin_native_jit_null_eof() {
    verify("jit", Input::Null);
}
#[test]
fn stdin_native_interpreter_null_eof() {
    verify("interpreter", Input::Null);
}
#[test]
fn stdin_native_jit_empty_file_eof() {
    verify("jit", Input::EmptyFile);
}
#[test]
fn stdin_native_interpreter_empty_file_eof() {
    verify("interpreter", Input::EmptyFile);
}
#[test]
fn stdin_native_jit_file_preserves_nul_and_bytes() {
    verify("jit", Input::DataFile);
}
#[test]
fn stdin_native_interpreter_file_preserves_nul_and_bytes() {
    verify("interpreter", Input::DataFile);
}
#[test]
fn stdin_native_jit_write_only_null_returns_access_denied() {
    verify("jit", Input::WriteOnlyNull);
}
#[test]
fn stdin_native_interpreter_write_only_null_returns_access_denied() {
    verify("interpreter", Input::WriteOnlyNull);
}
