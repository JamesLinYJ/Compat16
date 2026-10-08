use super::path::{
    encode_exact_guest_path, standard_path_from_extended, win16_main_module_path,
};
use crate::windows::guest_text::GuestTextCodec;
use std::path::Path;

#[test]
fn startup_module_path_uses_the_executable_guest_code_page() {
    let codec = GuestTextCodec::new(1252).expect("Windows-1252 is installed");
    let path = win16_main_module_path(Path::new("C:\\Apps\\café.exe"), codec)
        .expect("encode startup path");
    assert_eq!(path, b"C:\\Apps\\caf\xe9.exe");
}

#[test]
fn startup_module_path_rejects_default_character_replacement() {
    let codec = GuestTextCodec::new(1252).expect("Windows-1252 is installed");
    let path: Vec<u16> = "C:\\中文\\app.exe".encode_utf16().collect();
    let error = encode_exact_guest_path(codec, &path)
        .expect_err("unrepresentable path must not become question marks");
    assert_eq!(error.kind(), runtime::DiagnosticKind::InvalidInput);
}

#[test]
fn extended_drive_path_normalization_preserves_suffix() {
    let extended: Vec<u16> = "\\\\?\\C:\\apps\\module.dll".encode_utf16().collect();
    let normalized = standard_path_from_extended(&extended)
        .expect("normalize extended drive path")
        .expect("supported drive prefix");
    assert_eq!(
        String::from_utf16(&normalized).expect("valid path units"),
        "C:\\apps\\module.dll"
    );
}

#[test]
fn extended_unc_path_normalization_preserves_server_and_share() {
    let extended: Vec<u16> = "\\\\?\\UNC\\server\\share\\module.dll"
        .encode_utf16()
        .collect();
    let normalized = standard_path_from_extended(&extended)
        .expect("normalize extended UNC path")
        .expect("supported UNC prefix");
    assert_eq!(
        String::from_utf16(&normalized).expect("valid path units"),
        "\\\\server\\share\\module.dll"
    );
}
