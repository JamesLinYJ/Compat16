use std::{env, fs, path::PathBuf};

#[path = "../../build-support/windows_resources.rs"]
mod windows_resources;

const WINDOWS_APIS: &str = include_str!("windows_api_bindings.txt");
const WINDOWS_COM_INTERFACES: &str = include_str!("windows_com_bindings.txt");

fn main() {
    windows_resources::link_resources(&["compat16host"]);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=windows_api_bindings.txt");
    println!("cargo:rerun-if-changed=windows_com_bindings.txt");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");

    let target_os = env::var("CARGO_CFG_TARGET_OS")
        .expect("Cargo must set CARGO_CFG_TARGET_OS for the host build script");
    if target_os != "windows" {
        return;
    }

    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR for the host build script"),
    );
    let output = out_dir.join("host_windows_bindings.rs");
    let output_path = output
        .to_str()
        .expect("Cargo OUT_DIR must be Unicode for the generated Rust module path");

    let mut arguments = vec![
        "--out".to_owned(),
        output_path.to_owned(),
        "--flat".to_owned(),
        "--sys".to_owned(),
    ];
    for api in WINDOWS_APIS.lines().map(str::trim) {
        if !api.is_empty() && !api.starts_with('#') {
            arguments.push("--filter".to_owned());
            arguments.push(api.to_owned());
        }
    }

    // With no custom input, windows-bindgen uses its bundled Windows metadata.
    // Keep its output in an external module source so generator-owned module
    // attributes have a valid boundary. Emit a small bridge item with a
    // Rust-escaped absolute path; do not rewrite or strip the generated text.
    windows_bindgen::bindgen(arguments);

    let bridge = out_dir.join("host_windows_bindings_module.rs");
    let module_path = format!("{output_path:?}");
    let bridge_source = format!(
        "#[path = {module_path}]\nmod generated;\npub(super) use generated::*;\n"
    );
    fs::write(&bridge, bridge_source)
        .expect("write the host Windows bindings module bridge");

    // The sys bindings expose API functions and data, but no callable COM
    // interface wrappers or callback implementation traits. Generate those
    // from the same official metadata, avoiding handwritten vtable layouts.
    let com_output = out_dir.join("host_com_bindings.rs");
    let com_path = com_output.to_str()
        .expect("Cargo OUT_DIR must be Unicode for COM bindings");
    let mut com_arguments = vec![
        "--out".to_owned(), com_path.to_owned(), "--flat".to_owned(),
        "--implement".to_owned(), "Windows.Win32.IOleClientSite".to_owned(),
        "Windows.Win32.IAdviseSink".to_owned(),
    ];
    for interface in WINDOWS_COM_INTERFACES.lines().map(str::trim) {
        if !interface.is_empty() && !interface.starts_with('#') {
            com_arguments.push("--filter".to_owned());
            com_arguments.push(interface.to_owned());
        }
    }
    windows_bindgen::bindgen(com_arguments);
    let com_bridge = format!(
        "#[path = {com_path:?}]\npub(super) mod generated;\n"
    );
    fs::write(out_dir.join("host_com_bindings_module.rs"), com_bridge)
        .expect("write the host COM bindings module bridge");
}
