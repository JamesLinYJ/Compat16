use std::{env, error::Error, path::PathBuf, process::Command};

pub fn link_resources(binaries: &[&str]) {
    let target = env::var("TARGET").expect("Cargo must set TARGET for the build script");
    if !target.contains("windows") || !target.ends_with("-msvc") {
        return;
    }

    let file_type = if binaries.is_empty() { "0x2L" } else { "0x1L" };
    let resource = compile_resource(file_type)
        .unwrap_or_else(|error| panic!("compile Compat16 Windows resources: {error}"));
    if binaries.is_empty() {
        println!("cargo:rustc-link-arg-cdylib={}", resource.display());
    } else {
        for binary in binaries {
            println!("cargo:rustc-link-arg-bin={binary}={}", resource.display());
        }
    }
}

fn compile_resource(file_type: &str) -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")
        .ok_or("Cargo did not set CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .ok_or("crate manifest directory is outside the workspace")?;
    let assets = workspace_root.join("assets");
    let resource_script = assets.join("runtime.rc");
    let icon = assets.join("icon.ico");
    println!("cargo:rerun-if-changed={}", resource_script.display());
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", assets.join("launcher.manifest").display());
    if !resource_script.is_file() {
        return Err(format!("resource script is missing: {}", resource_script.display()).into());
    }
    if !icon.is_file() {
        return Err(format!("application icon is missing: {}", icon.display()).into());
    }

    let output_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo did not set OUT_DIR")?);
    let resource = output_dir.join("compat16_windows_resources.res");
    let output = Command::new("rc.exe")
        .current_dir(&assets)
        .arg("/nologo")
        .arg(format!("/dCOMPAT16_FILETYPE={file_type}"))
        .arg("/fo")
        .arg(&resource)
        .arg("runtime.rc")
        .output()?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "rc.exe exited with {}\n{}{}",
            output.status,
            stdout,
            stderr
        )
        .into());
    }
    Ok(resource)
}
