use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use build_tools::{compile_catalog, manifest::load_catalog};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let base = std::env::temp_dir();
        loop {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("compat16-build-tools-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../abi")
}

fn command(name: &str, root: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_build-tools"))
        .arg(name).arg("--catalog").arg(root).args(arguments)
        .output().expect("run build-tools")
}

fn succeeded(output: &Output) {
    assert!(output.status.success(), "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
fn inspect_and_audit_accept_shared_module_aliases() {
    let root = root();
    let catalog = load_catalog(&root).unwrap();
    let module = catalog.module("KERNEL").unwrap();
    let output = command("inspect", &root, &["--module", &module.source_module]);
    succeeded(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("module \"KERNEL\""));
    assert!(text.contains("declaration_evidence="));
    assert!(text.contains("binding="));
    let output = command("audit-win16", &root, &["--module", &module.source_module]);
    succeeded(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Manifest/compiled ABI consistency only"));
    assert!(text.contains("differences=0"));
}

#[test]
fn generate_uses_the_shared_generator_for_both_fragments() {
    let directory = TestDirectory::new();
    let root = root();
    let generated = compile_catalog(&load_catalog(&root).unwrap());
    let output = Command::new(env!("CARGO_BIN_EXE_build-tools"))
        .arg("generate").arg("--catalog").arg(&root)
        .arg("--output").arg(directory.0.join("generated"))
        .output().expect("run generator");
    succeeded(&output);
    assert_eq!(fs::read_to_string(directory.0.join("generated/win16_exports.rs")).unwrap(), generated.metadata);
    assert_eq!(fs::read_to_string(directory.0.join("generated/win16_bindings.rs")).unwrap(), generated.bindings);
}

#[test]
fn invalid_catalog_never_creates_generated_output() {
    let directory = TestDirectory::new();
    fs::write(directory.0.join("catalog.toml"), r#"
version = 999
modules = []
name_resolutions = []
groups = []
types = []
"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_build-tools"))
        .arg("generate").arg("--catalog").arg(&directory.0)
        .arg("--output").arg(directory.0.join("generated"))
        .output().expect("run generator");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported schema version"));
    assert!(!directory.0.join("generated").exists());
}

#[test]
fn removed_spec_arguments_and_unknown_modules_fail_closed() {
    for arguments in [vec!["--spec", "legacy.spec"], vec!["--module", "MISSING_MODULE"]] {
        let output = command("audit-win16", &root(), &arguments);
        assert!(!output.status.success());
    }
    let output = command("inspect", &root(), &["--output", "unused"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inspect does not accept --output"));
    let output = command("generate", &root(), &["--module", "KERNEL", "--output", "unused"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not accept --module"));
}
