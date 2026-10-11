use std::process::Command;

#[test]
fn user_queries_command_writes_the_deterministic_ne_fixture() {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("compat16-user-queries-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    let _cleanup = Cleanup(directory.clone());
    let path = directory.join("QUERIES.EXE");
    let result = Command::new(env!("CARGO_BIN_EXE_build-tools"))
        .args(["win16-user-queries-probe", "--output"]).arg(&path).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(std::fs::read(path).unwrap(), build_tools::win16_user_queries_probe_bytes().unwrap());
}

#[test]
fn user_queries_command_requires_output_and_is_listed_in_help() {
    let executable = env!("CARGO_BIN_EXE_build-tools");
    let missing = Command::new(executable).arg("win16-user-queries-probe").output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("win16-user-queries-probe requires --output"));
    let help = Command::new(executable).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("win16-user-queries-probe --output FILE"));
}
