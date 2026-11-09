use super::process_is_running;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

#[test]
fn shell_process_liveness_uses_the_process_object_even_for_exit_code_259() {
    let shell = std::env::var_os("ComSpec").expect("native command processor");
    let mut child = Command::new(&shell)
        .args(["/d", "/c", "exit /b 259"])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(259));
    assert!(!process_is_running(&child).unwrap());

    // The child waits on its own input pipe, without keyboard or GUI input.
    let mut child = Command::new(&shell)
        .args(["/d", "/q", "/c", "set /p compat16_wait="])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let running = process_is_running(&child);
    drop(child.stdin.take());
    child.wait().unwrap();
    assert!(running.unwrap());
}
