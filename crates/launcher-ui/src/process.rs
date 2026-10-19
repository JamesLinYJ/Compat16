use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;

use crate::{model::Prepared, store};

pub(crate) enum Event {
    Started {
        name: String,
        pid: u32,
        log: PathBuf,
    },
    Finished {
        name: String,
        log: PathBuf,
        result: Result<i32, String>,
        details: String,
    },
}

/// The worker owns the child and never touches a window. Closing the launcher
/// leaves already-launched applications running; the receiver can be dropped.
pub(crate) fn launch(request: Prepared, root: &Path, events: Sender<Event>) -> Result<(), String> {
    let (log, mut stderr) = store::unique_file(&root.join("logs"), "run", "log")
        .map_err(|error| format!("无法创建运行日志：{error}"))?;
    let trace = if request.diagnostics {
        let (path, file) = store::unique_file(&root.join("logs"), "trace", "txt")
            .map_err(|error| format!("无法创建诊断文件：{error}"))?;
        drop(file);
        Some(path)
    } else {
        None
    };
    if let Some(path) = &trace {
        writeln!(stderr, "诊断文件：{}", crate::model::display_path(path))
            .map_err(|error| format!("无法写入运行日志：{error}"))?;
    }
    std::thread::Builder::new()
        .name("launcher-child".into())
        .spawn(move || {
            let name = request
                .program
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let result = (|| {
                let mut command = Command::new(&request.executable);
                if let Some(trace) = trace {
                    command.arg("--trace-file").arg(trace);
                }
                // Do not use CREATE_NO_WINDOW or a valid NUL stdin handle: DOS
                // programs must still be able to allocate their own console.
                let mut child = command
                    .args(&request.arguments)
                    .current_dir(&request.directory)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::from(stderr))
                    .spawn()
                    .map_err(|error| format!("无法启动程序：{error}"))?;
                let _ = events.send(Event::Started {
                    name: name.clone(),
                    pid: child.id(),
                    log: log.clone(),
                });
                let status = child
                    .wait()
                    .map_err(|error| format!("无法读取退出状态：{error}"))?;
                Ok(status.code().unwrap_or(-1))
            })();
            let details = log_excerpt(&log);
            let _ = events.send(Event::Finished {
                name,
                log,
                result,
                details,
            });
        })
        .map(|_| ())
        .map_err(|error| format!("无法创建启动线程：{error}"))
}

fn log_excerpt(path: &Path) -> String {
    let mut bytes = Vec::new();
    if let Ok(file) = File::open(path) {
        let _ = file.take(16 * 1024).read_to_end(&mut bytes);
    }
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[cfg(all(test, windows))]
mod native_tests {
    use super::*;
    use crate::{
        model::{Request, Settings},
        test_support::Fixture,
    };
    use windows_sys::Win32::System::Console::{FreeConsole, GetStdHandle, SetStdHandle};
    struct Streams([*mut core::ffi::c_void; 2]);
    impl Drop for Streams {
        fn drop(&mut self) {
            // SAFETY: `SetStdHandle` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
                SetStdHandle((-10_i32) as u32, self.0[0]);
                SetStdHandle((-11_i32) as u32, self.0[1]);
            }
        }
    }
    #[test]
    #[ignore = "requires COMPAT16_TEST_PACKAGE_DIR; run alone to exercise detached GUI standard handles"]
    fn launcher_native_detached_dos_child_keeps_console_io_and_error_log() {
        let fixture = Fixture::new();
        let program = fixture.file("OUTPUT.COM");
        let mut image = vec![
            0xba, 0x0c, 0x01, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0, 0x4c, 0xcd, 0x21,
        ];
        image.extend(b"CONSOLE-OK$");
        std::fs::write(&program, image).unwrap();
        let installation = PathBuf::from(
            std::env::var_os("COMPAT16_TEST_PACKAGE_DIR").expect("official package required"),
        );
        let mut prepared = Request {
            program: program.to_string_lossy().into_owned(),
            arguments: String::new(),
            directory: String::new(),
            settings: Settings::default(),
        }
        .prepare(&installation)
        .unwrap();
        prepared
            .arguments
            .splice(0..0, ["--max-instructions".into(), "50000".into()]);
        let streams =
            // SAFETY: `Streams` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
            let streams = Streams([
                GetStdHandle((-10_i32) as u32),
                GetStdHandle((-11_i32) as u32),
            ]);
            FreeConsole();
            SetStdHandle((-10_i32) as u32, std::ptr::null_mut());
            SetStdHandle((-11_i32) as u32, std::ptr::null_mut());
            streams
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        launch(prepared, &fixture.0, sender).unwrap();
        let result = loop {
            match receiver
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("bounded DOS child did not finish")
            {
                Event::Finished { result, log, .. } => break (result, log),
                Event::Started { .. } => {}
            }
        };
        drop(streams);
        assert_eq!(
            result.0.unwrap(),
            0,
            "{}",
            std::fs::read_to_string(result.1).unwrap()
        );
    }
}
