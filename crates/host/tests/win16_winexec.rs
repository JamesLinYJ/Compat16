//! Real NE programs run through a complete native package; no GUI input.

#[path = "win16_winexec/image.rs"]
mod image;

#[cfg(windows)]
#[path = "win16_winexec/dos_message.rs"]
mod dos_message;

#[cfg(windows)]
#[path = "win16_winexec/dos_version.rs"]
mod dos_version;

#[cfg(windows)]
#[path = "win16_winexec/fcb_parse.rs"]
mod fcb_parse;

#[cfg(windows)]
#[path = "win16_winexec/fcb_search.rs"]
mod fcb_search;
#[cfg(windows)]
#[path = "win16_winexec/fcb_mutation.rs"]
mod fcb_mutation;
#[cfg(windows)]
#[path = "win16_winexec/canonical_name.rs"]
mod canonical_name;

#[cfg(windows)]
#[path = "win16_winexec/extended_error.rs"]
mod extended_error;

#[cfg(windows)]
#[path = "win16_winexec/extended_open.rs"]
mod extended_open;

#[cfg(windows)]
#[path = "win16_winexec/stdin.rs"]
mod stdin;

#[cfg(windows)]
#[path = "win16_winexec/dbcs.rs"]
mod dbcs;

#[cfg(windows)]
#[path = "win16_winexec/country.rs"]
mod country;

#[cfg(windows)]
#[path = "win16_winexec/registry_expand.rs"]
mod registry_expand;

#[cfg(windows)]
#[path = "win16_winexec/registry_cursor.rs"]
mod registry_cursor;

#[cfg(windows)]
#[path = "win16_winexec/registry_aliases.rs"]
mod registry_aliases;

#[cfg(windows)]
#[path = "win16_winexec/child_dialog.rs"]
mod child_dialog;

#[cfg(windows)]
#[path = "win16_winexec/dialog_init.rs"]
mod dialog_init;

#[cfg(windows)]
#[path = "win16_winexec/registry.rs"]
mod registry;

#[cfg(windows)]
#[path = "win16_winexec/registry_roots.rs"]
mod registry_roots;

#[cfg(windows)]
#[path = "win16_winexec/oem_bitmap.rs"]
mod oem_bitmap;

#[cfg(windows)]
#[path = "win16_winexec/current_directory.rs"]
mod current_directory;

#[cfg(windows)]
#[path = "win16_winexec/launch_options.rs"]
mod launch_options;

#[cfg(windows)]
#[path = "win16_winexec/load_module.rs"]
mod load_module;

#[cfg(windows)]
#[path = "win16_winexec/global_notify.rs"]
mod global_notify;

#[cfg(windows)]
#[path = "win16_winexec/dialog_icon.rs"]
mod dialog_icon;

#[cfg(windows)]
#[path = "win16_winexec/printer.rs"]
mod printer;

#[test]
fn fixtures_have_checked_ne_imports_segments_and_library_entry() {
    for bytes in [
        image::parent(b"BIN\\CHILD.EXE", None),
        image::native_parent(b"NATIVE.EXE --help"),
        image::parent_with_show(b"BIN\\CHILD.EXE", 3),
        image::child(),
        image::failing_app(),
        image::failing_dll(),
        image::module_parent(image::ModuleLaunch {
            name: b"BIN\\CHILD.EXE",
            tail: b"  \"a b\"  z",
            show: 3,
            environment: Some(image::ENVIRONMENT),
            expected_error: None,
        }),
        image::module_library_parent(),
        image::library(),
        image::child_after_release(),
        image::global_notify_program(),
        image::named_dialog_icon_program(),
        image::named_class_dialog_icon_program(),
        image::default_printer_round_trip_program(),
        image::ext_device_mode_round_trip_program(),
        image::current_directory_program(),
        image::oem_bitmap_program(),
        image::registry_program("Compat16Test.fixture"),
        image::registry_query_program("Compat16Test.fixture"),
        image::registry_buffer_program("Compat16Test.fixture"),
        image::registry_optional_length_program("Compat16Test.fixture"),
        image::registry_roots_program("Compat16Test.fixture"),
        image::child_dialog_program(),
        image::extended_error_program(),
    ] {
        let module = formats::parse_ne(&bytes).expect("valid fixed-layout NE input");
        assert_eq!(module.header.target_os, 2);
        assert_eq!(module.segments.len(), 2);
        assert_eq!(module.header.initial_cs, 1);
    }
    let dll = formats::parse_ne(&image::failing_dll()).unwrap();
    assert_ne!(dll.header.flags & 0x8000, 0);
}

#[cfg(windows)]
mod native {
    use super::image;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct Running(Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub(super) fn run(program: &Path, page: u32) {
        run_with_engine(program, page, "jit");
    }

    pub(super) fn run_with_engine(program: &Path, page: u32, engine: &str) {
        run_with_input(program, page, engine, Stdio::null());
    }

    pub(super) fn run_with_input(program: &Path, page: u32, engine: &str, input: Stdio) {
        run_with_pages(program, page, 437, engine, input);
    }

    pub(super) fn run_with_dos_code_page(program: &Path, page: u32, engine: &str) {
        run_with_pages(program, page, page, engine, Stdio::null());
    }

    fn run_with_pages(program: &Path, page: u32, dos_page: u32, engine: &str, input: Stdio) {
        run_configured(program, page, dos_page, engine, input, None);
    }

    pub(super) fn run_with_dos_version(program: &Path, page: u32, engine: &str, version: &str) {
        run_configured(program, page, 437, engine, Stdio::null(), Some(version));
    }

    fn run_configured(program: &Path, page: u32, dos_page: u32, engine: &str, input: Stdio, version: Option<&str>) {
        run_configured_with_options(program, page, dos_page, engine, input, version, &[]);
    }

    pub(super) fn run_with_launch_options(program: &Path, page: u32, engine: &str, tail: &str, directory: &Path) {
        run_configured_with_options(program, page, 437, engine, Stdio::null(), None, &[
            "--command-tail".into(), tail.into(), "--working-directory".into(), directory.as_os_str().to_os_string(),
        ]);
    }

    fn run_configured_with_options(program: &Path, page: u32, dos_page: u32, engine: &str, input: Stdio,
        version: Option<&str>, launch_options: &[std::ffi::OsString]) {
        let package = PathBuf::from(
            std::env::var_os("COMPAT16_TEST_PACKAGE_DIR")
                .expect("set COMPAT16_TEST_PACKAGE_DIR to the matching scripts/build.ps1 package"),
        );
        for file in [
            "compat16.exe",
            "compat16w.exe",
            "compat16.dll",
            "compat16host.exe",
        ] {
            assert!(
                package.join(file).is_file(),
                "incomplete native package: {file}"
            );
        }
        let trace = program.with_extension("io.log");
        let mut running = Running(
            Command::new(package.join("compat16.exe"))
                .args([
                    "--cpu-engine",
                    engine,
                    "--no-jit-cache",
                    "--max-instructions",
                    "100000",
                    "--code-page",
                    &dos_page.to_string(),
                    "--win16-code-page",
                    &page.to_string(),
                ])
                .args(version.into_iter().flat_map(|version| ["--dos-version", version]))
                .arg("--trace-win16-io-complete")
                .arg(&trace)
                .args(launch_options)
                .arg(program)
                .stdin(input)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start actual Compat16 launcher"),
        );
        let deadline = Instant::now() + Duration::from_secs(45);
        let status = loop {
            if let Some(status) = running.0.try_wait().expect("poll native parent") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "WinExec parent did not finish within 45 seconds"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        use std::io::Read;
        let mut stderr = String::new();
        running
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            status.success(),
            "parent status {status}: {stderr}\n{}",
            std::fs::read_to_string(trace).unwrap_or_default()
        );
    }

    fn setup(command: &[u8], expected_error: Option<u16>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for directory in ["APP", "WORK/BIN"] {
            std::fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        let parent = image::parent(command, expected_error);
        formats::parse_ne(&parent).expect("valid parent NE fixture");
        std::fs::write(root.path().join("APP/PARENT.EXE"), parent).unwrap();
        root
    }

    fn verify_inheritance(page: u32, name: &str, command: &str, show: u16) {
        let command = if command.is_ascii() {
            command.as_bytes().to_vec()
        } else {
            host_services::windows::encode(command, page).unwrap()
        };
        let root = setup(&command, None);
        std::fs::write(
            root.path().join("APP/PARENT.EXE"),
            image::parent_with_show(&command, show),
        )
        .unwrap();
        let child = image::child();
        formats::parse_ne(&child).expect("valid child NE fixture");
        std::fs::write(root.path().join("WORK/BIN").join(name), child).unwrap();
        run(&root.path().join("APP/PARENT.EXE"), page);
        // The image lives in BIN; its relative output must use the parent's
        // changed task cwd, independent of the image and native launcher dirs.
        let output = std::fs::read(root.path().join("WORK/CHILD.OUT")).unwrap();
        let tail = b"\"a b\"  z";
        assert_eq!(output.len(), 54);
        assert_eq!(output[0] as usize, tail.len());
        assert_eq!(&output[1..1 + tail.len()], tail);
        assert_eq!(output[1 + tail.len()], 0); // InitTask converts the original CR to NUL.
        assert_eq!(&output[32..52], image::ENVIRONMENT);
        assert_eq!(u16::from_le_bytes([output[52], output[53]]), show);
        assert!(!root.path().join("WORK/BIN/CHILD.OUT").exists());
        let value = std::fs::read(root.path().join("WORK/RESULT.OUT")).unwrap();
        assert!(u16::from_le_bytes(value.try_into().unwrap()) > 31);
    }

    #[test]
    fn quoted_child_preserves_task_directory_environment_and_raw_tail() {
        verify_inheritance(
            1252,
            "Child App.exe",
            "\"BIN\\Child App.exe\" \"a b\"  z",
            0,
        );
    }

    #[test]
    fn dbcs_child_filename_preserves_original_argument_bytes() {
        verify_inheritance(936, "孩子 app.exe", "\"BIN\\孩子 app.exe\" \"a b\"  z", 0);
    }

    #[test]
    fn executable_search_uses_the_guest_environment_path() {
        verify_inheritance(1252, "CHILD.EXE", "CHILD.EXE \"a b\"  z", 0);
    }

    #[test]
    fn show_command_reaches_the_guest_init_task_result() {
        verify_inheritance(1252, "CHILD.EXE", "BIN\\CHILD.EXE \"a b\"  z", 3);
    }

    #[test]
    fn native_pe_executable_keeps_the_windows_process_path() {
        let package = PathBuf::from(std::env::var_os("COMPAT16_TEST_PACKAGE_DIR").unwrap());
        let command = format!("\"{}\" --help", package.join("compat16.exe").display());
        assert!(
            command.is_ascii(),
            "native fixture command must be ANSI representable"
        );
        let root = setup(command.as_bytes(), None);
        std::fs::write(
            root.path().join("APP/PARENT.EXE"),
            image::native_parent(command.as_bytes()),
        )
        .unwrap();
        run(&root.path().join("APP/PARENT.EXE"), 1252);
        let value = std::fs::read(root.path().join("WORK/RESULT.OUT")).unwrap();
        assert!(u16::from_le_bytes(value.try_into().unwrap()) > 31);
    }

    #[test]
    fn failures_reach_the_parent_before_any_success_receipt() {
        for (name, expected) in [
            ("MISSING.EXE", 2),
            ("BAD.EXE", 11),
            ("FAILAPP.EXE", 0),
            ("NUL", 11),
        ] {
            let root = setup(format!("BIN\\{name}").as_bytes(), Some(expected));
            if name == "BAD.EXE" {
                let mut malformed = image::child();
                malformed.truncate(0x82);
                assert!(formats::parse_ne(&malformed).is_err());
                std::fs::write(root.path().join("WORK/BIN/BAD.EXE"), malformed).unwrap();
            } else if name == "FAILAPP.EXE" {
                let app = image::failing_app();
                let dll = image::failing_dll();
                formats::parse_ne(&app).unwrap();
                formats::parse_ne(&dll).unwrap();
                std::fs::write(root.path().join("WORK/BIN/FAILAPP.EXE"), app).unwrap();
                std::fs::write(root.path().join("WORK/BIN/FAIL.DLL"), dll).unwrap();
            }
            run(&root.path().join("APP/PARENT.EXE"), 1252);
            let value = std::fs::read(root.path().join("WORK/RESULT.OUT")).unwrap();
            assert_eq!(
                u16::from_le_bytes(value.try_into().unwrap()),
                expected,
                "{name}"
            );
            assert!(!root.path().join("WORK/CHILD.OUT").exists(), "{name}");
        }
    }
}
