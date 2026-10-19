use super::*;
use crate::test_support::Fixture;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled;

struct HiddenWindow(HWND);
impl Drop for HiddenWindow {
    fn drop(&mut self) {
        unsafe {
            DestroyWindow(self.0);
        }
    }
}

fn state(fixture: &Fixture) -> (HiddenWindow, State) {
    let window = unsafe {
        CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            wide("UI contract test").as_ptr(),
            WS_POPUP,
            0,
            0,
            640,
            492,
            null_mut(),
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        )
    };
    assert!(!window.is_null());
    let window = HiddenWindow(window);
    let settings = Settings::default();
    let fonts = controls::Fonts::new(96).unwrap();
    let controls = controls::Controls::new(window.0, &fonts, &settings).unwrap();
    let (sender, events) = mpsc::channel();
    let state = State {
        window: window.0,
        controls,
        fonts,
        settings,
        root: fixture.directory("profile"),
        installation: fixture.0.clone(),
        events,
        sender,
        advanced: false,
        error: false,
        running: 0,
        log: None,
        dpi: 96,
        scroll: 0,
        logs: Default::default(),
    };
    (window, state)
}

#[test]
fn native_controls_validate_then_report_spawn_failure_without_closing() {
    let fixture = Fixture::new();
    let (window, mut state) = state(&fixture);
    state.command(controls::RUN, BN_CLICKED as u16);
    assert!(state.error);
    assert!(text(state.controls.status).contains("请选择"));
    assert_eq!(state.running, 0);
    assert!(!state.root.join("launcher.json").exists());

    let program = fixture.file("guest.com");
    for name in ["compat16w.exe", "compat16.dll", "compat16host.exe"] {
        fixture.file(name);
    }
    set_text(state.controls.program, &display_path(&program));
    state.command(controls::RUN, BN_CLICKED as u16);
    assert_eq!(state.running, 1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state.running != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
        state.poll();
    }
    assert_eq!(state.running, 0);
    assert!(state.error);
    assert!(text(state.controls.status).contains("无法启动程序"));
    assert!(state.log.as_ref().unwrap().is_file());
    assert!(unsafe { IsWindowEnabled(state.controls.log) } != 0);
    assert!(unsafe { IsWindow(window.0) } != 0);
    // Controls must be destroyed before their font handles are released.
    drop(window);
    drop(state);
}

#[test]
fn advanced_native_controls_round_trip_settings_and_dpi_layout() {
    let fixture = Fixture::new();
    let (window, mut state) = state(&fixture);
    state.command(controls::ADVANCED, BN_CLICKED as u16);
    assert!(state.advanced);
    unsafe {
        SendMessageW(state.controls.engine, CB_SETCURSEL, 2, 0);
        SendMessageW(state.controls.dos, CB_SETCURSEL, 1, 0);
        SendMessageW(state.controls.diagnostics, BM_SETCHECK, 1, 0);
    }
    set_text(state.controls.ansi, "932");
    set_text(state.controls.version, "6.22");
    let settings = state.current_settings().unwrap();
    assert!(settings.engine == crate::model::Engine::Interpreter);
    assert_eq!(settings.ansi_page, Some(932));
    assert_eq!(settings.dos_page, 936);
    assert_eq!(settings.dos_version, "6.22");
    assert!(settings.diagnostics);
    for dpi in [96, 144, 192] {
        let fonts = controls::Fonts::new(dpi).unwrap();
        state.controls.fonts(&fonts);
        state.fonts = fonts;
        state.dpi = dpi;
        state.layout(true);
        let mut client = RECT::default();
        assert_ne!(unsafe { GetClientRect(window.0, &mut client) }, 0);
        assert!(client.right > 0);
        assert!(client.bottom > 0);
        state.scroll(SB_BOTTOM, 0);
        assert!(state.scroll >= 0);
    }
    state.command(controls::ADVANCED, BN_CLICKED as u16);
    assert!(!state.advanced);
    drop(window);
    drop(state);
}

#[test]
fn embedded_log_keeps_recent_output_and_is_read_only() {
    let fixture = Fixture::new();
    let (window, state) = state(&fixture);
    state.append_log(&"日志 test\n".repeat(20_000));
    state.append_log("LAST-LOG-LINE\r\n");
    let contents = text(state.controls.log_view);
    assert!(contents.ends_with("LAST-LOG-LINE\r\n"));
    assert!(contents.encode_utf16().count() <= 64 * 1024);
    assert_ne!(
        unsafe { GetWindowLongW(state.controls.log_view, GWL_STYLE) } & ES_READONLY,
        0
    );
    drop(window);
    drop(state);
}
