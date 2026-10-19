use super::*;
use crate::{
    model::{Engine, Request},
    process,
};
use windows_sys::Win32::UI::Controls::Dialogs::*;

impl State {
    pub fn command(&mut self, id: u16, notification: u16) {
        match id {
            controls::RUN if notification == BN_CLICKED as u16 => self.launch(),
            controls::CLOSE => unsafe {
                PostMessageW(self.window, WM_CLOSE, 0, 0);
            },
            controls::ADVANCED if notification == BN_CLICKED as u16 => {
                self.advanced = !self.advanced;
                set_text(
                    self.controls.advanced,
                    if self.advanced {
                        "高级设置  ▴"
                    } else {
                        "高级设置  ▾"
                    },
                );
                self.layout(true);
            }
            controls::BROWSE if notification == BN_CLICKED as u16 => {
                match browse_program(self.window) {
                    Ok(Some(path)) => self.select_program(path),
                    Err(error) => self.status(&error, true),
                    _ => {}
                }
            }
            controls::DIRECTORY_BROWSE if notification == BN_CLICKED as u16 => {
                if let Some(path) = browse_directory(self.window) {
                    set_text(self.controls.directory, &display_path(&path));
                }
            }
            controls::LOG if notification == BN_CLICKED as u16 => {
                if let Some(log) = &self.log {
                    let result = unsafe {
                        ShellExecuteW(
                            self.window,
                            wide("open").as_ptr(),
                            wide(log.as_os_str()).as_ptr(),
                            null(),
                            null(),
                            SW_SHOWNORMAL,
                        )
                    } as isize;
                    if result <= 32 {
                        self.status(&format!("无法打开日志（Windows 错误 {result}）。"), true);
                    }
                }
            }
            controls::PROGRAM if notification == CBN_SELCHANGE as u16 => {
                let index = unsafe { SendMessageW(self.controls.program, CB_GETCURSEL, 0, 0) };
                if index >= 0 {
                    let length = unsafe {
                        SendMessageW(self.controls.program, CB_GETLBTEXTLEN, index as usize, 0)
                    };
                    if (0..=32_767).contains(&length) {
                        let mut buffer = vec![0; length as usize + 1];
                        unsafe {
                            SendMessageW(
                                self.controls.program,
                                CB_GETLBTEXT,
                                index as usize,
                                buffer.as_mut_ptr() as isize,
                            );
                        }
                        self.select_program(PathBuf::from(OsString::from_wide(
                            &buffer[..length as usize],
                        )));
                    }
                }
            }
            _ => {}
        }
    }

    fn select_program(&mut self, path: PathBuf) {
        set_text(self.controls.program, &display_path(&path));
        set_text(self.controls.directory, "");
        self.status("已选择程序，点击“运行”启动。", false);
    }

    pub fn drop_files(&mut self, drop: HDROP) {
        struct DropFiles(HDROP);
        impl Drop for DropFiles {
            fn drop(&mut self) {
                unsafe {
                    DragFinish(self.0);
                }
            }
        }
        let drop = DropFiles(drop);
        if unsafe { DragQueryFileW(drop.0, u32::MAX, null_mut(), 0) } != 1 {
            self.status("请一次拖入一个程序文件。", true);
            return;
        }
        let length = unsafe { DragQueryFileW(drop.0, 0, null_mut(), 0) };
        if length == 0 || length > 32_767 {
            self.status("拖入的文件路径不可用。", true);
            return;
        }
        let mut buffer = vec![0; length as usize + 1];
        let copied = unsafe { DragQueryFileW(drop.0, 0, buffer.as_mut_ptr(), buffer.len() as u32) };
        self.select_program(PathBuf::from(OsString::from_wide(
            &buffer[..copied as usize],
        )));
    }

    pub(super) fn current_settings(&self) -> Result<Settings, String> {
        let mut settings = self.settings.clone();
        settings.engine = match unsafe { SendMessageW(self.controls.engine, CB_GETCURSEL, 0, 0) } {
            1 => Engine::Jit,
            2 => Engine::Interpreter,
            _ => Engine::Default,
        };
        let ansi = text(self.controls.ansi);
        settings.ansi_page = if matches!(ansi.trim(), "" | "自动" | "auto") {
            None
        } else {
            Some(
                ansi.trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|page| *page > 0)
                    .ok_or("Win16 字符编码须为“自动”或 Windows 代码页编号。")?,
            )
        };
        settings.dos_page = if unsafe { SendMessageW(self.controls.dos, CB_GETCURSEL, 0, 0) } == 1 {
            936
        } else {
            437
        };
        settings.dos_version = text(self.controls.version);
        settings.diagnostics =
            unsafe { SendMessageW(self.controls.diagnostics, BM_GETCHECK, 0, 0) } == 1;
        Ok(settings)
    }

    fn launch(&mut self) {
        let result = (|| {
            let settings = self.current_settings()?;
            let request = Request {
                program: text(self.controls.program),
                arguments: text(self.controls.arguments),
                directory: text(self.controls.directory),
                settings: settings.clone(),
            };
            let prepared = request.prepare(&self.installation)?;
            let program = prepared.program.clone();
            process::launch(prepared, &self.root, self.sender.clone())?;
            self.running += 1;
            self.settings = settings;
            self.settings.remember(&program);
            self.status("正在启动程序…", false);
            if let Err(error) = store::save(&self.root, &self.settings) {
                self.status(&error, true);
            }
            unsafe {
                SendMessageW(self.controls.program, CB_RESETCONTENT, 0, 0);
            }
            for path in &self.settings.recent {
                unsafe {
                    SendMessageW(
                        self.controls.program,
                        CB_ADDSTRING,
                        0,
                        wide(path).as_ptr() as isize,
                    );
                }
            }
            set_text(self.controls.program, &display_path(&program));
            Ok::<_, String>(())
        })();
        if let Err(error) = result {
            self.status(&error, true);
        }
    }

    pub fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Started { name, pid, log } => {
                    self.append_log(&format!(
                        "\r\n启动 {name} · PID {pid}\r\n日志：{}\r\n",
                        display_path(&log)
                    ));
                    match crate::log_reader::LogReader::open(&log) {
                        Ok(reader) => {
                            self.logs.insert(log.clone(), reader);
                        }
                        Err(error) => self.append_log(&format!("无法读取运行日志：{error}\r\n")),
                    }
                    self.log = Some(log);
                    self.status(
                        &format!("{name} 已启动（PID {pid}）。可以继续启动其他程序。"),
                        false,
                    );
                }
                Event::Finished {
                    name,
                    log,
                    result,
                    details,
                } => {
                    self.drain_logs(Some(&log));
                    self.running = self.running.saturating_sub(1);
                    self.log = Some(log);
                    let (message, error) = match result {
                        Ok(code) => (
                            format!(
                                "{name} 已退出，退出代码 {code}。{}",
                                if details.is_empty() {
                                    String::new()
                                } else {
                                    "请查看下方运行日志。".into()
                                }
                            ),
                            code != 0 || details.contains("runtime:"),
                        ),
                        Err(error) => (error, true),
                    };
                    self.status(&message, error);
                    if !error {
                        self.append_log(&format!("{message}\r\n"));
                    }
                }
            }
            unsafe {
                EnableWindow(self.controls.log, 1);
            }
        }
        self.drain_logs(None);
    }
}

fn browse_program(owner: HWND) -> Result<Option<PathBuf>, String> {
    let mut buffer = vec![0_u16; 32_768];
    let filter = wide("旧程序 (*.exe;*.com)\0*.exe;*.com\0所有文件 (*.*)\0*.*\0");
    let mut request = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: filter.as_ptr(),
        lpstrFile: buffer.as_mut_ptr(),
        nMaxFile: buffer.len() as u32,
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    if unsafe { GetOpenFileNameW(&mut request) } == 0 {
        let error = unsafe { CommDlgExtendedError() };
        return if error == 0 {
            Ok(None)
        } else {
            Err(format!("文件选择失败（Windows 错误 {error:#x}）。"))
        };
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(Some(PathBuf::from(OsString::from_wide(&buffer[..length]))))
}

fn browse_directory(owner: HWND) -> Option<PathBuf> {
    let title = wide("选择工作目录");
    let request = BROWSEINFOW {
        hwndOwner: owner,
        lpszTitle: title.as_ptr(),
        ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX,
        ..Default::default()
    };
    let item = unsafe { SHBrowseForFolderW(&request) };
    if item.is_null() {
        return None;
    }
    let mut buffer = vec![0; 32_768];
    let success =
        unsafe { SHGetPathFromIDListEx(item, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    unsafe {
        CoTaskMemFree(item.cast());
    }
    if success == 0 {
        return None;
    }
    let length = buffer.iter().position(|unit| *unit == 0)?;
    Some(PathBuf::from(OsString::from_wide(&buffer[..length])))
}
