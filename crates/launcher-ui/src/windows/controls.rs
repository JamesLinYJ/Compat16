use super::*;

pub(super) const PROGRAM: u16 = 100;
pub(super) const BROWSE: u16 = 101;
pub(super) const DIRECTORY_BROWSE: u16 = 102;
pub(super) const ADVANCED: u16 = 103;
pub(super) const RUN: u16 = 104;
pub(super) const LOG: u16 = 105;
pub(super) const CLOSE: u16 = 2;
pub(super) const WINDOW_STYLE: u32 =
    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VSCROLL;

pub(super) struct Fonts {
    pub(super) regular: HFONT,
    title: HFONT,
    mono: HFONT,
}
impl Fonts {
    pub fn new(dpi: u32) -> Result<Self, String> {
        let font = |height, weight, face|
            // SAFETY: `CreateFontW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
            CreateFontW(
                -scale(height, dpi),
                0,
                0,
                0,
                weight,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                wide(face).as_ptr(),
            )
        };
        let fonts = Self {
            regular: font(15, FW_NORMAL as i32, "Segoe UI"),
            title: font(28, FW_SEMIBOLD as i32, "Segoe UI"),
            mono: font(13, FW_NORMAL as i32, "Consolas"),
        };
        if fonts.regular.is_null() || fonts.title.is_null() || fonts.mono.is_null() {
            Err("无法创建界面字体。".into())
        } else {
            Ok(fonts)
        }
    }
}
impl Drop for Fonts {
    fn drop(&mut self) {
        // SAFETY: `DeleteObject` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            if !self.regular.is_null() {
                DeleteObject(self.regular);
            }
            if !self.title.is_null() {
                DeleteObject(self.title);
            }
            if !self.mono.is_null() {
                DeleteObject(self.mono);
            }
        }
    }
}

pub(super) struct Item {
    pub(super) window: HWND,
    pub(super) rect: [i32; 4],
    pub(super) advanced: bool,
    pub(super) footer: bool,
    title: bool,
}
pub(super) struct Controls {
    pub(super) items: Vec<Item>,
    pub program: HWND,
    pub arguments: HWND,
    pub directory: HWND,
    pub engine: HWND,
    pub ansi: HWND,
    pub dos: HWND,
    pub version: HWND,
    pub diagnostics: HWND,
    pub status: HWND,
    pub log: HWND,
    pub advanced: HWND,
    pub log_view: HWND,
    pub icon: HWND,
}

impl Controls {
    pub fn new(parent: HWND, fonts: &Fonts, settings: &Settings) -> Result<Self, String> {
        let mut items = Vec::new();
        let mut add = |class: &str,
                       label: &str,
                       style: u32,
                       id: u16,
                       rect: [i32; 4],
                       advanced: bool,
                       footer: bool,
                       title: bool|
         -> Result<HWND, String> {
            let window =
                // SAFETY: `CreateWindowExW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
                unsafe {
                CreateWindowExW(
                    0,
                    wide(class).as_ptr(),
                    wide(label).as_ptr(),
                    WS_CHILD | WS_VISIBLE | style,
                    0,
                    0,
                    0,
                    0,
                    parent,
                    id as usize as HMENU,
                    GetModuleHandleW(null()),
                    null(),
                )
            };
            if window.is_null() {
                return Err(format!(
                    "无法创建界面控件：{}",
                    std::io::Error::last_os_error()
                ));
            }
            items.push(Item {
                window,
                rect,
                advanced,
                footer,
                title,
            });
            Ok(window)
        };
        let tab = WS_TABSTOP;
        let edit = WS_BORDER | tab | ES_AUTOHSCROLL as u32;
        let combo = WS_VSCROLL | tab | CBS_DROPDOWNLIST as u32;
        let icon = add(
            "STATIC",
            "",
            0x0003,
            0,
            [28, 26, 40, 40],
            false,
            false,
            false,
        )?; // SS_ICON
        add(
            "STATIC",
            "Compat16",
            0,
            0,
            [86, 20, 526, 38],
            false,
            false,
            true,
        )?;
        add(
            "STATIC",
            "运行 DOS 与 Windows 16 位程序",
            0,
            0,
            [86, 62, 526, 26],
            false,
            false,
            false,
        )?;
        add(
            "STATIC",
            "程序文件  ·  也可以将 EXE / COM 拖入窗口",
            0,
            0,
            [28, 106, 584, 22],
            false,
            false,
            false,
        )?;
        let program = add(
            "COMBOBOX",
            "",
            WS_VSCROLL | tab | CBS_DROPDOWN as u32 | CBS_AUTOHSCROLL as u32,
            PROGRAM,
            [28, 133, 474, 220],
            false,
            false,
            false,
        )?;
        add(
            "BUTTON",
            "浏览…",
            tab,
            BROWSE,
            [514, 131, 98, 30],
            false,
            false,
            false,
        )?;
        add(
            "STATIC",
            "程序参数（可选）",
            0,
            0,
            [28, 178, 584, 22],
            false,
            false,
            false,
        )?;
        let arguments = add("EDIT", "", edit, 0, [28, 203, 584, 28], false, false, false)?;
        add(
            "STATIC",
            "工作目录（留空时使用程序所在目录）",
            0,
            0,
            [28, 245, 584, 22],
            false,
            false,
            false,
        )?;
        let directory = add("EDIT", "", edit, 0, [28, 270, 474, 28], false, false, false)?;
        add(
            "BUTTON",
            "浏览…",
            tab,
            DIRECTORY_BROWSE,
            [514, 268, 98, 30],
            false,
            false,
            false,
        )?;
        let advanced = add(
            "BUTTON",
            "高级设置  ▾",
            tab,
            ADVANCED,
            [28, 315, 152, 30],
            false,
            false,
            false,
        )?;
        add(
            "STATIC",
            "执行引擎",
            0,
            0,
            [28, 356, 275, 22],
            true,
            false,
            false,
        )?;
        let engine = add(
            "COMBOBOX",
            "",
            combo,
            0,
            [28, 381, 275, 180],
            true,
            false,
            false,
        )?;
        add(
            "STATIC",
            "Win16 字符编码",
            0,
            0,
            [330, 356, 282, 22],
            true,
            false,
            false,
        )?;
        let ansi = add(
            "COMBOBOX",
            "",
            WS_VSCROLL | tab | CBS_DROPDOWN as u32 | CBS_AUTOHSCROLL as u32,
            0,
            [330, 381, 282, 200],
            true,
            false,
            false,
        )?;
        add(
            "STATIC",
            "DOS 代码页",
            0,
            0,
            [28, 422, 275, 22],
            true,
            false,
            false,
        )?;
        let dos = add(
            "COMBOBOX",
            "",
            combo,
            0,
            [28, 447, 275, 120],
            true,
            false,
            false,
        )?;
        add(
            "STATIC",
            "DOS 版本（留空时为 5.00）",
            0,
            0,
            [330, 422, 282, 22],
            true,
            false,
            false,
        )?;
        let version = add("EDIT", "", edit, 0, [330, 447, 282, 28], true, false, false)?;
        let diagnostics = add(
            "BUTTON",
            "出错时保存详细诊断",
            tab | BS_AUTOCHECKBOX as u32,
            0,
            [28, 489, 584, 26],
            true,
            false,
            false,
        )?;
        let status = add(
            "STATIC",
            "选择程序后点击“运行”。",
            0,
            0,
            [28, 362, 584, 44],
            false,
            true,
            false,
        )?;
        add(
            "STATIC",
            "运行日志",
            0,
            0,
            [28, 418, 584, 22],
            false,
            true,
            false,
        )?;
        let log_view = add(
            "EDIT",
            "准备就绪。运行日志将显示在这里。\r\n",
            WS_BORDER
                | WS_VSCROLL
                | WS_HSCROLL
                | WS_TABSTOP
                | ES_MULTILINE as u32
                | ES_READONLY as u32
                | ES_AUTOVSCROLL as u32
                | ES_AUTOHSCROLL as u32,
            0,
            [28, 447, 584, 120],
            false,
            true,
            false,
        )?;
        let log = add(
            "BUTTON",
            "打开日志文件",
            tab,
            LOG,
            [28, 590, 132, 34],
            false,
            true,
            false,
        )?;
        add(
            "BUTTON",
            "关闭",
            tab,
            CLOSE,
            [392, 590, 100, 34],
            false,
            true,
            false,
        )?;
        add(
            "BUTTON",
            "运行",
            tab | BS_OWNERDRAW as u32,
            RUN,
            [504, 590, 108, 34],
            false,
            true,
            false,
        )?;
        let controls = Self {
            items,
            program,
            arguments,
            directory,
            engine,
            ansi,
            dos,
            version,
            diagnostics,
            status,
            log,
            advanced,
            log_view,
            icon,
        };
        controls.fonts(fonts);
        for path in &settings.recent {
            combo_add(program, path);
        }
        if let Some(path) = settings.recent.first() {
            set_text(program, path);
        }
        for label in ["默认（JIT）", "JIT", "解释器"] {
            combo_add(engine, label);
        }
        combo_select(
            engine,
            match settings.engine {
                crate::model::Engine::Default => 0,
                crate::model::Engine::Jit => 1,
                crate::model::Engine::Interpreter => 2,
            },
        );
        for label in ["自动", "1252", "936", "932", "949", "950", "1251"] {
            combo_add(ansi, label);
        }
        set_text(
            ansi,
            &settings
                .ansi_page
                .map_or_else(|| "自动".into(), |page| page.to_string()),
        );
        for label in ["437 · 美国", "936 · 简体中文"] {
            combo_add(dos, label);
        }
        combo_select(dos, usize::from(settings.dos_page == 936));
        set_text(version, &settings.dos_version);
        // SAFETY: `SendMessageW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            SendMessageW(
                diagnostics,
                BM_SETCHECK,
                usize::from(settings.diagnostics),
                0,
            );
            EnableWindow(log, 0);
            SendMessageW(program, CB_LIMITTEXT, 32_000, 0);
            SendMessageW(ansi, CB_LIMITTEXT, 32, 0);
            SendMessageW(arguments, 0x00c5, 32_000, 0); // EM_LIMITTEXT
            SendMessageW(directory, 0x00c5, 32_000, 0);
            SendMessageW(version, 0x00c5, 16, 0);
            SendMessageW(log_view, 0x00c5, 80_000, 0);
        }
        Ok(controls)
    }

    pub fn fonts(&self, fonts: &Fonts) {
        for item in &self.items {
            // SAFETY: `SendMessageW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
                SendMessageW(
                    item.window,
                    WM_SETFONT,
                    if item.window == self.log_view {
                        fonts.mono
                    } else if item.title {
                        fonts.title
                    } else {
                        fonts.regular
                    } as usize,
                    1,
                );
            }
        }
    }
}

pub(super) fn scale(value: i32, dpi: u32) -> i32 {
    ((i64::from(value) * i64::from(dpi) + 48) / 96) as i32
}
fn combo_add(window: HWND, label: &str) {
    // SAFETY: `SendMessageW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        SendMessageW(window, CB_ADDSTRING, 0, wide(label).as_ptr() as isize);
    }
}
fn combo_select(window: HWND, index: usize) {
    // SAFETY: `SendMessageW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        SendMessageW(window, CB_SETCURSEL, index, 0);
    }
}
