use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Engine {
    #[default]
    Default,
    Jit,
    Interpreter,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct Settings {
    pub recent: Vec<String>,
    pub engine: Engine,
    pub ansi_page: Option<u32>,
    pub dos_page: u32,
    pub dos_version: String,
    pub diagnostics: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            recent: Vec::new(),
            engine: Engine::Default,
            ansi_page: None,
            dos_page: 437,
            dos_version: String::new(),
            diagnostics: false,
        }
    }
}

impl Settings {
    pub fn remember(&mut self, program: &Path) {
        let path = display_path(program);
        self.recent.retain(|previous| previous != &path);
        self.recent.insert(0, path);
        self.recent.truncate(8);
    }
}

pub(crate) struct Request {
    pub program: String,
    pub arguments: String,
    pub directory: String,
    pub settings: Settings,
}

pub(crate) struct Prepared {
    pub executable: PathBuf,
    pub program: PathBuf,
    pub directory: PathBuf,
    pub arguments: Vec<OsString>,
    pub diagnostics: bool,
}

impl Request {
    pub fn prepare(&self, installation: &Path) -> Result<Prepared, String> {
        let input = unquote(&self.program);
        if input.is_empty() {
            return Err("请选择要运行的 EXE 或 COM 程序。".into());
        }
        let program = Path::new(input)
            .canonicalize()
            .map_err(|error| format!("无法打开程序：{error}"))?;
        if !program.is_file() {
            return Err("请选择程序文件，而不是文件夹。".into());
        }
        let directory = if self.directory.trim().is_empty() {
            program
                .parent()
                .ok_or("程序没有可用的所在目录。")?
                .to_path_buf()
        } else {
            Path::new(unquote(&self.directory))
                .canonicalize()
                .map_err(|error| format!("工作目录不可用：{error}"))?
        };
        if !directory.is_dir() {
            return Err("工作目录必须是文件夹。".into());
        }
        if self.arguments.contains('\0') {
            return Err("程序参数包含无效字符。".into());
        }
        let version = self.settings.dos_version.trim();
        if !version.is_empty()
            && !version.split_once('.').is_some_and(|(major, minor)| {
                [major, minor].iter().all(|part| {
                    !part.is_empty()
                        && part.bytes().all(|byte| byte.is_ascii_digit())
                        && part.parse::<u8>().is_ok()
                })
            })
        {
            return Err("DOS 版本须为两段十进制数，例如 5.00 或 6.22。".into());
        }
        for name in ["compat16w.exe", "compat16.dll", "compat16host.exe"] {
            if !installation.join(name).is_file() {
                return Err(format!("缺少 {name}。请将发布包中的文件放在同一文件夹。"));
            }
        }
        let mut arguments = Vec::<OsString>::new();
        match self.settings.engine {
            Engine::Default => {}
            Engine::Jit => arguments.extend(["--cpu-engine".into(), "jit".into()]),
            Engine::Interpreter => arguments.extend(["--cpu-engine".into(), "interpreter".into()]),
        }
        if let Some(page) = self.settings.ansi_page {
            arguments.extend(["--win16-code-page".into(), page.to_string().into()]);
        }
        if self.settings.dos_page != 437 {
            arguments.extend([
                "--code-page".into(),
                self.settings.dos_page.to_string().into(),
            ]);
        }
        if !self.settings.dos_version.trim().is_empty() {
            arguments.extend([
                "--dos-version".into(),
                self.settings.dos_version.trim().into(),
            ]);
        }
        arguments.extend([
            "--command-tail".into(),
            self.arguments.clone().into(),
            "--working-directory".into(),
            directory.as_os_str().to_os_string(),
        ]);
        arguments.push(program.as_os_str().to_os_string());
        Ok(Prepared {
            executable: installation.join("compat16w.exe"),
            program,
            directory,
            arguments,
            diagnostics: self.settings.diagnostics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn launch_preserves_literal_tail_unicode_paths_and_separate_working_directory() {
        let fixture = Fixture::new();
        let program = fixture.file("旧 程序.com");
        let directory = fixture.directory("工作 目录");
        for name in ["compat16w.exe", "compat16.dll", "compat16host.exe"] {
            fixture.file(name);
        }
        let original_directory = std::env::current_dir().unwrap();
        let raw = r#"/A  "file with spaces.txt" ""  中文"#;
        let prepared = Request {
            program: format!("\"{}\"", program.display()),
            arguments: raw.into(),
            directory: directory.to_string_lossy().into_owned(),
            settings: Settings::default(),
        }
        .prepare(&fixture.0)
        .unwrap();
        assert_eq!(prepared.program, program.canonicalize().unwrap());
        assert_eq!(prepared.directory, directory.canonicalize().unwrap());
        assert_eq!(prepared.arguments[0], "--command-tail");
        assert_eq!(prepared.arguments[1], raw);
        assert_eq!(prepared.arguments[2], "--working-directory");
        assert_eq!(
            prepared.arguments.last().unwrap(),
            prepared.program.as_os_str()
        );
        assert_eq!(std::env::current_dir().unwrap(), original_directory);
    }

    #[test]
    fn invalid_inputs_and_incomplete_bundle_fail_before_spawn() {
        let fixture = Fixture::new();
        let program = fixture.file("app.exe");
        let mut request = Request {
            program: program.to_string_lossy().into_owned(),
            arguments: String::new(),
            directory: String::new(),
            settings: Settings::default(),
        };
        assert!(
            request
                .prepare(&fixture.0)
                .err()
                .unwrap()
                .contains("compat16w.exe")
        );
        request.arguments = "a\0b".into();
        assert!(
            request
                .prepare(&fixture.0)
                .err()
                .unwrap()
                .contains("无效字符")
        );
        request.arguments.clear();
        request.directory = program.to_string_lossy().into_owned();
        assert!(
            request
                .prepare(&fixture.0)
                .err()
                .unwrap()
                .contains("文件夹")
        );
        request.directory.clear();
        request.settings.dos_version = "6.256".into();
        assert!(
            request
                .prepare(&fixture.0)
                .err()
                .unwrap()
                .contains("DOS 版本")
        );
    }
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

pub(crate) fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
    }
}
