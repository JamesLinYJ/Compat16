use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::Settings;

pub(crate) fn root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Compat16")
}

pub(crate) fn load(root: &Path) -> Result<Settings, String> {
    let file = match File::open(root.join("launcher.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Settings::default());
        }
        Err(error) => return Err(format!("无法读取设置，已使用默认值：{error}")),
    };
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("设置文件过大，已使用默认值。".into());
    }
    let mut settings: Settings = serde_json::from_slice(&bytes)
        .map_err(|error| format!("设置无法读取，已使用默认值：{error}"))?;
    settings.recent.truncate(8);
    Ok(settings)
}

pub(crate) fn save(root: &Path, settings: &Settings) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|error| error.to_string())?;
    let temporary = unique_file(root, "settings", "tmp").map_err(|error| error.to_string())?;
    let (path, mut file) = temporary;
    let result = (|| {
        serde_json::to_writer_pretty(&mut file, settings).map_err(std::io::Error::other)?;
        file.flush()?;
        drop(file);
        fs::rename(&path, root.join("launcher.json"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&path);
    }
    result.map_err(|error| format!("设置未能保存：{error}"))
}

pub(crate) fn unique_file(
    root: &Path,
    prefix: &str,
    extension: &str,
) -> std::io::Result<(PathBuf, File)> {
    fs::create_dir_all(root)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for serial in 0..64 {
        let path = root.join(format!(
            "{prefix}-{}-{nonce}-{serial}.{extension}",
            std::process::id()
        ));
        match File::create_new(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot allocate a new log file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::Engine, test_support::Fixture};

    #[test]
    fn settings_replace_atomically_and_recent_list_stays_bounded() {
        let fixture = Fixture::new();
        let mut settings = load(&fixture.0).unwrap();
        for index in 0..12 {
            settings.remember(&fixture.0.join(format!("app{index}.exe")));
        }
        settings.engine = Engine::Interpreter;
        settings.ansi_page = Some(936);
        save(&fixture.0, &settings).unwrap();
        settings.remember(&fixture.0.join("app8.exe"));
        settings.diagnostics = true;
        save(&fixture.0, &settings).unwrap();
        let restored = load(&fixture.0).unwrap();
        assert_eq!(restored.recent.len(), 8);
        assert_eq!(
            restored
                .recent
                .iter()
                .filter(|path| path.ends_with("app8.exe"))
                .count(),
            1
        );
        assert!(restored.engine == Engine::Interpreter && restored.diagnostics);
        assert_eq!(restored.ansi_page, Some(936));
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn damaged_settings_are_reported_without_overwriting_them() {
        let fixture = Fixture::new();
        let path = fixture.0.join("launcher.json");
        std::fs::write(&path, b"{broken").unwrap();
        assert!(load(&fixture.0).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{broken");
    }
}
