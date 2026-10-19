//! Shell association dispatch by file format, including native PE .com files.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::{ffi::OsStringExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

pub(super) fn run() -> Result<ExitCode, String> {
    let raw = native_loader::command_line().map_err(|error| error.to_string())?;
    let (program, tail) = parse(&raw)?;
    let program = PathBuf::from(std::ffi::OsString::from_wide(&program));
    let program = program
        .canonicalize()
        .map_err(|error| format!("无法打开程序：{error}"))?;
    let native = is_native_pe(&program).map_err(|error| error.to_string())?;
    let mut command = if native {
        Command::new(&program)
    } else {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        Command::new(executable)
    };
    if native {
        if !tail.is_empty() {
            command.raw_arg(std::ffi::OsString::from_wide(tail));
        }
    } else {
        let tail = String::from_utf16(tail).map_err(|_| "程序参数包含无效 UTF-16。")?;
        command.arg("--command-tail").arg(tail).arg(&program);
    }
    // Command invokes CreateProcess directly, avoiding the .com association
    // when the target is native. No command shell or launcher UI is involved.
    let status = command
        .status()
        .map_err(|error| format!("无法启动程序：{error}"))?;
    // Stable ExitCode accepts only u8; native Windows programs own all 32 exit
    // bits. The child has already been waited and released by Command::status.
    std::process::exit(status.code().unwrap_or(125))
}

fn is_native_pe(path: &Path) -> std::io::Result<bool> {
    let mut file = File::open(path)?;
    let mut header = [0; 64];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error),
    }
    if &header[..2] != b"MZ" {
        return Ok(false);
    }
    let offset = u64::from(u32::from_le_bytes(
        header[60..64].try_into().expect("fixed DOS field"),
    ));
    if offset > file.metadata()?.len().saturating_sub(4) {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut signature = [0; 4];
    Ok(file.read_exact(&mut signature).is_ok() && &signature == b"PE\0\0")
}

/// The association quotes the module. Only its first separator is structural;
/// everything after it stays original UTF-16, including empty quotes/spaces.
fn parse(raw: &[u16]) -> Result<(Vec<u16>, &[u16]), String> {
    let invalid = || "COM 打开入口的命令行格式无效。".to_string();
    let mut quoted = false;
    let first = raw
        .iter()
        .position(|unit| {
            if *unit == 34 {
                quoted = !quoted;
            }
            !quoted && matches!(*unit, 9 | 32)
        })
        .ok_or_else(invalid)?;
    let rest = trim_start(&raw[first..]);
    let (rest, quoted_marker) = match rest.strip_prefix(&[34]) {
        Some(rest) => (rest, true),
        None => (rest, false),
    };
    let marker: Vec<_> = "--shell-open".encode_utf16().collect();
    let rest = rest.strip_prefix(marker.as_slice()).ok_or_else(invalid)?;
    let rest = if quoted_marker {
        rest.strip_prefix(&[34]).ok_or_else(invalid)?
    } else {
        rest
    };
    if !rest.first().is_some_and(|unit| matches!(unit, 9 | 32)) {
        return Err(invalid());
    }
    let rest = trim_start(rest).strip_prefix(&[34]).ok_or_else(invalid)?;
    let end = rest
        .iter()
        .position(|unit| *unit == 34)
        .ok_or_else(invalid)?;
    if end == 0 || rest[..end].contains(&0) {
        return Err(invalid());
    }
    let tail = &rest[end + 1..];
    let tail = match tail.first() {
        None => tail,
        Some(9 | 32) => &tail[1..],
        _ => return Err(invalid()),
    };
    Ok((rest[..end].to_vec(), tail))
}
fn trim_start(raw: &[u16]) -> &[u16] {
    &raw[raw.iter().take_while(|unit| matches!(unit, 9 | 32)).count()..]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn association_keeps_unicode_path_quotes_and_exact_tail() {
        let raw: Vec<_> =
            r#""C:\Tools\compat16w.exe" --shell-open "C:\旧 文件\APP.COM"  "a b" ""  z "#
                .encode_utf16()
                .collect();
        let (path, tail) = parse(&raw).unwrap();
        assert_eq!(String::from_utf16(&path).unwrap(), r"C:\旧 文件\APP.COM");
        assert_eq!(String::from_utf16(tail).unwrap(), " \"a b\" \"\"  z ");
        for text in [
            r#"x --shell-open "a.com" "#,
            r#"x --shell-open "a.com""#,
            r#"x "--shell-open" "a.com" "#,
        ] {
            assert!(
                parse(&text.encode_utf16().collect::<Vec<_>>())
                    .unwrap()
                    .1
                    .is_empty()
            );
        }
        for text in [
            r#"x --shell-openx "a.com""#,
            r#"x --shell-open """#,
            r#"x --shell-open "a.com"x"#,
        ] {
            assert!(parse(&text.encode_utf16().collect::<Vec<_>>()).is_err());
        }
    }
    #[test]
    fn native_pe_detection_uses_signature_instead_of_extension() {
        let current = std::env::current_exe().unwrap();
        assert!(is_native_pe(&current).unwrap());
    }
}
