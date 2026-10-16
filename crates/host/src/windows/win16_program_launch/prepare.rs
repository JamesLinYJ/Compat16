//! Resolve WinExec in the calling task's filename and environment namespace.

use super::*;
use crate::filesystem::Filesystem;
use cap_std::fs::OpenOptions;
use cap_std::fs::OpenOptionsExt as CapOpenOptionsExt;
use runtime::{Win16HostShellExecutionOperation, Win16KernelFileSystemState};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

pub(in crate::windows) fn prepare(
    host: &mut super::super::WindowsHost,
    operation: &Win16HostShellExecutionOperation,
) -> Result<Result<PreparedLaunch, u16>, RuntimeError> {
    let Win16HostShellExecutionOperation::WinExec {
        command_line,
        directory,
        application_path,
        environment,
        owner,
        show,
    } = operation
    else {
        return Err(invalid("program preparation requires WinExec"));
    };
    let codec = host.win16_dcs.text_codec();
    let (wide, spans) = match codec.to_wide_with_ranges(command_line) {
        Ok(value) => value,
        Err(error) if error.kind() == Kind::InvalidInput => return Ok(Err(11)),
        Err(error) => return Err(error),
    };
    if wide.contains(&0) {
        return Ok(Err(11));
    }
    let Some((file_start, file_end, tail_start)) = split_command(&wide) else {
        return Ok(Err(2));
    };
    let file_name = String::from_utf16(&wide[file_start..file_end])
        .map_err(|error| failure("decode WinExec filename", error))?;
    if reserved_component(std::path::Path::new(&file_name)) {
        return Ok(Err(11));
    }
    // WinExec consumes its first separator while building EXECBLOCK's PSP
    // tail (KERNEL31 WINEXEC.ASM WELoop2). Additional whitespace and quotes
    // remain exact original guest bytes; the native command keeps its space.
    let guest_tail_start = if tail_start < wide.len() {
        tail_start + 1
    } else {
        tail_start
    };
    let tail_byte = if guest_tail_start == wide.len() {
        command_line.len()
    } else {
        spans
            .iter()
            .find(|span| span.utf16_units.start == guest_tail_start)
            .map(|span| span.guest_bytes.start)
            .ok_or_else(|| invalid("WinExec argument boundary splits a guest character"))?
    };
    let command_tail = command_line[tail_byte..].to_vec();
    let mut directories = Win16KernelFileSystemState::new();
    directories.seed_owner(*owner, directory.clone())?;
    let cwd = directories.resolve_guest_path_text(*owner, ".", false)?;
    let cwd = match super::super::win16_file_paths::resolve(&mut host.filesystem, &cwd, true, false)
    {
        Ok(path) => host.filesystem.canonical_root.join(path),
        Err(_) => return Ok(Err(3)),
    };
    let leaf = file_name
        .rsplit(['\\', '/', ':'])
        .next()
        .unwrap_or_default();
    let file_name = if leaf.contains('.') {
        file_name
    } else {
        format!("{file_name}.exe")
    };
    let search = !file_name.contains(['\\', '/', ':']);
    let mut found = task_candidate(&mut host.filesystem, &directories, *owner, &file_name);
    if matches!(&found, Err(2 | 3)) && search {
        // KERNEL31 DefaultOrder: current, Windows, 16-bit system, system,
        // application, PATH. The first candidate used the exact task cwd.
        let mut search_directories = Vec::new();
        search_directories.push(system_directory(GetWindowsDirectoryW)?);
        if let Some(path) = std::env::var_os("VDM_SYSTEM_DIR") {
            search_directories.push(PathBuf::from(path));
        }
        search_directories.push(system_directory(GetSystemDirectoryW)?);
        let app = PathBuf::from(
            String::from_utf16(&codec.to_wide(application_path)?)
                .map_err(|error| failure("decode WinExec application directory", error))?,
        );
        if let Some(parent) = app.parent() {
            search_directories.push(parent.to_path_buf());
        }
        for path in search_directories {
            found = if path.is_absolute() {
                native_candidate(path.join(&file_name))
            } else {
                task_candidate(
                    &mut host.filesystem,
                    &directories,
                    *owner,
                    &path.join(&file_name).to_string_lossy(),
                )
            };
            if !matches!(&found, Err(2 | 3)) {
                break;
            }
        }
        if matches!(&found, Err(2 | 3)) {
            if let Some(path) = environment.split(|byte| *byte == 0).find_map(|entry| {
                (entry.len() >= 5 && entry[..5].eq_ignore_ascii_case(b"PATH="))
                    .then_some(&entry[5..])
            }) {
                let path = host
                    .filesystem
                    .guest_code_page()
                    .decode(path)
                    .map_err(|error| failure("decode inherited WinExec PATH", error))?;
                for directory in path.split(';').map(|value| value.trim_matches('"')) {
                    if directory.is_empty() {
                        continue;
                    }
                    found = task_candidate(
                        &mut host.filesystem,
                        &directories,
                        *owner,
                        &format!("{directory}\\{file_name}"),
                    );
                    if !matches!(&found, Err(2 | 3)) {
                        break;
                    }
                }
            }
        }
    }
    let (mut file, program) = match found {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    let guest = is_guest(&mut file, &program)?;
    if guest && command_tail.len() > 126 {
        return Ok(Err(11));
    }
    if guest
        && file
            .metadata()
            .map_err(|error| failure("inspect guest executable", error))?
            .len()
            > MAX_IMAGE_BYTES
    {
        return Ok(Err(8));
    }
    file.rewind()
        .map_err(|error| failure("rewind owned executable image", error))?;
    let environment: Vec<Vec<u8>> = environment
        .split(|byte| *byte == 0)
        .take_while(|entry| !entry.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    let program_wide: Vec<u16> = program.as_os_str().encode_wide().collect();
    let mut native_command = Vec::new();
    native_command.push(0x22);
    native_command.extend_from_slice(&program_wide);
    native_command.push(0x22);
    native_command.extend_from_slice(&wide[tail_start..]);
    native_command.push(0);
    if native_command.len() > 32_767 {
        return Ok(Err(11));
    }
    let request = LaunchRequest {
        version: 1,
        program: program_wide,
        directory: cwd.as_os_str().encode_wide().collect(),
        command_tail,
        environment,
        dos_code_page: host.code_page,
        ansi_code_page: codec.code_page(),
        show: *show,
        execution: host.child_execution,
    };
    Ok(Ok(PreparedLaunch {
        file,
        program,
        directory: cwd,
        native_command,
        request,
        guest,
    }))
}

fn split_command(wide: &[u16]) -> Option<(usize, usize, usize)> {
    let space = |unit: u16| matches!(unit, 0x20 | 0x09);
    let start = wide.iter().position(|unit| !space(*unit))?;
    if wide[start] == 0x22 {
        let end = wide[start + 1..].iter().position(|unit| *unit == 0x22)? + start + 1;
        if start + 1 == end || wide.get(end + 1).is_some_and(|unit| !space(*unit)) {
            return None;
        }
        Some((start + 1, end, end + 1))
    } else {
        let end = wide[start..]
            .iter()
            .position(|unit| space(*unit))
            .map_or(wide.len(), |end| end + start);
        Some((start, end, end))
    }
}

fn task_candidate(
    filesystem: &mut Filesystem,
    directories: &Win16KernelFileSystemState,
    owner: runtime::Win16HostTaskOwner,
    name: &str,
) -> Result<(File, PathBuf), u16> {
    let resolved = directories
        .resolve_guest_path_text(owner, name, false)
        .map_err(|_| 3_u16)
        .and_then(|path| {
            super::super::win16_file_paths::resolve(filesystem, &path, true, false)
                .map_err(|error| error.code as u16)
        });
    let relative = match resolved {
        Ok(path) => path,
        Err(2 | 3 | 15) if native_absolute_file(name) => {
            return native_candidate(PathBuf::from(name));
        }
        Err(code) => return Err(code),
    };
    let mut options = OpenOptions::new();
    options.read(true).share_mode(FILE_SHARE_READ);
    let file = filesystem
        .root
        .open_with(&relative, &options)
        .map_err(io_code)?
        .into_std();
    if !file.metadata().map_err(io_code)?.is_file() {
        return Err(2);
    }
    Ok((file, filesystem.canonical_root.join(relative)))
}

fn native_absolute_file(name: &str) -> bool {
    use std::path::{Component, Path, Prefix};
    let path = Path::new(name);
    // Native PE applications can live on another volume or a UNC share. Keep
    // their WinExec path working without admitting device/raw-volume prefixes.
    path.is_absolute()
        && matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)))
}

fn native_candidate(program: PathBuf) -> Result<(File, PathBuf), u16> {
    use std::path::{Component, Prefix};
    if !program.is_absolute()
        || reserved_component(&program)
        || !matches!(program.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)
                | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _)))
    {
        return Err(11);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&program)
        .map_err(io_code)?;
    if !file.metadata().map_err(io_code)?.is_file() {
        return Err(2);
    }
    let program = program.canonicalize().map_err(io_code)?;
    Ok((file, program))
}

fn reserved_component(path: &std::path::Path) -> bool {
    path.components().any(|part| {
        matches!(part, std::path::Component::Normal(name)
        if crate::filesystem::is_reserved_device_name(&name.to_string_lossy()))
    })
}

fn io_code(error: std::io::Error) -> u16 {
    match error.raw_os_error() {
        Some(2) => 2,
        Some(3 | 15 | 123 | 161) => 3,
        Some(5 | 32 | 33) => 5,
        Some(8 | 14) => 8,
        _ => 11,
    }
}

fn is_guest(file: &mut File, path: &std::path::Path) -> Result<bool, RuntimeError> {
    let mut header = [0_u8; 64];
    let length = file
        .metadata()
        .map_err(|error| failure("inspect executable signature", error))?
        .len();
    let size = usize::try_from(length.min(header.len() as u64)).expect("bounded header size");
    file.read_exact(&mut header[..size])
        .map_err(|error| failure("read executable signature", error))?;
    // These fixed on-disk signature fields select a loader only. The child
    // still performs the complete formats crate validation before execution.
    if size >= 2 && &header[..2] == b"MZ" {
        if size == header.len() {
            let offset = u32::from_le_bytes(header[60..64].try_into().expect("four-byte field"));
            if offset >= 64 {
                file.seek(SeekFrom::Start(u64::from(offset)))
                    .map_err(|error| failure("seek executable signature", error))?;
                let mut signature = [0_u8; 4];
                let read = usize::try_from(length.saturating_sub(u64::from(offset)).min(4))
                    .expect("bounded signature size");
                file.read_exact(&mut signature[..read])
                    .map_err(|error| failure("read executable format", error))?;
                if read >= 2 && matches!(&signature[..2], b"NE") {
                    return Ok(true);
                }
                if read >= 2 && matches!(&signature[..2], b"PE" | b"LE" | b"LX") {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }
    Ok(path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("com")))
}

fn system_directory(
    api: unsafe extern "system" fn(*mut u16, u32) -> u32,
) -> Result<PathBuf, RuntimeError> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0_u16; 32_768];
    let count = unsafe { api(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if count == 0 || count >= buffer.len() {
        return Err(failure(
            "query executable search directory",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..count],
    )))
}
