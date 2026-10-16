//! Task-resolved LZ paths over the common capability-rooted file service.
//! Decompression consumes a duplicate of the retained open object; no LZ
//! filename entrypoint may reopen guest text in the native process directory.

mod names;

use super::guest_text::GuestTextCodec;
use super::win16::Win16Files;
use crate::filesystem::Filesystem;
use cap_std::fs::{File, OpenOptions, OpenOptionsExt};
use compat_services::lzexpand::{SZDD_HEADER_LEN, inspect_szdd_header};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16GuestPath, Win16HostFile, Win16HostLzInit,
    Win16HostLzName, Win16HostLzOpen,
};
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
};

pub(super) fn open(
    filesystem: &mut Filesystem,
    files: &mut Win16Files,
    codec: GuestTextCodec,
    path: &Win16GuestPath,
    search_name: Option<&str>,
    style: u16,
    ofstruct: Vec<u8>,
) -> Result<Win16HostLzOpen, RuntimeError> {
    loop {
        let mut opened = open_once(
            filesystem,
            files,
            codec,
            path,
            search_name,
            style & !0x2000,
            ofstruct.clone(),
        )?;
        if !super::win16_open_file::needs_prompt(style, opened.result, &opened.ofstruct) {
            return Ok(opened);
        }
        if !super::win16_open_file::prompt_retry(path)? {
            opened.ofstruct[2..4].copy_from_slice(&2u16.to_le_bytes());
            return Ok(opened);
        }
    }
}

fn open_once(
    filesystem: &mut Filesystem,
    files: &mut Win16Files,
    codec: GuestTextCodec,
    path: &Win16GuestPath,
    search_name: Option<&str>,
    style: u16,
    ofstruct: Vec<u8>,
) -> Result<Win16HostLzOpen, RuntimeError> {
    let mut opened =
        super::win16_open_file::open(filesystem, files, codec, path, search_name, style, ofstruct)?;
    // Only FileNotFound permits compressed-name fallback. Sharing/access
    // failures and OF_VERIFY mismatches retain their original result. Reopen
    // names come from the saved OFSTRUCT and must not be rewritten here.
    if opened.result < 0
        && style & 0x8000 == 0
        && u16::from_le_bytes([opened.ofstruct[2], opened.ofstruct[3]])
            == ERROR_FILE_NOT_FOUND as u16
    {
        if let Some(mut fallback) = path
            .components
            .last()
            .filter(|leaf| leaf.source == runtime::Win16PathComponentSource::GuestInput)
            .cloned()
        {
            if let Some(name) = names::compressed_leaf(codec, &fallback.text)? {
                let mut compressed = path.clone();
                fallback.text = name.clone();
                fallback.source = runtime::Win16PathComponentSource::GuestInput;
                *compressed
                    .components
                    .last_mut()
                    .expect("existing LZ filename") = fallback;
                opened = super::win16_open_file::open(
                    filesystem,
                    files,
                    codec,
                    &compressed,
                    search_name.map(|_| name.as_str()),
                    style,
                    opened.ofstruct,
                )?;
            }
        }
    }
    let Some(source) = opened.file else {
        return Ok(Win16HostLzOpen {
            result: if opened.result < 0 { -1 } else { opened.result },
            file: None,
            ofstruct: opened.ofstruct,
        });
    };
    if !super::win16_compat_calls_lzexpand::is_lz_read_style(i32::from(style)) {
        return Ok(Win16HostLzOpen {
            result: 0,
            file: Some(source),
            ofstruct: opened.ofstruct,
        });
    }
    // LZInit duplicates this already-opened object with the same rights.
    // Its typed wrapper owns the private source too, so one close consumes
    // both identities even though only the stream receives a guest HFILE.
    match super::win16_compat_calls_lzexpand::init(files, source, true) {
        Ok(Win16HostLzInit::File(stream)) => Ok(Win16HostLzOpen {
            result: 0,
            file: Some(stream),
            ofstruct: opened.ofstruct,
        }),
        Ok(Win16HostLzInit::Error(error)) => {
            close_source(files, source)?;
            Ok(Win16HostLzOpen {
                result: error,
                file: None,
                ofstruct: opened.ofstruct,
            })
        }
        Err(error) => {
            close_source(files, source)?;
            Err(error)
        }
    }
}

pub(super) fn expanded_name(
    filesystem: &mut Filesystem,
    codec: GuestTextCodec,
    source: &[u8],
    path: &Win16GuestPath,
    search_name: Option<&str>,
) -> Result<Win16HostLzName, RuntimeError> {
    // GetExpandedName opens the requested name directly, without the
    // compressed-name retry or decompression performed by LZOpenFile.
    if super::win16_file_devices::name(path).is_some() {
        return Ok(Win16HostLzName::Error(-7));
    }
    let Ok(path) = super::win16_open_file::resolve_search_path(filesystem, path, search_name, 0)?
    else {
        return Ok(Win16HostLzName::Error(-7));
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let Ok(mut file) = filesystem.root.open_with(&path, &options) else {
        return Ok(Win16HostLzName::Error(-7));
    };
    let Ok(last) = query_header(&mut file) else {
        return Ok(Win16HostLzName::Error(-7));
    };
    // The private capability file is RAII-owned on every return. No guest
    // handle, OFSTRUCT limit, or local-time conversion is needed to query it.
    match names::expanded(codec, source, last) {
        Ok(name) => Ok(Win16HostLzName::Name(name)),
        Err(error) if matches!(error.kind(), Kind::InvalidInput | Kind::GuestFault) => {
            Ok(Win16HostLzName::Error(-7))
        }
        Err(error) => Err(error),
    }
}

fn query_header(file: &mut File) -> Result<Option<u8>, ()> {
    let handle = file.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: The private file remains retained through the metadata/read.
    // Non-disk objects fail this query without a potentially blocking read.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
    {
        return Err(());
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if size < SZDD_HEADER_LEN as u64 {
        return Ok(None);
    }
    let mut header = [0; SZDD_HEADER_LEN];
    if file.read(&mut header).map_err(|_| ())? != header.len() {
        return Err(());
    }
    inspect_szdd_header(&header)
        .map(|header| header.map(|header| header.last_character))
        .map_err(|_| ())
}

fn close_source(files: &mut Win16Files, file: Win16HostFile) -> Result<(), RuntimeError> {
    files.close_checked(file).map(|_| ()).map_err(|error| {
        RuntimeError::with_source(Kind::HostFailure, "close private LZ source file", error)
    })
}
