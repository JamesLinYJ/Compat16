//! Native Windows VER services plus checked Win16 NE resource extraction.

use super::guest_text::GuestTextCodec;
use compat_services::win16_ver::{
    VersionBlockError, VersionInfoTranscodeError, query_win16_ansi, transcode_win32_to_win16_ansi,
    version_info_extent,
};
use formats::{NeResource, NeResourceId, parse_ne};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostResourceName};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VFF_BUFFTOOSMALL, VIF_BUFFTOOSMALL, VerFindFileW,
    VerInstallFileW, VerLanguageNameW,
};
#[path = "win16_compat_calls_ver_text.rs"]
mod text;
use text::{
    checked_u16, checked_u32, grow_wide_capacity, guest_wide_z, guest_wide_z_required,
    wide_output_text, write_guest_string, zeroed_wide_buffer,
};

const MAX_VERSION_BLOCK_BYTES: usize = 64 * 1024 * 1024;
const MAX_VER_PATH_UNITS: usize = 32 * 1024;
const INITIAL_VER_PATH_UNITS: usize = 260;
const VERSION_RESOURCE_TYPE: u16 = 16;
const VERSION_RESOURCE_NAME: u16 = 1;

pub(super) fn resource_size(
    codec: GuestTextCodec,
    path: &[u8],
    resource_type: &Win16HostResourceName,
    resource_name: &Win16HostResourceName,
) -> Result<Option<(u32, u32)>, RuntimeError> {
    let Some((image, resource)) = load_ne_resource(codec, path, resource_type, resource_name)?
    else {
        return Ok(None);
    };
    let end = resource
        .file_offset
        .checked_add(resource.byte_length)
        .filter(|end| *end <= image.image.len())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "parsed Win16 NE resource exceeds its copied file image",
            )
        })?;
    let size = u32::try_from(resource.byte_length).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 NE resource size exceeds the DWORD result",
            error,
        )
    })?;
    let offset = u32::try_from(resource.file_offset).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 NE resource offset exceeds the DWORD result",
            error,
        )
    })?;
    if end < resource.file_offset {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "parsed Win16 NE resource range is reversed",
        ));
    }
    Ok(Some((size, offset)))
}

pub(super) fn resource(
    codec: GuestTextCodec,
    path: &[u8],
    resource_type: &Win16HostResourceName,
    resource_name: &Win16HostResourceName,
    offset: u32,
    count: u32,
    _initial: Vec<u8>,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let count = usize::try_from(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "Win16 NE resource count does not fit host memory",
            error,
        )
    })?;
    let (image, start, limit) = if offset == 0 {
        let Some((image, resource)) = load_ne_resource(codec, path, resource_type, resource_name)?
        else {
            return Ok(None);
        };
        let end = resource
            .file_offset
            .checked_add(resource.byte_length)
            .filter(|end| *end <= image.image.len())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "parsed Win16 NE resource exceeds its copied file image",
                )
            })?;
        (image, resource.file_offset, end)
    } else {
        // Win16 GetFileResource treats a nonzero dwFileOffset as an absolute
        // file offset. It seeks directly to that position and reads to EOF;
        // the resource type/name are consulted only when the offset is zero.
        let loaded = super::win16_module_files::read_module(codec, path, &[])?;
        let Ok(image) = loaded else {
            return Ok(None);
        };
        let start = usize::try_from(offset).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "Win16 resource file offset does not fit host memory",
                error,
            )
        })?;
        if start > image.image.len() {
            return Ok(Some(Vec::new()));
        }
        let end = image.image.len();
        (image, start, end)
    };
    let copied = count.min(limit - start);
    let slice_end = start.checked_add(copied).ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 NE resource copy range overflowed",
        )
    })?;
    let mut output = Vec::new();
    output.try_reserve_exact(copied).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 NE resource result",
            error,
        )
    })?;
    output.extend_from_slice(&image.image[start..slice_end]);
    Ok(Some(output))
}

fn native_file_info(
    codec: GuestTextCodec,
    path: &[u8],
) -> Result<Option<(Vec<u8>, u32)>, RuntimeError> {
    let Some(path_z) = guest_wide_z(codec, path, "Win16 GetFileVersionInfo path")? else {
        return Ok(None);
    };
    let mut handle = 0u32;
    // SAFETY: path_z is an owned NUL-terminated UTF-16 string and handle
    // points to a live local DWORD for this synchronous Windows call.
    let size = unsafe { GetFileVersionInfoSizeW(path_z.as_ptr(), &mut handle) };
    if size == 0 {
        return Ok(None);
    }
    let size = usize::try_from(size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "native version block size does not fit host memory",
            error,
        )
    })?;
    if size > MAX_VERSION_BLOCK_BYTES {
        return Ok(None);
    }
    let mut block = allocate_bounded(size, "native version information block")?;
    let capacity = u32::try_from(block.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "native version block length exceeds DWORD",
            error,
        )
    })?;
    // SAFETY: block has exactly the size advertised by Windows and is
    // exclusively owned writable storage for this synchronous call.
    if unsafe { GetFileVersionInfoW(path_z.as_ptr(), handle, capacity, block.as_mut_ptr().cast()) }
        == 0
    {
        return Ok(None);
    }
    Ok(Some((block, handle)))
}

fn convert_native_version_block(
    codec: GuestTextCodec,
    block: &[u8],
) -> Result<Option<Vec<u8>>, RuntimeError> {
    if let Some(header) = block.get(..2) {
        if let Ok(length) = version_info_extent(header, block.len()) {
            let ansi_block = &block[..length];
            match query_win16_ansi(ansi_block, b"\\") {
                Ok(Some(_)) => return copy_prefix(ansi_block, length).map(Some),
                Err(VersionBlockError::AllocationFailed) => {
                    return Err(RuntimeError::new(
                        Kind::ResourceExhausted,
                        "allocate Win16 version query tree",
                    ));
                }
                _ => {}
            }
        }
    }
    match transcode_win32_to_win16_ansi(block, |text| {
        Ok::<_, RuntimeError>(codec.from_wide(text)?.bytes)
    }) {
        Ok(block) => Ok(Some(block)),
        Err(VersionInfoTranscodeError::Block(VersionBlockError::AllocationFailed)) => {
            Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "allocate converted version-information tree",
            ))
        }
        Err(VersionInfoTranscodeError::Block(_)) => Ok(None),
        Err(VersionInfoTranscodeError::Text(error)) => Err(error),
    }
}

pub(super) fn file_info_size(
    codec: GuestTextCodec,
    path: &[u8],
) -> Result<Option<(u32, u32)>, RuntimeError> {
    if let Some((native, handle)) = native_file_info(codec, path)? {
        let Some(win16) = convert_native_version_block(codec, &native)? else {
            return Ok(None);
        };
        let size = u32::try_from(win16.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 converted version block exceeds DWORD",
                error,
            )
        })?;
        return Ok(Some((size, handle)));
    }

    // Win16 GetFileVersionInfoSize reports the VERSION/1 resource size and
    // stores its absolute file offset in the legacy handle field.
    resource_size(
        codec,
        path,
        &Win16HostResourceName::Id(VERSION_RESOURCE_TYPE),
        &Win16HostResourceName::Id(VERSION_RESOURCE_NAME),
    )
}

pub(super) fn file_info(
    codec: GuestTextCodec,
    path: &[u8],
    _handle: u32,
    initial: Vec<u8>,
) -> Result<Option<(Vec<u8>, u32)>, RuntimeError> {
    let capacity = initial.len();
    if let Some((native, _handle)) = native_file_info(codec, path)? {
        let Some(full) = convert_native_version_block(codec, &native)? else {
            return Ok(None);
        };
        let copied = capacity.min(full.len());
        return Ok(Some((copy_prefix(&full, copied)?, copied as u32)));
    }

    let count = u32::try_from(capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "Win16 version output capacity exceeds DWORD",
            error,
        )
    })?;
    let fallback = resource(
        codec,
        path,
        &Win16HostResourceName::Id(VERSION_RESOURCE_TYPE),
        &Win16HostResourceName::Id(VERSION_RESOURCE_NAME),
        0,
        count,
        initial,
    )?;
    let Some(bytes) = fallback else {
        return Ok(None);
    };
    let copied = u32::try_from(bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "Win16 version resource copy exceeds DWORD",
            error,
        )
    })?;
    Ok(Some((bytes, copied)))
}

pub(super) fn query_value(
    block: Vec<u8>,
    sub_block: &[u8],
) -> Result<Option<(usize, u32)>, RuntimeError> {
    if sub_block.contains(&0) {
        return Ok(None);
    }
    match query_win16_ansi(&block, sub_block) {
        Ok(Some(value)) => Ok(Some((value.offset, value.length))),
        Ok(None) | Err(VersionBlockError::NotWin16VersionBlock) => Ok(None),
        Err(VersionBlockError::AllocationFailed) => Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "allocate Win16 version query tree",
        )),
        Err(_) => Ok(None),
    }
}

pub(super) fn find_file(
    codec: GuestTextCodec,
    flags: u16,
    file: &[u8],
    windows_dir: &[u8],
    app_dir: &[u8],
    mut current_buffer: Vec<u8>,
    current_capacity: u16,
    mut destination_buffer: Vec<u8>,
    destination_capacity: u16,
) -> Result<(u32, Vec<u8>, u16, Vec<u8>, u16), RuntimeError> {
    let file_z = guest_wide_z_required(codec, file, "Win16 VerFindFile filename")?;
    let windows_z =
        guest_wide_z_required(codec, windows_dir, "Win16 VerFindFile Windows directory")?;
    let app_z = guest_wide_z_required(codec, app_dir, "Win16 VerFindFile application directory")?;
    if current_buffer.len() != usize::from(current_capacity)
        || destination_buffer.len() != usize::from(destination_capacity)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 VerFindFile host buffers do not match their guest capacities",
        ));
    }
    let mut current_native = zeroed_wide_buffer(INITIAL_VER_PATH_UNITS)?;
    let mut destination_native = zeroed_wide_buffer(INITIAL_VER_PATH_UNITS)?;
    let mut status: u32;
    let (current_length, destination_length) = loop {
        let mut current_length = checked_u32(
            current_native.len(),
            "VerFindFileW current directory capacity",
        )?;
        let mut destination_length = checked_u32(
            destination_native.len(),
            "VerFindFileW destination directory capacity",
        )?;
        // The wide API counts UTF-16 characters, while the Win16 buffers are
        // byte-counted in the selected guest code page. Use bounded wide
        // scratch, then apply the guest byte capacities after conversion.
        // SAFETY: Inputs are owned, NUL-terminated UTF-16 strings. Output
        // vectors are initialized and their unit capacities match the lengths.
        status = unsafe {
            VerFindFileW(
                u32::from(flags),
                file_z.as_ptr(),
                windows_z.as_ptr(),
                app_z.as_ptr(),
                current_native.as_mut_ptr(),
                &mut current_length,
                destination_native.as_mut_ptr(),
                &mut destination_length,
            )
        };
        let current_needed = usize::try_from(current_length).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "VerFindFileW current directory length does not fit host memory",
                error,
            )
        })?;
        let destination_needed = usize::try_from(destination_length).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "VerFindFileW destination directory length does not fit host memory",
                error,
            )
        })?;
        let api_too_small = status & VFF_BUFFTOOSMALL != 0;
        let current_too_small = current_needed > current_native.len();
        let destination_too_small = destination_needed > destination_native.len();
        let native_too_small = current_too_small || destination_too_small || api_too_small;
        if !native_too_small {
            break (current_length, destination_length);
        }
        if current_native.len() >= MAX_VER_PATH_UNITS
            && destination_native.len() >= MAX_VER_PATH_UNITS
        {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "VerFindFileW output exceeds the bounded UTF-16 path capacity",
            ));
        }
        let current_capacity = grow_wide_capacity(
            current_native.len(),
            current_needed,
            api_too_small && !current_too_small && current_native.len() < MAX_VER_PATH_UNITS,
            "VerFindFileW current directory",
        )?;
        let destination_capacity = grow_wide_capacity(
            destination_native.len(),
            destination_needed,
            api_too_small
                && !destination_too_small
                && destination_native.len() < MAX_VER_PATH_UNITS,
            "VerFindFileW destination directory",
        )?;
        current_native = zeroed_wide_buffer(current_capacity)?;
        destination_native = zeroed_wide_buffer(destination_capacity)?;
    };

    let current_wide = wide_output_text(
        &current_native,
        current_length,
        "VerFindFileW current directory",
    )?;
    let destination_wide = wide_output_text(
        &destination_native,
        destination_length,
        "VerFindFileW destination directory",
    )?;
    let (current_required, current_truncated) = write_guest_string(
        codec,
        current_wide,
        &mut current_buffer,
        "VerFindFile current directory",
    )?;
    let (destination_required, destination_truncated) = write_guest_string(
        codec,
        destination_wide,
        &mut destination_buffer,
        "VerFindFile destination directory",
    )?;
    if current_truncated || destination_truncated {
        status |= VFF_BUFFTOOSMALL;
    }
    Ok((
        status,
        current_buffer,
        checked_u16(current_required, "VerFindFile current directory byte count")?,
        destination_buffer,
        checked_u16(
            destination_required,
            "VerFindFile destination directory byte count",
        )?,
    ))
}

pub(super) fn install_file(
    codec: GuestTextCodec,
    flags: u16,
    source: &[u8],
    destination: &[u8],
    source_dir: &[u8],
    destination_dir: &[u8],
    current_dir: &[u8],
    mut temporary_buffer: Vec<u8>,
    capacity: u16,
) -> Result<(u32, Vec<u8>, u16), RuntimeError> {
    let source_z = guest_wide_z_required(codec, source, "Win16 VerInstallFile source filename")?;
    let destination_z = guest_wide_z_required(
        codec,
        destination,
        "Win16 VerInstallFile destination filename",
    )?;
    let source_dir_z =
        guest_wide_z_required(codec, source_dir, "Win16 VerInstallFile source directory")?;
    let destination_dir_z = guest_wide_z_required(
        codec,
        destination_dir,
        "Win16 VerInstallFile destination directory",
    )?;
    let current_dir_z =
        guest_wide_z_required(codec, current_dir, "Win16 VerInstallFile current directory")?;
    if temporary_buffer.len() != usize::from(capacity) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 VerInstallFile host buffer does not match its guest capacity",
        ));
    }
    // VerInstallFileW can modify files. Give its one call the maximum bounded
    // wide scratch so a guest DBCS/UTF-8 byte capacity cannot trigger a second,
    // side-effecting retry just to discover the full temporary pathname.
    let mut native_buffer = zeroed_wide_buffer(MAX_VER_PATH_UNITS)?;
    let mut native_length = checked_u32(
        native_buffer.len(),
        "VerInstallFileW temporary filename capacity",
    )?;
    // SAFETY: All path arguments are owned NUL-terminated UTF-16 strings. The
    // output vector has the exact UTF-16 capacity advertised by its DWORD.
    let status = unsafe {
        VerInstallFileW(
            u32::from(flags),
            source_z.as_ptr(),
            destination_z.as_ptr(),
            source_dir_z.as_ptr(),
            destination_dir_z.as_ptr(),
            current_dir_z.as_ptr(),
            native_buffer.as_mut_ptr(),
            &mut native_length,
        )
    };
    let required_units = usize::try_from(native_length).map_err(|error| {
        RuntimeError::with_source(
            Kind::InvalidInput,
            "VerInstallFileW temporary filename length does not fit host memory",
            error,
        )
    })?;
    if required_units > native_buffer.len() {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "VerInstallFileW temporary filename exceeds the bounded UTF-16 path capacity",
        ));
    }
    let wide = wide_output_text(
        &native_buffer,
        native_length,
        "VerInstallFileW temporary filename",
    )?;
    let (required_bytes, truncated) = write_guest_string(
        codec,
        wide,
        &mut temporary_buffer,
        "VerInstallFile temporary filename",
    )?;
    let status = if truncated {
        status | VIF_BUFFTOOSMALL
    } else {
        status
    };
    Ok((
        status,
        temporary_buffer,
        checked_u16(required_bytes, "VerInstallFile guest byte count")?,
    ))
}

pub(super) fn language_name(
    codec: GuestTextCodec,
    language: u16,
    mut output: Vec<u8>,
) -> Result<(Vec<u8>, u32), RuntimeError> {
    let capacity = output.len();
    let mut native = zeroed_wide_buffer(MAX_VER_PATH_UNITS)?;
    let capacity_u32 = checked_u32(native.len(), "VerLanguageNameW output capacity")?;
    // SAFETY: `native` owns the advertised UTF-16 output capacity; the W API
    // returns a count excluding NUL, unlike VerFindFile/VerInstallFile lengths.
    let copied =
        unsafe { VerLanguageNameW(u32::from(language), native.as_mut_ptr(), capacity_u32) };
    if copied == 0 {
        return Ok((output, 0));
    }
    let copied = usize::try_from(copied).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "VerLanguageNameW count does not fit host memory",
            error,
        )
    })?;
    if copied >= native.len() || native[copied] != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "VerLanguageNameW returned an incomplete or unterminated language name",
        ));
    }
    let copied_guest = if capacity == 0 {
        0
    } else {
        // VerLanguageName reports bytes actually copied, excluding NUL. The
        // file-version APIs use required sizes instead and share a different
        // output helper; preserve a complete DBCS prefix here.
        let encoded = codec.from_wide_bounded(&native[..copied], capacity - 1)?;
        let written = encoded.bytes.len();
        output[..written].copy_from_slice(&encoded.bytes);
        output[written] = 0;
        written
    };
    Ok((
        output,
        checked_u32(copied_guest, "VerLanguageName guest byte count")?,
    ))
}

fn load_ne_resource(
    codec: GuestTextCodec,
    path: &[u8],
    resource_type: &Win16HostResourceName,
    resource_name: &Win16HostResourceName,
) -> Result<Option<(runtime::Win16ModuleImage, NeResource)>, RuntimeError> {
    let loaded = super::win16_module_files::read_module(codec, path, &[])?;
    let Ok(image) = loaded else {
        return Ok(None);
    };
    let Ok(module) = parse_ne(&image.image) else {
        return Ok(None);
    };
    let type_id = resource_id(resource_type);
    let name_id = resource_id(resource_name);
    for group in module.resource_types {
        if !resource_ids_match(&group.id, &type_id) {
            continue;
        }
        if let Some(resource) = group
            .resources
            .into_iter()
            .find(|resource| resource_ids_match(&resource.id, &name_id))
        {
            return Ok(Some((image, resource)));
        }
    }
    Ok(None)
}

fn resource_id(name: &Win16HostResourceName) -> NeResourceId {
    match name {
        Win16HostResourceName::Id(id) => NeResourceId::Numeric(*id),
        Win16HostResourceName::Name(bytes) => NeResourceId::Name(bytes.clone()),
    }
}

fn resource_ids_match(left: &NeResourceId, right: &NeResourceId) -> bool {
    match (left, right) {
        (NeResourceId::Numeric(left), NeResourceId::Numeric(right)) => left == right,
        (NeResourceId::Name(left), NeResourceId::Name(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

fn allocate_bounded(length: usize, operation: &'static str) -> Result<Vec<u8>, RuntimeError> {
    if length > MAX_VERSION_BLOCK_BYTES {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            format!("{operation} exceeds the bounded 64 MiB host copy limit"),
        ));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            format!("allocate {operation}"),
            error,
        )
    })?;
    output.resize(length, 0);
    Ok(output)
}

fn copy_prefix(source: &[u8], length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy Win16 version information result",
            error,
        )
    })?;
    output.extend_from_slice(&source[..length]);
    Ok(output)
}

#[cfg(test)]
#[path = "win16_compat_calls_ver_tests.rs"]
mod tests;
