//! Checked ABI decoder for the Win16 COM/OLE/storage services implemented by
//! the COM batch. Routing keys are the catalog's normalized module and
//! ordinal; names and stack widths remain owned by the export catalog.

use guest_core::GuestMemory;

use crate::{SelectorTable, Win16Argument, Win16Error};

use super::request::com_ole::{
    Win16ComOleRequest as Request, Win16ComRequest as ComRequest, Win16GuidBytes,
    Win16GuidStringKind as GuidStringKind, Win16OleRequest as OleRequest,
    Win16StorageRequest as StorageRequest,
};

/// Decode one explicitly implemented family entry. `Ok(None)` means that the
/// catalogued function has a known ABI but this service subset does not yet
/// implement it; callers must preserve the normal unsupported-export result.
/// Source stubs and unknown signatures are not accepted here.
pub fn decode_com_ole(
    module: &str,
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let module = module.to_ascii_uppercase();
    let decoded = match module.as_str() {
        "COMPOBJ" => decode_compobj(ordinal, arguments, selectors, memory)?,
        "OLE2" => decode_ole2(ordinal, arguments, selectors, memory)?,
        "STORAGE" => decode_storage(ordinal, arguments, selectors, memory)?,
        _ => None,
    };
    Ok(decoded)
}

fn decode_compobj(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match ordinal {
        1 if arguments.is_empty() => ComRequest::BuildVersion,
        2 => ComRequest::Initialize {
            reserved: dword(arguments, 0)?,
        },
        3 if arguments.is_empty() => ComRequest::Uninitialize,
        4 => ComRequest::GetMalloc {
            context: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        7 => ComRequest::CoGetClassObject {
            clsid: guid(arguments, 0, selectors, memory)?,
            context: dword(arguments, 1)?,
            server_info: dword(arguments, 2)?,
            iid: guid(arguments, 3, selectors, memory)?,
            output: dword(arguments, 4)?,
        },
        15 => ComRequest::DisconnectObject {
            object: dword(arguments, 0)?,
            reserved: dword(arguments, 1)?,
        },
        17 if arguments.is_empty() => ComRequest::FreeUnusedLibraries,
        13 => ComRequest::CoCreateInstance {
            clsid: guid(arguments, 0, selectors, memory)?,
            outer: dword(arguments, 1)?,
            context: dword(arguments, 2)?,
            iid: guid(arguments, 3, selectors, memory)?,
            output: dword(arguments, 4)?,
        },
        14 => ComRequest::AllocateGuidString {
            kind: GuidStringKind::Iid,
            guid: guid(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        18 => ComRequest::IsEqualGuid {
            left: guid(arguments, 0, selectors, memory)?,
            right: guid(arguments, 1, selectors, memory)?,
        },
        19 => ComRequest::AllocateGuidString {
            kind: GuidStringKind::Clsid,
            guid: guid(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        20 | 69 => ComRequest::GuidFromString {
            kind: if ordinal == 20 {
                GuidStringKind::Clsid
            } else {
                GuidStringKind::Iid
            },
            text: far_string(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        34 if arguments.is_empty() => ComRequest::GetCurrentProcess,
        36 => ComRequest::IsOle1Class {
            clsid: guid(arguments, 0, selectors, memory)?,
        },
        61 => ComRequest::ClsidFromProgId {
            progid: far_string(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        62 => ComRequest::ProgIdFromClsid {
            clsid: guid(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        63 => ComRequest::LockObjectExternal {
            object: dword(arguments, 0)?,
            lock: word(arguments, 1)?,
            last_unlock_releases: word(arguments, 2)?,
        },
        65 => ComRequest::GetTreatAsClass {
            clsid: guid(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        66 => ComRequest::TreatAsClass {
            clsid: guid(arguments, 0, selectors, memory)?,
            treat_as: guid(arguments, 1, selectors, memory)?,
        },
        73 => ComRequest::CreateGuid {
            output: dword(arguments, 0)?,
        },
        76 => ComRequest::StringFromGuid {
            kind: GuidStringKind::Clsid,
            guid: guid(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
            capacity: word(arguments, 2)?,
        },
        82 => ComRequest::CoFileTimeNow {
            output: dword(arguments, 0)?,
        },
        30 => ComRequest::CoFileTimeToDosDateTime {
            file_time: fixed_guest::<8>(dword(arguments, 0)?, selectors, memory)?,
            date: dword(arguments, 1)?,
            time: dword(arguments, 2)?,
        },
        31 => ComRequest::CoDosDateTimeToFileTime {
            date: word(arguments, 0)?,
            time: word(arguments, 1)?,
            output: dword(arguments, 2)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(Request::Com(request)))
}

fn decode_ole2(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match ordinal {
        2 => OleRequest::Initialize {
            reserved: dword(arguments, 0)?,
        },
        3 if arguments.is_empty() => OleRequest::Uninitialize,
        14 => OleRequest::Run {
            object: dword(arguments, 0)?,
        },
        16 => OleRequest::IsRunning {
            object: dword(arguments, 0)?,
        },
        17 => OleRequest::LockRunning {
            object: dword(arguments, 0)?,
            lock: word(arguments, 1)?,
            last_unlock_closes: word(arguments, 2)?,
        },
        12 => OleRequest::OleLoad {
            storage: dword(arguments, 0)?,
            iid: guid(arguments, 1, selectors, memory)?,
            client_site: dword(arguments, 2)?,
            output: dword(arguments, 3)?,
        },
        13 => OleRequest::OleSave {
            persist_storage: dword(arguments, 0)?,
            storage: dword(arguments, 1)?,
            same_as_load: word(arguments, 2)?,
        },
        24 => OleRequest::OleSaveToStream {
            persist_stream: dword(arguments, 0)?,
            stream: dword(arguments, 1)?,
        },
        25 => OleRequest::OleLoadFromStream {
            stream: dword(arguments, 0)?,
            iid: guid(arguments, 1, selectors, memory)?,
            output: dword(arguments, 2)?,
        },
        18 => OleRequest::ReadClassStorage {
            storage: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        19 => OleRequest::WriteClassStorage {
            storage: dword(arguments, 0)?,
            clsid: guid(arguments, 1, selectors, memory)?,
        },
        20 => OleRequest::ReadClassStream {
            stream: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        21 => OleRequest::WriteClassStream {
            stream: dword(arguments, 0)?,
            clsid: guid(arguments, 1, selectors, memory)?,
        },
        49 => OleRequest::SetClipboard {
            data_object: dword(arguments, 0)?,
        },
        50 => OleRequest::GetClipboard {
            output: dword(arguments, 0)?,
        },
        76 if arguments.is_empty() => OleRequest::FlushClipboard,
        77 => OleRequest::IsCurrentClipboard {
            data_object: dword(arguments, 0)?,
        },
        6 => OleRequest::QueryLinkFromData {
            data_object: dword(arguments, 0)?,
        },
        7 => OleRequest::QueryCreateFromData {
            data_object: dword(arguments, 0)?,
        },
        22 => OleRequest::BindMoniker {
            moniker: dword(arguments, 0)?,
            options: dword(arguments, 1)?,
            iid: guid(arguments, 2, selectors, memory)?,
            output: dword(arguments, 3)?,
        },
        23 => OleRequest::ParseDisplayName {
            bind_context: dword(arguments, 0)?,
            display_name: far_string(arguments, 1, selectors, memory)?,
            eaten: dword(arguments, 2)?,
            output: dword(arguments, 3)?,
        },
        26 => OleRequest::CreateBindContext {
            reserved: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        27 => OleRequest::CreateItemMoniker {
            delimiter: far_string(arguments, 0, selectors, memory)?,
            item: far_string(arguments, 1, selectors, memory)?,
            output: dword(arguments, 2)?,
        },
        28 => OleRequest::CreateFileMoniker {
            path: far_string(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        29 => OleRequest::CreateGenericComposite {
            first: dword(arguments, 0)?,
            rest: dword(arguments, 1)?,
            output: dword(arguments, 2)?,
        },
        30 => OleRequest::GetRunningObjectTable {
            reserved: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        74 => OleRequest::ReadFormatUserType {
            storage: dword(arguments, 0)?,
            format_output: dword(arguments, 1)?,
            user_type_output: dword(arguments, 2)?,
        },
        75 => OleRequest::WriteFormatUserType {
            storage: dword(arguments, 0)?,
            format: word(arguments, 1)?,
            user_type: far_string(arguments, 2, selectors, memory)?,
        },
        79 => OleRequest::DoAutoConvert {
            storage: dword(arguments, 0)?,
            clsid_output: dword(arguments, 1)?,
        },
        80 => OleRequest::GetAutoConvert {
            clsid: guid(arguments, 0, selectors, memory)?,
            output: dword(arguments, 1)?,
        },
        81 => OleRequest::SetAutoConvert {
            clsid: guid(arguments, 0, selectors, memory)?,
            convert_to: guid(arguments, 1, selectors, memory)?,
        },
        82 => OleRequest::GetConvertStorage {
            storage: dword(arguments, 0)?,
        },
        83 => OleRequest::SetConvertStorage {
            storage: dword(arguments, 0)?,
            converted: word(arguments, 1)?,
        },
        84 => OleRequest::CreateStreamOnHGlobal {
            global: word(arguments, 0)?,
            delete_on_release: word(arguments, 1)?,
            output: dword(arguments, 2)?,
        },
        85 => OleRequest::GetHGlobalFromStream {
            stream: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        54 => OleRequest::CreateLockBytesOnHGlobal {
            global: word(arguments, 0)?,
            delete_on_release: word(arguments, 1)?,
            output: dword(arguments, 2)?,
        },
        55 => OleRequest::GetHGlobalFromLockBytes {
            lock_bytes: dword(arguments, 0)?,
            output: dword(arguments, 1)?,
        },
        86 => OleRequest::SetContainedObject {
            object: dword(arguments, 0)?,
            contained: word(arguments, 1)?,
        },
        87 => OleRequest::NoteObjectVisible {
            object: dword(arguments, 0)?,
            visible: word(arguments, 1)?,
        },
        86 => OleRequest::SetContainedObject {
            object: dword(arguments, 0)?,
            contained: word(arguments, 1)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(Request::Ole(request)))
}

fn decode_storage(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Request>, Win16Error> {
    let request = match ordinal {
        1 => StorageRequest::CreateDocFile {
            path: far_string(arguments, 0, selectors, memory)?,
            mode: dword(arguments, 1)?,
            reserved: dword(arguments, 2)?,
            output: dword(arguments, 3)?,
        },
        2 => StorageRequest::CreateDocFileOnLockBytes {
            lock_bytes: dword(arguments, 0)?,
            mode: dword(arguments, 1)?,
            reserved: dword(arguments, 2)?,
            output: dword(arguments, 3)?,
        },
        3 => StorageRequest::OpenStorage {
            path: far_string(arguments, 0, selectors, memory)?,
            priority_storage: dword(arguments, 1)?,
            mode: dword(arguments, 2)?,
            exclude: dword(arguments, 3)?,
            reserved: dword(arguments, 4)?,
            output: dword(arguments, 5)?,
        },
        4 => StorageRequest::OpenStorageOnLockBytes {
            lock_bytes: dword(arguments, 0)?,
            priority_storage: dword(arguments, 1)?,
            mode: dword(arguments, 2)?,
            exclude: dword(arguments, 3)?,
            reserved: dword(arguments, 4)?,
            output: dword(arguments, 5)?,
        },
        5 => StorageRequest::IsStorageFile {
            path: far_string(arguments, 0, selectors, memory)?,
        },
        6 => StorageRequest::IsStorageLockBytes {
            lock_bytes: dword(arguments, 0)?,
        },
        7 => StorageRequest::SetTimes {
            path: far_string(arguments, 0, selectors, memory)?,
            creation_time: optional_fixed_guest::<8>(dword(arguments, 1)?, selectors, memory)?,
            access_time: optional_fixed_guest::<8>(dword(arguments, 2)?, selectors, memory)?,
            modification_time: optional_fixed_guest::<8>(dword(arguments, 3)?, selectors, memory)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(Request::Storage(request)))
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn far_string(
    arguments: &[Win16Argument],
    index: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    crate::strings::read_ansi_z(
        selectors,
        memory,
        dword(arguments, index)?,
        crate::exports::MAX_WIN16_STRING_BYTES,
    )
}

fn guid(
    arguments: &[Win16Argument],
    index: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16GuidBytes, Win16Error> {
    fixed_guest::<16>(dword(arguments, index)?, selectors, memory).map(Win16GuidBytes)
}

fn fixed_guest<const N: usize>(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<[u8; N], Win16Error> {
    let pointer = selectors.pointer_from_far(far)?;
    let mut bytes = [0; N];
    selectors.read(memory, pointer, &mut bytes)?;
    Ok(bytes)
}

fn optional_fixed_guest<const N: usize>(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<[u8; N]>, Win16Error> {
    if far == 0 {
        Ok(None)
    } else {
        fixed_guest(far, selectors, memory).map(Some)
    }
}
