//! Owned Win16 COM, OLE and structured-storage requests.
//!
//! This file is intentionally separate from the central request catalog: the
//! catalog and dispatcher own their enum/wiring, while this module defines the
//! ABI-side values they can route here. Guest pointers remain FAR-address
//! tokens. No host pointer or borrowed guest memory crosses this boundary.

/// Bytes of a Windows GUID as stored in guest memory (`Data1`, `Data2`,
/// `Data3` little-endian followed by the eight `Data4` bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win16GuidBytes(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16GuidStringKind {
    Clsid,
    Iid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComRequest {
    Initialize {
        reserved: u32,
    },
    Uninitialize,
    BuildVersion,
    GetCurrentProcess,
    GetMalloc {
        context: u32,
        output: u32,
    },
    FreeUnusedLibraries,
    DisconnectObject {
        object: u32,
        reserved: u32,
    },
    LockObjectExternal {
        object: u32,
        lock: u16,
        last_unlock_releases: u16,
    },
    CreateGuid {
        output: u32,
    },
    GuidFromString {
        kind: Win16GuidStringKind,
        text: Vec<u8>,
        output: u32,
    },
    StringFromGuid {
        kind: Win16GuidStringKind,
        guid: Win16GuidBytes,
        output: u32,
        capacity: u16,
    },
    /// The legacy StringFromCLSID/StringFromIID contracts allocate an OLE
    /// string and write the resulting pointer through `output`.
    AllocateGuidString {
        kind: Win16GuidStringKind,
        guid: Win16GuidBytes,
        output: u32,
    },
    IsEqualGuid {
        left: Win16GuidBytes,
        right: Win16GuidBytes,
    },
    IsOle1Class {
        clsid: Win16GuidBytes,
    },
    ClsidFromProgId {
        progid: Vec<u8>,
        output: u32,
    },
    ProgIdFromClsid {
        clsid: Win16GuidBytes,
        output: u32,
    },
    GetTreatAsClass {
        clsid: Win16GuidBytes,
        output: u32,
    },
    TreatAsClass {
        clsid: Win16GuidBytes,
        treat_as: Win16GuidBytes,
    },
    CoCreateInstance {
        clsid: Win16GuidBytes,
        outer: u32,
        context: u32,
        iid: Win16GuidBytes,
        output: u32,
    },
    CoGetClassObject {
        clsid: Win16GuidBytes,
        context: u32,
        /// Guest COSERVERINFO far-address token. The host boundary never
        /// receives this address; runtime must validate/copy or reject it.
        server_info: u32,
        iid: Win16GuidBytes,
        output: u32,
    },
    CoFileTimeNow {
        output: u32,
    },
    CoFileTimeToDosDateTime {
        file_time: [u8; 8],
        date: u32,
        time: u32,
    },
    CoDosDateTimeToFileTime {
        date: u16,
        time: u16,
        output: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16OleRequest {
    Initialize {
        reserved: u32,
    },
    Uninitialize,
    Run {
        object: u32,
    },
    IsRunning {
        object: u32,
    },
    LockRunning {
        object: u32,
        lock: u16,
        last_unlock_closes: u16,
    },
    SetClipboard {
        data_object: u32,
    },
    GetClipboard {
        output: u32,
    },
    FlushClipboard,
    IsCurrentClipboard {
        data_object: u32,
    },
    QueryLinkFromData {
        data_object: u32,
    },
    QueryCreateFromData {
        data_object: u32,
    },
    SetContainedObject {
        object: u32,
        contained: u16,
    },
    NoteObjectVisible {
        object: u32,
        visible: u16,
    },
    CreateStreamOnHGlobal {
        global: u16,
        delete_on_release: u16,
        output: u32,
    },
    GetHGlobalFromStream {
        stream: u32,
        output: u32,
    },
    CreateLockBytesOnHGlobal {
        global: u16,
        delete_on_release: u16,
        output: u32,
    },
    GetHGlobalFromLockBytes {
        lock_bytes: u32,
        output: u32,
    },
    ReadClassStorage {
        storage: u32,
        output: u32,
    },
    WriteClassStorage {
        storage: u32,
        clsid: Win16GuidBytes,
    },
    ReadClassStream {
        stream: u32,
        output: u32,
    },
    WriteClassStream {
        stream: u32,
        clsid: Win16GuidBytes,
    },
    OleLoad {
        storage: u32,
        iid: Win16GuidBytes,
        client_site: u32,
        output: u32,
    },
    OleSave {
        persist_storage: u32,
        storage: u32,
        same_as_load: u16,
    },
    OleLoadFromStream {
        stream: u32,
        iid: Win16GuidBytes,
        output: u32,
    },
    OleSaveToStream {
        persist_stream: u32,
        stream: u32,
    },
    CreateBindContext {
        reserved: u32,
        output: u32,
    },
    GetRunningObjectTable {
        reserved: u32,
        output: u32,
    },
    CreateFileMoniker {
        path: Vec<u8>,
        output: u32,
    },
    CreateItemMoniker {
        delimiter: Vec<u8>,
        item: Vec<u8>,
        output: u32,
    },
    CreateGenericComposite {
        first: u32,
        rest: u32,
        output: u32,
    },
    BindMoniker {
        moniker: u32,
        options: u32,
        iid: Win16GuidBytes,
        output: u32,
    },
    ParseDisplayName {
        bind_context: u32,
        display_name: Vec<u8>,
        eaten: u32,
        output: u32,
    },
    DoAutoConvert {
        storage: u32,
        clsid_output: u32,
    },
    GetAutoConvert {
        clsid: Win16GuidBytes,
        output: u32,
    },
    SetAutoConvert {
        clsid: Win16GuidBytes,
        convert_to: Win16GuidBytes,
    },
    GetConvertStorage {
        storage: u32,
    },
    SetConvertStorage {
        storage: u32,
        converted: u16,
    },
    ReadFormatUserType {
        storage: u32,
        format_output: u32,
        user_type_output: u32,
    },
    WriteFormatUserType {
        storage: u32,
        format: u16,
        user_type: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16StorageRequest {
    CreateDocFile {
        path: Vec<u8>,
        mode: u32,
        reserved: u32,
        output: u32,
    },
    CreateDocFileOnLockBytes {
        lock_bytes: u32,
        mode: u32,
        reserved: u32,
        output: u32,
    },
    OpenStorage {
        path: Vec<u8>,
        priority_storage: u32,
        mode: u32,
        /// Win16 SNB far-address token. Runtime must decode this into owned
        /// UTF-16 names before crossing the host boundary.
        exclude: u32,
        reserved: u32,
        output: u32,
    },
    OpenStorageOnLockBytes {
        lock_bytes: u32,
        priority_storage: u32,
        mode: u32,
        /// Win16 SNB far-address token. Runtime must decode this into owned
        /// UTF-16 names before crossing the host boundary.
        exclude: u32,
        reserved: u32,
        output: u32,
    },
    IsStorageFile {
        path: Vec<u8>,
    },
    IsStorageLockBytes {
        lock_bytes: u32,
    },
    SetTimes {
        path: Vec<u8>,
        creation_time: Option<[u8; 8]>,
        access_time: Option<[u8; 8]>,
        modification_time: Option<[u8; 8]>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComOleRequest {
    Com(Win16ComRequest),
    Ole(Win16OleRequest),
    Storage(Win16StorageRequest),
}
