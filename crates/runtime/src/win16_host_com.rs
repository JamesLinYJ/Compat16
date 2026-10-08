//! Owned host-boundary values for Win16 COM, OLE, and structured storage.
//!
//! Guest FAR tokens are resolved by the runtime before a request is sent here.
//! Returned COM interfaces use opaque host object identities; native pointers
//! stay in the Windows adapter.

use compat_services::com::{ComObjectId, Guid, ReferenceDisposition};
use crate::DiagnosticKind;

/// One native COM/OLE operation submitted to its owning USER STA. `generation`
/// distinguishes a later operation if an owner recycles a numeric operation
/// slot; neither field is a guest handle or pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ComHostOperationIdentity {
    pub id: u64,
    pub generation: u64,
}

impl Win16ComHostOperationIdentity {
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.generation != 0
    }
}

/// A specific incarnation of the host COM/USER owner. Callback frames from an
/// earlier worker incarnation cannot be resumed on a replacement STA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ComHostOwnerIdentity {
    pub id: u64,
    pub generation: u64,
}

impl Win16ComHostOwnerIdentity {
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.generation != 0
    }
}

/// Explicitly end one COM owner incarnation. Seal stops admission without
/// releasing objects; Poll reports retirement only after its native stacks
/// and acknowledged operation journals have drained. The owner cannot be
/// reused for subsequent COM work after sealing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ComHostShutdownOperation {
    Seal,
    Poll,
}

/// Completed native owner retirement. A callback cancellation alone cannot
/// produce this receipt: native objects must have been released on their
/// owning STA. The worker's permanent apartment lease remains owned until
/// USER worker shutdown, so window cleanup can still use its initialized STA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ComHostShutdownReceipt {
    pub owner: Win16ComHostOwnerIdentity,
    pub callback_ingress_closed: bool,
    pub native_objects_shutdown: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ComHostShutdownStep {
    Sealed { owner: Win16ComHostOwnerIdentity },
    Pending { owner: Win16ComHostOwnerIdentity },
    Retired(Win16ComHostShutdownReceipt),
}

/// Identity of one synchronous COM callback suspended through the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ComHostCallbackFrame(pub u64);

/// The runtime-facing projection of a native COM callback. Native interface
/// pointers and guest FAR pointers remain in their respective owner layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostCallbackStep {
    pub frame: Win16ComHostCallbackFrame,
    pub parent: Option<Win16ComHostOperationIdentity>,
    pub owner: Win16ComHostOwnerIdentity,
    /// Runtime-allocated OLE1 callback route supplied when the native proxy
    /// was created. It identifies the guest object/client without carrying a
    /// guest FAR address through the host bridge.
    pub route: Win16ComHostCallbackRoute,
    pub callback: Win16ComHostCallbackCall,
}

impl Win16ComHostCallbackStep {
    pub fn has_valid_identity(&self) -> bool {
        self.frame.0 != 0
            && self.owner.is_valid()
            && self.route.0 != 0
            && self.parent.is_none_or(Win16ComHostOperationIdentity::is_valid)
    }
}

/// Typed COM callbacks needed by OLE1 client projections. The native COM
/// method kind is preserved because HRESULT methods and void notification
/// methods have different completion contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostCallbackCall {
    /// A container-save request from COM. This is not the OLE1 `OLE_SAVED`
    /// notification; the route handler must perform or reject persistence and
    /// return the resulting HRESULT without synthesizing that notification.
    ClientSiteSaveObject {
        site: ComObjectId,
        object: Option<ComObjectId>,
    },
    AdviseSink {
        sink: ComObjectId,
        object: Option<ComObjectId>,
        method: Win16ComHostAdviseSinkCall,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostAdviseSinkCall {
    OnDataChange {
        format: Win16ComHostFormatEtc,
        /// Callback-scoped identity for the native medium. It is never a
        /// native pointer and is retired when the exact callback frame resumes.
        medium: Win16ComHostMediumId,
        /// Deep-copied media supported by this host adapter. For interface
        /// media or native resources this is None; `medium` remains the
        /// callback-scoped identity and the OLE1 notification does not claim
        /// that the guest can dereference the native resource.
        payload: Option<Win16ComHostStorageMedium>,
        tymed: u32,
    },
    OnViewChange { aspect: u32, index: i32 },
    /// The host resolves the COM moniker while still on the owning STA and
    /// sends copied UTF-16. It never forwards an IMoniker pointer.
    OnRename { display_name: Vec<u16> },
    OnSave,
    OnClose,
}

/// Owned native FORMATETC projection. `target_device`, when present, contains
/// a complete host Windows DVTARGETDEVICE record produced by the adapter.
/// Win16 OLE1 OLETARGETDEVICE and Win16 DEVMODE records have separate guest
/// layouts and must be converted field by field before crossing this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostFormatEtc {
    pub format: u16,
    pub target_device: Option<Vec<u8>>,
    pub aspect: u32,
    pub index: i32,
    pub tymed: u32,
}

/// Host-only identity for a callback-scoped native STGMEDIUM. The USER STA
/// owns its lifetime; callers may not retain or reinterpret it as a pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ComHostMediumId(pub u64);

/// Owner-table identity for a native STGMEDIUM retained beyond IDataObject's
/// GetData call. Owner generation is embedded and numeric IDs are never reused
/// in this process, so stale tokens cannot release resources from a later STA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ComHostOwnedMediumId {
    pub owner: Win16ComHostOwnerIdentity,
    pub id: u64,
}

impl Win16ComHostOwnedMediumId {
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.owner.is_valid()
    }
}

/// Runtime-owned callback route for one guest OLE1 object. The value is
/// allocated by the runtime and lets the host report callbacks without
/// receiving a guest FAR pointer or a CPU-specific callback frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ComHostCallbackRoute(pub u64);

/// Exact callback reply domains. The OLE1 client's WORD result is retained
/// separately from COM HRESULTs; AdviseSink itself has a void native ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ComHostCallbackReply {
    ClientSiteSaveObjectHresult(u32),
    AdviseSinkClientWord(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ComHostCallbackFailureKind {
    CheckedGuestCallback,
    CallbackRouteUnavailable,
    CallbackTransport,
    InvalidNativeCallbackArguments,
    CallbackImplementation,
}

/// Owned failure details from checked guest callback execution or callback
/// transport. `context` preserves the runtime's original diagnostic text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostCallbackFailure {
    pub kind: Win16ComHostCallbackFailureKind,
    pub context: String,
}

/// One checked-callback failure retained by its parent native operation.
/// The route remains explicit when an operation invokes more than one proxy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostOperationFailure {
    pub route: Win16ComHostCallbackRoute,
    pub failure: Win16ComHostCallbackFailure,
}

/// Root cause when a native operation could not produce a result after one or
/// more checked callbacks had already failed. The classification remains a
/// runtime diagnostic kind; `context` owns the complete formatted source
/// chain so the callback journal is not allowed to hide the native failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostExecutionFailure {
    pub kind: DiagnosticKind,
    pub context: String,
}

/// Native callback outcome. A checked guest failure is never converted into a
/// synthetic HRESULT or WORD merely to unblock the native call stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostCallbackOutcome {
    Reply(Win16ComHostCallbackReply),
    Failed(Win16ComHostCallbackFailure),
}

/// A terminal result is emitted only after the native COM/OLE API has returned
/// and its owner has reconciled callback frames and native interface leases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostCompletion {
    pub operation: Win16ComHostOperationIdentity,
    pub result: Win16ComHostResult,
}

/// Result of one start/continue step. `Callback` suspends a synchronous native
/// call until that exact frame is resumed. `CallbackFrameComplete` retires an
/// unsolicited callback only; it is not an API-operation completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostStep {
    Running(Win16ComHostOperationIdentity),
    Callback(Win16ComHostCallbackStep),
    Complete(Win16ComHostCompletion),
    CallbackFrameComplete {
        frame: Win16ComHostCallbackFrame,
        owner: Win16ComHostOwnerIdentity,
    },
    CallbackFailed {
        frame: Option<Win16ComHostCallbackFrame>,
        parent: Option<Win16ComHostOperationIdentity>,
        owner: Win16ComHostOwnerIdentity,
        route: Win16ComHostCallbackRoute,
        failure: Win16ComHostCallbackFailure,
    },
    OperationFailed {
        operation: Win16ComHostOperationIdentity,
        failures: Vec<Win16ComHostOperationFailure>,
        /// A native method may return an owned interface or medium while a
        /// void callback has failed. Preserve that exact result so the runtime
        /// can release its owner-bound resources instead of dropping tokens.
        /// The consumer must reconcile Owned interfaces and medium tokens on
        /// this operation's USER STA before discarding the terminal step.
        result: Option<Win16ComHostResult>,
        /// Present when the native method also failed. Its formatted context
        /// includes the original RuntimeError source chain.
        execution_failure: Option<Win16ComHostExecutionFailure>,
    },
}

/// Resume token submitted only after the runtime's checked guest callback has
/// returned. All identity fields must match the suspended native frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostResume {
    pub frame: Win16ComHostCallbackFrame,
    pub parent: Option<Win16ComHostOperationIdentity>,
    pub owner: Win16ComHostOwnerIdentity,
    pub outcome: Win16ComHostCallbackOutcome,
}

/// One operation submitted to the actual host USER STA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostStart {
    pub operation: Win16ComHostOperationIdentity,
    pub request: Win16ComHostRequest,
}

/// Continue the same native API after a callback reply, or poll it while the
/// worker remains inside that native call. `resume` is None only when no
/// callback frame is being acknowledged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ComHostContinue {
    /// Parent native operation for a synchronous callback, or `None` for a
    /// callback delivered after that operation has already returned.
    pub operation: Option<Win16ComHostOperationIdentity>,
    pub resume: Option<Win16ComHostResume>,
}

/// Typed calls on native COM interfaces used by the OLE1-to-COM object path.
/// Each variant names the required interface, method, and owned parameters;
/// no guest vtable slot, pointer, or arbitrary IID crosses the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostInterfaceCall {
    OleSetClientSite { site: Option<ComObjectId> },
    OleSetHostNames { application: Vec<u16>, document: Vec<u16> },
    OleSetMoniker { assign: u32, moniker: ComObjectId },
    OleAdvise { sink: ComObjectId },
    OleUnadvise { cookie: u32 },
    OleGetExtent { aspect: u32 },
    OleSetExtent { aspect: u32, width: i32, height: i32 },
    OleDoVerb {
        verb: i32,
        site: Option<ComObjectId>,
        window: Option<crate::Win16HostWindow>,
        position: Option<crate::Win16HostRect>,
    },
    OleClose { save_option: u32 },
    OleUpdate,
    PersistStorageInitNew { storage: ComObjectId },
    PersistStorageLoad { storage: ComObjectId },
    PersistStorageSave { storage: ComObjectId, same_as_load: bool },
    PersistStorageSaveCompleted { storage: Option<ComObjectId> },
    PersistStorageHandsOff,
    PersistFileLoad { path: Vec<u16>, mode: u32 },
    PersistFileSave { path: Vec<u16>, remember: bool },
    DataObjectQueryGetData { format: Win16ComHostFormatEtc },
    DataObjectGetData { format: Win16ComHostFormatEtc },
    DataObjectEnumFormatEtc { direction: u32 },
    EnumFormatEtcNext { enumerator: ComObjectId, count: u32 },
    EnumFormatEtcReset { enumerator: ComObjectId },
    EnumFormatEtcSkip { enumerator: ComObjectId, count: u32 },
}

/// Pointer-free native storage-medium copy returned by IDataObject::GetData.
/// Interface values are retained as normal opaque COM identities. Resource
/// media unsupported by the requested adapter remain a tagged owner token for
/// a later host-side conversion or release operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostStorageMedium {
    HGlobal(Vec<u8>),
    /// Contents copied from a native TYMED_FILE while the STGMEDIUM still
    /// owns the provider's file. No unstable host path crosses the boundary.
    FileContents(Vec<u8>),
    Stream(Win16ComHostInterface),
    Storage(Win16ComHostInterface),
    NativeResource { tymed: u32, token: Win16ComHostOwnedMediumId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostRequest {
    Ole(Win16OleHostOperation),
    Storage(Win16StorageHostOperation),
    /// Create host-owned IOleClientSite and IAdviseSink proxy interfaces which
    /// report checked callback frames through the USER STA continuation port.
    CreateCallbackProxy { route: Win16ComHostCallbackRoute },
    /// Invoke a typed interface method while retaining its native HRESULT and
    /// the returned interface's opaque identity.
    InterfaceCall { object: ComObjectId, call: Win16ComHostInterfaceCall },
    /// Release a retained IDataObject STGMEDIUM on the same owner STA that
    /// acquired it. Callback-scoped medium IDs are not accepted here.
    ReleaseStorageMedium { medium: Win16ComHostOwnedMediumId },
    /// Release exactly one interface reference previously returned with
    /// `ReferenceDisposition::Owned`. `remaining_owned_references` is a bridge
    /// table count, not COM's process-wide AddRef count.
    ReleaseObject {
        object: ComObjectId,
        owner: Win16ComHostOwnerIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ComHostResult {
    Ole(Win16OleHostReply),
    Storage(Win16StorageHostReply),
    MediumReleased { medium: Win16ComHostOwnedMediumId },
    ObjectReferenceReleased {
        object: ComObjectId,
        owner: Win16ComHostOwnerIdentity,
        remaining_owned_references: u32,
    },
}

/// An owned native interface reference represented by an opaque object key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ComHostInterface {
    pub object: ComObjectId,
    /// The worker incarnation that owns this native reference. Runtime must
    /// preserve it for release; the numeric COM key is never reused by a
    /// replacement worker within this process.
    pub owner: Win16ComHostOwnerIdentity,
    pub iid: Guid,
    pub disposition: ReferenceDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16OleHostOperation {
    Initialize {
        ole: bool,
        reserved: u32,
    },
    Uninitialize {
        ole: bool,
    },
    BuildVersion,
    GetCurrentProcess,
    GetMalloc {
        context: u32,
    },
    FreeUnusedLibraries,
    QueryLinkFromData {
        data_object: ComObjectId,
    },
    QueryCreateFromData {
        data_object: ComObjectId,
    },
    SetClipboard {
        data_object: ComObjectId,
    },
    GetClipboard,
    FlushClipboard,
    IsCurrentClipboard {
        data_object: ComObjectId,
    },
    DoAutoConvert {
        storage: ComObjectId,
    },
    GetAutoConvert {
        clsid: Guid,
    },
    SetAutoConvert {
        clsid: Guid,
        convert_to: Guid,
    },
    GetConvertStg {
        storage: ComObjectId,
    },
    SetConvertStg {
        storage: ComObjectId,
        converted: bool,
    },
    ReadFormatUserType {
        storage: ComObjectId,
    },
    WriteFormatUserType {
        storage: ComObjectId,
        format: u16,
        user_type: Vec<u8>,
        code_page: u32,
    },
    Run {
        object: ComObjectId,
    },
    IsRunning {
        object: ComObjectId,
    },
    LockRunning {
        object: ComObjectId,
        lock: bool,
        last_unlock_closes: bool,
    },
    DisconnectObject {
        object: ComObjectId,
        reserved: u32,
    },
    LockObjectExternal {
        object: ComObjectId,
        lock: bool,
        last_unlock_releases: bool,
    },
    CreateGuid,
    GuidFromString {
        text: Vec<u8>,
    },
    ClsidFromProgId {
        progid: Vec<u8>,
        code_page: u32,
    },
    GuidToString {
        guid: Guid,
        allocated: bool,
        iid: bool,
    },
    ProgIdFromClsid {
        clsid: Guid,
    },
    IsEqualGuid {
        left: Guid,
        right: Guid,
    },
    IsOle1Class {
        clsid: Guid,
    },
    GetTreatAsClass {
        clsid: Guid,
    },
    TreatAsClass {
        clsid: Guid,
        treat_as: Guid,
    },
    CreateInstance {
        clsid: Guid,
        outer: Option<ComObjectId>,
        context: u32,
        iid: Guid,
    },
    GetClassObject {
        clsid: Guid,
        context: u32,
        iid: Guid,
    },
    CreateBindContext {
        reserved: u32,
    },
    GetRunningObjectTable {
        reserved: u32,
    },
    ReadClassStorage {
        storage: ComObjectId,
    },
    WriteClassStorage {
        storage: ComObjectId,
        clsid: Guid,
    },
    ReadClassStream {
        stream: ComObjectId,
    },
    WriteClassStream {
        stream: ComObjectId,
        clsid: Guid,
    },
    SetContainedObject {
        object: ComObjectId,
        contained: bool,
    },
    NoteObjectVisible {
        object: ComObjectId,
        visible: bool,
    },
    Load {
        storage: ComObjectId,
        iid: Guid,
        client_site: Option<ComObjectId>,
    },
    Save {
        persist_storage: ComObjectId,
        storage: ComObjectId,
        same_as_load: bool,
    },
    LoadFromStream {
        stream: ComObjectId,
        iid: Guid,
    },
    SaveToStream {
        persist_stream: ComObjectId,
        stream: ComObjectId,
    },
    CreateFileMoniker {
        path: Vec<u8>,
        code_page: u32,
    },
    CreateItemMoniker {
        delimiter: Vec<u8>,
        item: Vec<u8>,
        code_page: u32,
    },
    CreateGenericComposite {
        first: ComObjectId,
        rest: ComObjectId,
    },
    BindMoniker {
        moniker: ComObjectId,
        options: u32,
        iid: Guid,
    },
    ParseDisplayName {
        bind_context: ComObjectId,
        display_name: Vec<u8>,
        code_page: u32,
    },
    FileTimeNow,
    FileTimeToDosDateTime {
        file_time: [u8; 8],
    },
    DosDateTimeToFileTime {
        date: u16,
        time: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16OleHostValue {
    None,
    Scalar(u32),
    Guid(Guid),
    /// Canonical ASCII GUID including braces and a trailing NUL.
    GuidText(Vec<u8>),
    /// Copied native UTF-16 text. The runtime owns guest allocation and any
    /// Win16 code-page conversion before writing it to guest memory.
    WideText(Vec<u16>),
    FileTime([u8; 8]),
    DosDateTime {
        date: u16,
        time: u16,
    },
    Object(Win16ComHostInterface),
    CallbackInterfaces {
        client_site: Win16ComHostInterface,
        advise_sink: Win16ComHostInterface,
    },
    Extent { width: i32, height: i32 },
    Formats(Vec<Win16ComHostFormatEtc>),
    StorageMedium(Win16ComHostStorageMedium),
    ParsedDisplayName {
        eaten: u32,
        moniker: Option<Win16ComHostInterface>,
    },
    FormatUserType {
        format: u16,
        user_type: Vec<u16>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16OleHostReply {
    /// Exact native result bits, usually an HRESULT.
    pub status: u32,
    pub value: Win16OleHostValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16StorageHostOperation {
    /// Create a real in-memory IStorage whose ILockBytes backing store is
    /// owned by OLE structured storage and released with the storage object.
    CreateMemoryDocFile {
        mode: u32,
        reserved: u32,
    },
    CreateDocFile {
        path: Vec<u8>,
        mode: u32,
        reserved: u32,
    },
    CreateDocFileOnLockBytes {
        lock_bytes: ComObjectId,
        mode: u32,
        reserved: u32,
    },
    OpenStorage {
        path: Vec<u8>,
        priority_storage: Option<ComObjectId>,
        mode: u32,
        /// Owned UTF-16 SNB entries, each without its terminator. The host
        /// adapter builds the native null-terminated SNB table for one call.
        excluded_names: Vec<Vec<u16>>,
        reserved: u32,
    },
    OpenStorageOnLockBytes {
        lock_bytes: ComObjectId,
        priority_storage: Option<ComObjectId>,
        mode: u32,
        excluded_names: Vec<Vec<u16>>,
        reserved: u32,
    },
    IsStorageFile {
        path: Vec<u8>,
    },
    IsStorageLockBytes {
        lock_bytes: ComObjectId,
    },
    SetTimes {
        path: Vec<u8>,
        creation_time: Option<[u8; 8]>,
        access_time: Option<[u8; 8]>,
        modification_time: Option<[u8; 8]>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16StorageHostReply {
    /// Exact native HRESULT, including structured-storage error codes.
    pub hresult: u32,
    pub storage: Option<Win16ComHostInterface>,
}
