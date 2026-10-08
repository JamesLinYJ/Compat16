//! Owned requests for the Win16 OLE 1.0 client and server API subsets.
//!
//! Strings are copied from checked guest FAR ranges. `output` remains a guest
//! FAR token for runtime-side preflight/writeback and is never a host pointer.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Ole1Request {
    /// `OleCreate` and `OleCreateInvisible`. Strings are copied from checked
    /// guest FARs; the output remains a FAR token for runtime preflight.
    Create {
        class_name: Vec<u8>,
        client: u32,
        protocol: Vec<u8>,
        document: i32,
        item_name: Option<Vec<u8>>,
        object_output: u32,
        render_option: u16,
        clip_format: u16,
        activate: bool,
    },
    /// `OleCreateFromFile`, whose class and file names have separate OLE1
    /// meanings. Only the runtime may translate either string for the host.
    CreateFromFile {
        class_name: Vec<u8>,
        file_name: Vec<u8>,
        client: u32,
        native_type: Vec<u8>,
        document: i32,
        item_name: Option<Vec<u8>>,
        object_output: u32,
        render_option: u16,
        clip_format: u16,
    },
    /// Retain decoded input for APIs whose native OLE1 semantics are not yet
    /// represented by the typed host adapter. Runtime returns a typed gap.
    CreateFromTemplate {
        class_name: Vec<u8>,
        template_name: Vec<u8>,
        client: u32,
        document: i32,
        item_name: Option<Vec<u8>>,
        object_output: u32,
        render_option: u16,
        clip_format: u16,
    },
    CreateLinkFromFile {
        file_name: Vec<u8>,
        class_name: Vec<u8>,
        client: u32,
        native_type: Vec<u8>,
        link_source: Vec<u8>,
        document: i32,
        item_name: Option<Vec<u8>>,
        object_output: u32,
        render_option: u16,
        clip_format: u16,
    },
    LoadFromStream {
        stream: u32,
        protocol: Vec<u8>,
        client: u32,
        document: i32,
        item_name: Option<Vec<u8>>,
        object_output: u32,
    },
    /// An input string or pointer in a create API failed checked decoding.
    /// The runtime still clears the API's output object slot when possible.
    CreationInvalidAddress {
        object_output: u32,
        status: u16,
    },
    /// Delegate an OLE 1.0 public object API to its matching guest vtable slot.
    /// `ordinal` is the OLECLI public export ordinal; each raw argument keeps
    /// the guest bits decoded from its declared Win16 width.
    ObjectMethod {
        ordinal: u16,
        object: u32,
        arguments: Vec<u32>,
    },
    /// Delegate `OleSaveToStream` to the guest object's SaveToStream vtable
    /// method. Both pointers remain guest FAR tokens until runtime preflight.
    SaveToStream {
        object: u32,
        stream: u32,
    },
    QueryClientVersion,
    /// Test whether a checked Win16 HDC identifies a classic metafile DC.
    IsDcMeta {
        dc: u16,
    },
    QueryServerVersion,
    /// OLESVR server and server-document handles retain their guest LONG bit
    /// patterns. FAR inputs and outputs remain guest tokens until runtime
    /// preflight; no selector or host-pointer interpretation happens here.
    RegisterServer {
        class_name_far: u32,
        server_far: u32,
        output_far: u32,
        instance: u16,
        use_mode: u16,
    },
    RevokeServer {
        server: i32,
    },
    BlockServer {
        server: i32,
    },
    UnblockServer {
        server: i32,
        blocked_output_far: u32,
    },
    RegisterServerDoc {
        server: i32,
        document_name_far: u32,
        server_document_far: u32,
        output_far: u32,
    },
    RevokeServerDoc {
        document: i32,
    },
    RenameServerDoc {
        document: i32,
        document_name_far: u32,
    },
    RevertServerDoc {
        document: i32,
    },
    SavedServerDoc {
        document: i32,
    },
    RevokeObject {
        client_far: u32,
    },
    /// OLESVR ordinal 26 callback thunk: client FAR, OLE notification WORD,
    /// and object FAR, returning the 16-bit OLESTATUS value.
    ItemCallback {
        client_far: u32,
        notification: u16,
        object_far: u32,
    },
    /// A RegisterClientDoc name FAR value failed checked guest-memory decoding.
    /// The output FAR must still be probed and cleared before returning status.
    RegisterClientDocInvalidAddress {
        output: u32,
        status: u16,
    },
    /// A RenameClientDoc name FAR value failed checked guest-memory decoding.
    /// Retaining the handle preserves the API's handle-before-pointer checks.
    RenameClientDocInvalidAddress {
        document: i32,
        status: u16,
    },
    RegisterClientDoc {
        class_name: Vec<u8>,
        document_name: Vec<u8>,
        reserved: i32,
        output: u32,
    },
    RevokeClientDoc {
        document: i32,
    },
    RenameClientDoc {
        document: i32,
        document_name: Vec<u8>,
    },
    RevertClientDoc {
        document: i32,
    },
    SavedClientDoc {
        document: i32,
    },
    /// Enumerate document members through a checked guest object-pointer slot.
    EnumObjects {
        document: i32,
        object_inout: u32,
    },
}
