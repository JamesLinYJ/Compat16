//! Win16 OLE 1.0 client/server parameter layouts.
//!
//! Signatures follow the local Windows 3.1 SDK `OLE.H`; ordinals and existing
//! export spellings stay in `olecli.spec` and `olesvr.spec`. The `LPOLEOBJECT`,
//! `LPOLECLIENT`, `LPOLESTREAM`, `LPOLESERVER`, and `LPOLESERVERDOC` arguments
//! are guest FAR addresses to guest records. Their vtable slots are guest
//! callback addresses: they must be selector-validated and resumed through a
//! checked runtime continuation, never cast to native function pointers.
//! `LPOLEOBJECT FAR *`, `LHCLIENTDOC FAR *`, and related outputs are guest
//! writeback ranges, not slots for native pointers.
//!
//! Callback slot inventory from `OLE.H`:
//! - `OLECLIENTVTBL`: `CallBack`.
//! - `OLESTREAMVTBL`: `Get`, `Put`.
//! - `OLEOBJECTVTBL`: `QueryProtocol`, `Release`, `Show`, `DoVerb`, `GetData`,
//!   `SetData`, `SetTargetDevice`, `SetBounds`, `EnumFormats`, `SetColorScheme`,
//!   `Delete`, `SetHostNames`, `SaveToStream`, `Clone`, `CopyFromLink`, `Equal`,
//!   `CopyToClipboard`, `Draw`, `Activate`, `Execute`, `Close`, `Update`,
//!   `Reconnect`, `ObjectConvert`, `GetLinkUpdateOptions`, `SetLinkUpdateOptions`,
//!   `Rename`, `QueryName`, `QueryType`, `QueryBounds`, `QuerySize`, `QueryOpen`,
//!   `QueryOutOfDate`, `QueryReleaseStatus`, `QueryReleaseError`,
//!   `QueryReleaseMethod`, `RequestData`, `ObjectLong`, and private `ChangeData`.
//! - `OLESERVERVTBL`: `Open`, `Create`, `CreateFromTemplate`, `Edit`, `Exit`,
//!   `Release`, `Execute`.
//! - `OLESERVERDOCVTBL`: `Save`, `Close`, `SetHostNames`, `SetDocDimensions`,
//!   `GetObject`, `Release`, `SetColorScheme`, `Execute`.

use super::*;

macro_rules! parameters {
    ($name:ident: [$($argument:ident: $kind:ident / $role:expr),* $(,)?]) => {
        pub(super) const $name: &[Win16Parameter] = &[
            $(Win16Parameter {
                name: stringify!($argument),
                kind: ArgumentKind::$kind,
                parameter_type: $role,
            },)*
        ];
    };
}

// OLEOBJECT method table (including its private ChangeData slot).
parameters!(OLE_DELETE: [object: Dword / FAR_BUFFER]);
parameters!(OLE_RELEASE: [object: Dword / FAR_BUFFER]);
parameters!(OLE_SAVE_TO_STREAM: [object: Dword / FAR_BUFFER, stream: Dword / FAR_BUFFER]);
parameters!(OLE_EQUAL: [left: Dword / FAR_BUFFER, right: Dword / FAR_BUFFER]);
parameters!(OLE_COPY_TO_CLIPBOARD: [object: Dword / FAR_BUFFER]);
parameters!(OLE_SET_HOST_NAMES: [object: Dword / FAR_BUFFER, application_name: Dword / FAR_STRING, document_name: Dword / FAR_STRING]);
parameters!(OLE_SET_TARGET_DEVICE: [object: Dword / FAR_BUFFER, target_device: Word / SCALAR_WORD]);
parameters!(OLE_SET_BOUNDS: [object: Dword / FAR_BUFFER, bounds: Dword / FAR_BUFFER]);
parameters!(OLE_SET_COLOR_SCHEME: [object: Dword / FAR_BUFFER, palette: Dword / FAR_BUFFER]);
parameters!(OLE_QUERY_BOUNDS: [object: Dword / FAR_BUFFER, bounds: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_QUERY_SIZE: [object: Dword / FAR_BUFFER, size: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_DRAW: [object: Dword / FAR_BUFFER, dc: Word / SCALAR_WORD, object_bounds: Dword / FAR_BUFFER, clip_bounds: Dword / FAR_BUFFER, metafile_dc: Word / SCALAR_WORD]);
parameters!(OLE_QUERY_OPEN: [object: Dword / FAR_BUFFER]);
parameters!(OLE_ACTIVATE: [object: Dword / FAR_BUFFER, verb: Word / SCALAR_WORD, show: Word / SCALAR_WORD, take_focus: Word / SCALAR_WORD, parent: Word / SCALAR_WORD, bounds: Dword / FAR_BUFFER]);
parameters!(OLE_EXECUTE: [object: Dword / FAR_BUFFER, command_data: Word / SCALAR_WORD, command_length: Word / SCALAR_WORD]);
parameters!(OLE_CLOSE: [object: Dword / FAR_BUFFER]);
parameters!(OLE_UPDATE: [object: Dword / FAR_BUFFER]);
parameters!(OLE_RECONNECT: [object: Dword / FAR_BUFFER]);
parameters!(OLE_GET_LINK_UPDATE_OPTIONS: [object: Dword / FAR_BUFFER, options: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_SET_LINK_UPDATE_OPTIONS: [object: Dword / FAR_BUFFER, options: Word / SCALAR_WORD]);
parameters!(OLE_QUERY_PROTOCOL: [object: Dword / FAR_BUFFER, protocol: Dword / FAR_STRING]);
parameters!(OLE_QUERY_RELEASE_STATUS: [object: Dword / FAR_BUFFER]);
parameters!(OLE_QUERY_RELEASE_ERROR: [object: Dword / FAR_BUFFER]);
parameters!(OLE_QUERY_RELEASE_METHOD: [object: Dword / FAR_BUFFER]);
parameters!(OLE_QUERY_TYPE: [object: Dword / FAR_BUFFER, object_type: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_QUERY_CLIENT_VERSION: []);
parameters!(OLE_QUERY_SERVER_VERSION: []);
parameters!(OLE_ENUM_FORMATS: [object: Dword / FAR_BUFFER, format: Word / SCALAR_WORD]);
parameters!(OLE_GET_DATA: [object: Dword / FAR_BUFFER, format: Word / SCALAR_WORD, data_handle: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_SET_DATA: [object: Dword / FAR_BUFFER, format: Word / SCALAR_WORD, data_handle: Word / SCALAR_WORD]);
parameters!(OLE_QUERY_OUT_OF_DATE: [object: Dword / FAR_BUFFER]);
parameters!(OLE_REQUEST_DATA: [object: Dword / FAR_BUFFER, format: Word / SCALAR_WORD]);

// Client creation and conversion APIs.
parameters!(OLE_QUERY_LINK_FROM_CLIP: [class_name: Dword / FAR_STRING, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_QUERY_CREATE_FROM_CLIP: [class_name: Dword / FAR_STRING, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_CREATE_FROM_CLIP: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_CREATE_LINK_FROM_CLIP: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_CREATE_FROM_FILE: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, file_name: Dword / FAR_STRING, native_type: Dword / FAR_STRING, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_CREATE_LINK_FROM_FILE: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, file_name: Dword / FAR_STRING, native_type: Dword / FAR_STRING, link_source: Dword / FAR_STRING, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_LOAD_FROM_STREAM: [stream: Dword / FAR_BUFFER, class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_CREATE: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, document_name: Dword / FAR_STRING, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_CREATE_INVISIBLE: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, document_name: Dword / FAR_STRING, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD, invisible: Word / SCALAR_WORD]);
parameters!(OLE_CREATE_FROM_TEMPLATE: [class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, template_name: Dword / FAR_STRING, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER, render: Word / SCALAR_WORD, format: Word / SCALAR_WORD]);
parameters!(OLE_CLONE: [object: Dword / FAR_BUFFER, client: Dword / FAR_BUFFER, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_COPY_FROM_LINK: [object: Dword / FAR_BUFFER, class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_OBJECT_CONVERT: [object: Dword / FAR_BUFFER, class_name: Dword / FAR_STRING, client: Dword / FAR_BUFFER, client_document: Dword / SIGNED_SCALAR, item_name: Dword / FAR_STRING, object_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_RENAME: [object: Dword / FAR_BUFFER, name: Dword / FAR_STRING]);
parameters!(OLE_QUERY_NAME: [object: Dword / FAR_BUFFER, name: Dword / FAR_OUTPUT_BUFFER, capacity: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_REVOKE_OBJECT: [client: Dword / FAR_BUFFER]);
parameters!(OLE_IS_DC_META: [dc: Word / SCALAR_WORD]);

// Client-document APIs and OLESVR public exports.
parameters!(OLE_REGISTER_CLIENT_DOC: [class_name: Dword / FAR_STRING, document_name: Dword / FAR_STRING, reserved: Dword / SIGNED_SCALAR, document_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_REVOKE_CLIENT_DOC: [document: Dword / SIGNED_SCALAR]);
parameters!(OLE_RENAME_CLIENT_DOC: [document: Dword / SIGNED_SCALAR, document_name: Dword / FAR_STRING]);
parameters!(OLE_REVERT_CLIENT_DOC: [document: Dword / SIGNED_SCALAR]);
parameters!(OLE_SAVED_CLIENT_DOC: [document: Dword / SIGNED_SCALAR]);
parameters!(OLE_ENUM_OBJECTS: [document: Dword / SIGNED_SCALAR, object_inout: Dword / FAR_BUFFER]);
parameters!(OLE_REGISTER_SERVER: [class_name: Dword / FAR_STRING, server: Dword / FAR_BUFFER, server_output: Dword / FAR_OUTPUT_BUFFER, instance: Word / SCALAR_WORD, use_mode: Word / SCALAR_WORD]);
parameters!(OLE_REVOKE_SERVER: [server: Dword / SIGNED_SCALAR]);
parameters!(OLE_BLOCK_SERVER: [server: Dword / SIGNED_SCALAR]);
parameters!(OLE_UNBLOCK_SERVER: [server: Dword / SIGNED_SCALAR, blocked_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_LOCK_SERVER: [object: Dword / FAR_BUFFER, server_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_UNLOCK_SERVER: [server: Dword / SIGNED_SCALAR]);
parameters!(OLE_REGISTER_SERVER_DOC: [server: Dword / SIGNED_SCALAR, document_name: Dword / FAR_STRING, server_document: Dword / FAR_BUFFER, document_output: Dword / FAR_OUTPUT_BUFFER]);
parameters!(OLE_REVOKE_SERVER_DOC: [document: Dword / SIGNED_SCALAR]);
parameters!(OLE_RENAME_SERVER_DOC: [document: Dword / SIGNED_SCALAR, document_name: Dword / FAR_STRING]);
parameters!(OLE_REVERT_SERVER_DOC: [document: Dword / SIGNED_SCALAR]);
parameters!(OLE_SAVED_SERVER_DOC: [document: Dword / SIGNED_SCALAR]);
parameters!(OLE_ITEM_CALLBACK: [client_far: Dword / FAR_BUFFER, notification: Word / SCALAR_WORD, object_far: Dword / FAR_BUFFER]);
