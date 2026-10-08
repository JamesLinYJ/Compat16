// OLE 1.0 public APIs use the SDK 3.1 OLE.H argument layouts. The ordinal and
// export token remain the ones already recorded by the OLECLI/OLESVR specs.
macro_rules! export_catalog_with_ole1 {
    ($($existing:tt)*) => {
        export_catalog_with_global_arena! {
            $($existing)*
            Ole1Delete => OLE1_DELETE: ("OLECLI", 2u16, Stack, ole1::OLE_DELETE, Word);
            Ole1SaveToStream => OLE1_SAVE_TO_STREAM: ("OLECLI", 3u16, Stack, ole1::OLE_SAVE_TO_STREAM, Word);
            Ole1LoadFromStream => OLE1_LOAD_FROM_STREAM: ("OLECLI", 4u16, Stack, ole1::OLE_LOAD_FROM_STREAM, Word);
            Ole1Clone => OLE1_CLONE: ("OLECLI", 6u16, Stack, ole1::OLE_CLONE, Word);
            Ole1CopyFromLink => OLE1_COPY_FROM_LINK: ("OLECLI", 7u16, Stack, ole1::OLE_COPY_FROM_LINK, Word);
            Ole1Equal => OLE1_EQUAL: ("OLECLI", 8u16, Stack, ole1::OLE_EQUAL, Word);
            Ole1QueryLinkFromClip => OLE1_QUERY_LINK_FROM_CLIP: ("OLECLI", 9u16, Stack, ole1::OLE_QUERY_LINK_FROM_CLIP, Word);
            Ole1QueryCreateFromClip => OLE1_QUERY_CREATE_FROM_CLIP: ("OLECLI", 10u16, Stack, ole1::OLE_QUERY_CREATE_FROM_CLIP, Word);
            Ole1CreateLinkFromClip => OLE1_CREATE_LINK_FROM_CLIP: ("OLECLI", 11u16, Stack, ole1::OLE_CREATE_LINK_FROM_CLIP, Word);
            Ole1CreateFromClip => OLE1_CREATE_FROM_CLIP: ("OLECLI", 12u16, Stack, ole1::OLE_CREATE_FROM_CLIP, Word);
            Ole1CopyToClipboard => OLE1_COPY_TO_CLIPBOARD: ("OLECLI", 13u16, Stack, ole1::OLE_COPY_TO_CLIPBOARD, Word);
            Ole1QueryType => OLE1_QUERY_TYPE: ("OLECLI", 14u16, Stack, ole1::OLE_QUERY_TYPE, Word);
            Ole1SetHostNames => OLE1_SET_HOST_NAMES: ("OLECLI", 15u16, Stack, ole1::OLE_SET_HOST_NAMES, Word);
            Ole1SetTargetDevice => OLE1_SET_TARGET_DEVICE: ("OLECLI", 16u16, Stack, ole1::OLE_SET_TARGET_DEVICE, Word);
            Ole1SetBounds => OLE1_SET_BOUNDS: ("OLECLI", 17u16, Stack, ole1::OLE_SET_BOUNDS, Word);
            Ole1QueryBounds => OLE1_QUERY_BOUNDS: ("OLECLI", 18u16, Stack, ole1::OLE_QUERY_BOUNDS, Word);
            Ole1Draw => OLE1_DRAW: ("OLECLI", 19u16, Stack, ole1::OLE_DRAW, Word);
            Ole1QueryOpen => OLE1_QUERY_OPEN: ("OLECLI", 20u16, Stack, ole1::OLE_QUERY_OPEN, Word);
            Ole1Activate => OLE1_ACTIVATE: ("OLECLI", 21u16, Stack, ole1::OLE_ACTIVATE, Word);
            Ole1Update => OLE1_UPDATE: ("OLECLI", 22u16, Stack, ole1::OLE_UPDATE, Word);
            Ole1Reconnect => OLE1_RECONNECT: ("OLECLI", 23u16, Stack, ole1::OLE_RECONNECT, Word);
            Ole1GetLinkUpdateOptions => OLE1_GET_LINK_UPDATE_OPTIONS: ("OLECLI", 24u16, Stack, ole1::OLE_GET_LINK_UPDATE_OPTIONS, Word);
            Ole1SetLinkUpdateOptions => OLE1_SET_LINK_UPDATE_OPTIONS: ("OLECLI", 25u16, Stack, ole1::OLE_SET_LINK_UPDATE_OPTIONS, Word);
            Ole1EnumFormats => OLE1_ENUM_FORMATS: ("OLECLI", 26u16, Stack, ole1::OLE_ENUM_FORMATS, Word);
            Ole1Close => OLE1_CLOSE: ("OLECLI", 27u16, Stack, ole1::OLE_CLOSE, Word);
            Ole1GetData => OLE1_GET_DATA: ("OLECLI", 28u16, Stack, ole1::OLE_GET_DATA, Word);
            Ole1SetData => OLE1_SET_DATA: ("OLECLI", 29u16, Stack, ole1::OLE_SET_DATA, Word);
            Ole1QueryProtocol => OLE1_QUERY_PROTOCOL: ("OLECLI", 30u16, Stack, ole1::OLE_QUERY_PROTOCOL, FarPointer);
            Ole1QueryOutOfDate => OLE1_QUERY_OUT_OF_DATE: ("OLECLI", 31u16, Stack, ole1::OLE_QUERY_OUT_OF_DATE, Word);
            Ole1ObjectConvert => OLE1_OBJECT_CONVERT: ("OLECLI", 32u16, Stack, ole1::OLE_OBJECT_CONVERT, Word);
            Ole1CreateFromTemplate => OLE1_CREATE_FROM_TEMPLATE: ("OLECLI", 33u16, Stack, ole1::OLE_CREATE_FROM_TEMPLATE, Word);
            Ole1Create => OLE1_CREATE: ("OLECLI", 34u16, Stack, ole1::OLE_CREATE, Word);
            Ole1QueryReleaseStatus => OLE1_QUERY_RELEASE_STATUS: ("OLECLI", 35u16, Stack, ole1::OLE_QUERY_RELEASE_STATUS, Word);
            Ole1QueryReleaseError => OLE1_QUERY_RELEASE_ERROR: ("OLECLI", 36u16, Stack, ole1::OLE_QUERY_RELEASE_ERROR, Word);
            Ole1QueryReleaseMethod => OLE1_QUERY_RELEASE_METHOD: ("OLECLI", 37u16, Stack, ole1::OLE_QUERY_RELEASE_METHOD, Word);
            Ole1CreateFromFile => OLE1_CREATE_FROM_FILE: ("OLECLI", 38u16, Stack, ole1::OLE_CREATE_FROM_FILE, Word);
            Ole1CreateLinkFromFile => OLE1_CREATE_LINK_FROM_FILE: ("OLECLI", 39u16, Stack, ole1::OLE_CREATE_LINK_FROM_FILE, Word);
            Ole1Release => OLE1_RELEASE: ("OLECLI", 40u16, Stack, ole1::OLE_RELEASE, Word);
            Ole1RegisterClientDoc => OLE1_REGISTER_CLIENT_DOC: ("OLECLI", 41u16, Stack, ole1::OLE_REGISTER_CLIENT_DOC, Word);
            Ole1RevokeClientDoc => OLE1_REVOKE_CLIENT_DOC: ("OLECLI", 42u16, Stack, ole1::OLE_REVOKE_CLIENT_DOC, Word);
            Ole1RenameClientDoc => OLE1_RENAME_CLIENT_DOC: ("OLECLI", 43u16, Stack, ole1::OLE_RENAME_CLIENT_DOC, Word);
            Ole1RevertClientDoc => OLE1_REVERT_CLIENT_DOC: ("OLECLI", 44u16, Stack, ole1::OLE_REVERT_CLIENT_DOC, Word);
            Ole1SavedClientDoc => OLE1_SAVED_CLIENT_DOC: ("OLECLI", 45u16, Stack, ole1::OLE_SAVED_CLIENT_DOC, Word);
            Ole1Rename => OLE1_RENAME: ("OLECLI", 46u16, Stack, ole1::OLE_RENAME, Word);
            Ole1EnumObjects => OLE1_ENUM_OBJECTS: ("OLECLI", 47u16, Stack, ole1::OLE_ENUM_OBJECTS, Word);
            Ole1QueryName => OLE1_QUERY_NAME: ("OLECLI", 48u16, Stack, ole1::OLE_QUERY_NAME, Word);
            Ole1SetColorScheme => OLE1_SET_COLOR_SCHEME: ("OLECLI", 49u16, Stack, ole1::OLE_SET_COLOR_SCHEME, Word);
            Ole1RequestData => OLE1_REQUEST_DATA: ("OLECLI", 50u16, Stack, ole1::OLE_REQUEST_DATA, Word);
            Ole1LockServer => OLE1_LOCK_SERVER: ("OLECLI", 54u16, Stack, ole1::OLE_LOCK_SERVER, Word);
            Ole1UnlockServer => OLE1_UNLOCK_SERVER: ("OLECLI", 55u16, Stack, ole1::OLE_UNLOCK_SERVER, Word);
            Ole1QuerySize => OLE1_QUERY_SIZE: ("OLECLI", 56u16, Stack, ole1::OLE_QUERY_SIZE, Word);
            Ole1Execute => OLE1_EXECUTE: ("OLECLI", 57u16, Stack, ole1::OLE_EXECUTE, Word);
            Ole1CreateInvisible => OLE1_CREATE_INVISIBLE: ("OLECLI", 58u16, Stack, ole1::OLE_CREATE_INVISIBLE, Word);
            Ole1QueryClientVersion => OLE1_QUERY_CLIENT_VERSION: ("OLECLI", 59u16, Stack, ole1::OLE_QUERY_CLIENT_VERSION, Dword);
            Ole1IsDcMeta => OLE1_IS_DC_META: ("OLECLI", 60u16, Stack, ole1::OLE_IS_DC_META, Word);
            Ole1RegisterServer => OLE1_REGISTER_SERVER: ("OLESVR", 2u16, Stack, ole1::OLE_REGISTER_SERVER, Word);
            Ole1RevokeServer => OLE1_REVOKE_SERVER: ("OLESVR", 3u16, Stack, ole1::OLE_REVOKE_SERVER, Word);
            Ole1BlockServer => OLE1_BLOCK_SERVER: ("OLESVR", 4u16, Stack, ole1::OLE_BLOCK_SERVER, Word);
            Ole1UnblockServer => OLE1_UNBLOCK_SERVER: ("OLESVR", 5u16, Stack, ole1::OLE_UNBLOCK_SERVER, Word);
            Ole1RegisterServerDoc => OLE1_REGISTER_SERVER_DOC: ("OLESVR", 6u16, Stack, ole1::OLE_REGISTER_SERVER_DOC, Word);
            Ole1RevokeServerDoc => OLE1_REVOKE_SERVER_DOC: ("OLESVR", 7u16, Stack, ole1::OLE_REVOKE_SERVER_DOC, Word);
            Ole1RenameServerDoc => OLE1_RENAME_SERVER_DOC: ("OLESVR", 8u16, Stack, ole1::OLE_RENAME_SERVER_DOC, Word);
            Ole1RevertServerDoc => OLE1_REVERT_SERVER_DOC: ("OLESVR", 9u16, Stack, ole1::OLE_REVERT_SERVER_DOC, Word);
            Ole1SavedServerDoc => OLE1_SAVED_SERVER_DOC: ("OLESVR", 10u16, Stack, ole1::OLE_SAVED_SERVER_DOC, Word);
            Ole1RevokeObject => OLE1_REVOKE_OBJECT: ("OLESVR", 11u16, Stack, ole1::OLE_REVOKE_OBJECT, Word);
            Ole1QueryServerVersion => OLE1_QUERY_SERVER_VERSION: ("OLESVR", 12u16, Stack, ole1::OLE_QUERY_SERVER_VERSION, Dword);
            Ole1ItemCallback => OLE1_ITEM_CALLBACK: ("OLESVR", 26u16, Stack, ole1::OLE_ITEM_CALLBACK, Word);
        }
    };
}
