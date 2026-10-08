//! Win16 OLE 1.0 client OLEOBJECT method ABI descriptors.

use win16_abi::ArgumentKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OLE1ObjectMethodReturn {
    StatusWord,
    ClipFormatWord,
    FarPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OLE1ObjectMethodAbi {
    /// Arguments after the implicit `LPOLEOBJECT` `this` argument.
    pub(super) arguments: &'static [ArgumentKind],
    pub(super) result: OLE1ObjectMethodReturn,
}

const NO_ARGUMENTS: &[ArgumentKind] = &[];
const WORD: &[ArgumentKind] = &[ArgumentKind::Word];
const DWORD: &[ArgumentKind] = &[ArgumentKind::Dword];
const WORD_WORD: &[ArgumentKind] = &[ArgumentKind::Word, ArgumentKind::Word];
const WORD_DWORD: &[ArgumentKind] = &[ArgumentKind::Word, ArgumentKind::Dword];
const WORD_DWORD_WORD: &[ArgumentKind] =
    &[ArgumentKind::Word, ArgumentKind::Dword, ArgumentKind::Word];
const DWORD_DWORD: &[ArgumentKind] = &[ArgumentKind::Dword, ArgumentKind::Dword];
const WORD_WORD_WORD: &[ArgumentKind] =
    &[ArgumentKind::Word, ArgumentKind::Word, ArgumentKind::Word];
const WORD_DWORD_DWORD_WORD: &[ArgumentKind] = &[
    ArgumentKind::Word,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Word,
];
const WORD_WORD_WORD_WORD_DWORD: &[ArgumentKind] = &[
    ArgumentKind::Word,
    ArgumentKind::Word,
    ArgumentKind::Word,
    ArgumentKind::Word,
    ArgumentKind::Dword,
];
const DWORD_DWORD_DWORD_DWORD: &[ArgumentKind] = &[
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
];
const DWORD_DWORD_DWORD_DWORD_DWORD: &[ArgumentKind] = &[
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
];

/// Win16 OLE.H's client OLEOBJECTVTBL declarations (OLE.H:245–298).
/// HANDLE/HGLOBAL/HDC/HWND/BOOL/UINT/OLECLIPFORMAT are WORD in the Win16
/// non-STRICT ABI; FAR pointers and LHCLIENTDOC are DWORD. ObjectLong is a
/// public client entry. ChangeData is marked internal-only, but remains the
/// final physical entry in the client table. The separate SERVERONLY table
/// ends after SetColorScheme and is not this client proxy layout.
pub(super) const OBJECT_METHOD_ABI: [OLE1ObjectMethodAbi; 39] = [
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::FarPointer,
    }, // 0 QueryProtocol
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 1 Release
    OLE1ObjectMethodAbi {
        arguments: WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 2 Show
    OLE1ObjectMethodAbi {
        arguments: WORD_WORD_WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 3 DoVerb
    OLE1ObjectMethodAbi {
        arguments: WORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 4 GetData
    OLE1ObjectMethodAbi {
        arguments: WORD_WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 5 SetData
    OLE1ObjectMethodAbi {
        arguments: WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 6 SetTargetDevice
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 7 SetBounds
    OLE1ObjectMethodAbi {
        arguments: WORD,
        result: OLE1ObjectMethodReturn::ClipFormatWord,
    }, // 8 EnumFormats
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 9 SetColorScheme
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 10 Delete
    OLE1ObjectMethodAbi {
        arguments: DWORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 11 SetHostNames
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 12 SaveToStream
    OLE1ObjectMethodAbi {
        arguments: DWORD_DWORD_DWORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 13 Clone
    OLE1ObjectMethodAbi {
        arguments: DWORD_DWORD_DWORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 14 CopyFromLink; OLE.H omits protocol here
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 15 Equal
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 16 CopyToClipboard
    OLE1ObjectMethodAbi {
        arguments: WORD_DWORD_DWORD_WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 17 Draw
    OLE1ObjectMethodAbi {
        arguments: WORD_WORD_WORD_WORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 18 Activate
    OLE1ObjectMethodAbi {
        arguments: WORD_WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 19 Execute
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 20 Close
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 21 Update
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 22 Reconnect
    OLE1ObjectMethodAbi {
        arguments: DWORD_DWORD_DWORD_DWORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 23 ObjectConvert
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 24 GetLinkUpdateOptions
    OLE1ObjectMethodAbi {
        arguments: WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 25 SetLinkUpdateOptions
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 26 Rename
    OLE1ObjectMethodAbi {
        arguments: DWORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 27 QueryName
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 28 QueryType
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 29 QueryBounds
    OLE1ObjectMethodAbi {
        arguments: DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 30 QuerySize
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 31 QueryOpen
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 32 QueryOutOfDate
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 33 QueryReleaseStatus
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 34 QueryReleaseError
    OLE1ObjectMethodAbi {
        arguments: NO_ARGUMENTS,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 35 QueryReleaseMethod
    OLE1ObjectMethodAbi {
        arguments: WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 36 RequestData
    OLE1ObjectMethodAbi {
        arguments: WORD_DWORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 37 ObjectLong
    OLE1ObjectMethodAbi {
        arguments: WORD_DWORD_WORD,
        result: OLE1ObjectMethodReturn::StatusWord,
    }, // 38 ChangeData (internal-only, physically present)
];

/// Reason each currently unsupported client slot cannot be faithfully
/// represented by the checked OLE1/COM adapter. The checked gate reports this
/// diagnostic and returns a non-success status (or the SDK's null/end
/// sentinel for the two value-returning lookup methods).
pub(super) fn method_compatibility_gap(slot: u8) -> Option<&'static str> {
    Some(match slot {
        0 => "OLE1 QueryProtocol has no registered guest protocol adapter for this native object",
        2 => "OLE1 Show needs native window activation and visibility reconciliation",
        3 => "OLE1 DoVerb has two Win16 BOOL flags not represented by the typed IOleObject::DoVerb request",
        4 => "OLE1 GetData needs checked STGMEDIUM-to-Win16 HGLOBAL conversion and release",
        5 => "OLE1 SetData has no typed IDataObject::SetData request",
        6 => "OLE1 SetTargetDevice needs OLETARGETDEVICE-to-DVTARGETDEVICE conversion",
        7 => "OLE1 SetBounds needs guest RECT-to-native extent conversion with view coordinates",
        8 => "OLE1 EnumFormats has no checked IEnumFORMATETC cursor and guest clip-format mapping",
        9 => "OLE1 SetColorScheme needs checked LOGPALETTE-to-native palette conversion",
        10 => "OLE1 Delete needs the server-side OLE deletion contract, distinct from client Release",
        12 => "OLE1 SaveToStream needs an OLESTREAM adapter and exact guest stream callbacks",
        13 => "OLE1 Clone needs native clone creation plus checked client/document rebinding",
        14 => "OLE1 CopyFromLink needs moniker/link creation and release-notification reconciliation",
        15 => "OLE1 Equal needs canonical native identity comparison across owner-bound references",
        16 => "OLE1 CopyToClipboard needs checked IDataObject clipboard ownership transfer",
        17 => "OLE1 Draw needs guest HDC/RECT transfer and native drawing-surface ownership",
        18 => "OLE1 Activate needs checked HWND/RECT mapping and native UI activation callbacks",
        19 => "OLE1 Execute needs HGLOBAL command conversion and the OLE1 DDE execute path",
        22 => "OLE1 Reconnect needs a native moniker/container reconnection contract",
        23 => "OLE1 ObjectConvert needs a second typed create transaction and checked object replacement",
        26 => "OLE1 Rename needs moniker rebinding and copied guest client notifications",
        27 => "OLE1 QueryName needs bounded guest output conversion from the native moniker display name",
        28 => "OLE1 QueryType needs a registered OLE1 class-to-type mapping",
        29 => "OLE1 QueryBounds needs native HIMETRIC extent-to-guest RECT conversion",
        30 => "OLE1 QuerySize needs a defined OLE1 size source and guest DWORD conversion",
        31 => "OLE1 QueryOpen needs a typed storage/open-state query not exposed by the current COM request DTO",
        32 => "OLE1 QueryOutOfDate needs native link/source version reconciliation",
        36 => "OLE1 RequestData needs the OLE1 request/advise transaction and guest medium conversion",
        38 => "OLE1 ChangeData is marked internal-only in the Windows 3.1 OLE.H client vtable",
        _ => return None,
    })
}

/// Guest OLESTATUS for one known but not faithfully implemented method.
/// QueryProtocol and EnumFormats have their own documented null/end values;
/// QueryReleaseMethod is a separate enum and is handled from the exact OLE1
/// pending-operation journal rather than being mapped here.
pub(super) fn method_compatibility_status(slot: u8) -> Option<u16> {
    Some(match slot {
        2 => super::OLE1_ERROR_SHOW,
        3 | 18 => super::OLE1_ERROR_DOVERB,
        4 => super::OLE1_ERROR_FORMAT,
        5 => super::OLE1_ERROR_SETDATA_FORMAT,
        6 => super::OLE1_ERROR_DATATYPE,
        7 | 29 | 30 => super::OLE1_ERROR_SIZE,
        10 | 14 | 15 | 31 | 32 | 36 | 38 => super::OLE1_ERROR_GENERIC,
        9 => super::OLE1_ERROR_PALETTE,
        12 => super::OLE1_ERROR_STREAM,
        13 => super::OLE1_ERROR_NEW,
        16 => super::OLE1_ERROR_CLIPBOARD,
        17 => super::OLE1_ERROR_DRAW,
        19 => super::OLE1_ERROR_COMMAND,
        22 => super::OLE1_ERROR_COMM,
        23 => super::OLE1_ERROR_CLASS,
        26 | 27 => super::OLE1_ERROR_NAME,
        28 => super::OLE1_ERROR_CLASS,
        _ => return None,
    })
}

pub(super) fn method_signature(slot: u8) -> Option<([ArgumentKind; 6], usize)> {
    let abi = OBJECT_METHOD_ABI.get(usize::from(slot))?;
    let len = abi.arguments.len().checked_add(1)?;
    let mut signature = [ArgumentKind::Dword; 6];
    signature[0] = ArgumentKind::Dword; // implicit LPOLEOBJECT `this`
    signature.get_mut(1..len)?.copy_from_slice(abi.arguments);
    Some((signature, len))
}
