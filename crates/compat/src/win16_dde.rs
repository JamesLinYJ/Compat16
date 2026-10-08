//! Pointer-free DDEML values shared by the Win16 runtime and native adapter.
//!
//! DDEML instance, string, conversation, conversation-list, and data handles
//! are runtime tokens here. They are never native HSZ/HCONV/HDDEDATA values.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DdeInstanceToken(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DdeStringToken(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DdeConversationToken(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DdeConversationListToken(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DdeDataToken(pub u32);

/// A copied DDEML callback call. `data` owns a snapshot of the host data
/// object; `transaction_data` is a scalar ID or copied payload selected by the
/// transaction type. Guest procedure FAR values are retained only by runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DdeCallbackInvocation {
    pub instance: DdeInstanceToken,
    pub transaction_type: u32,
    pub format: u16,
    pub conversation: Option<DdeConversationToken>,
    pub string_1: Option<DdeStringToken>,
    pub string_2: Option<DdeStringToken>,
    pub data: Option<DdeDataToken>,
    pub data_snapshot: Option<Vec<u8>>,
    pub data_1: u32,
    pub data_2: u32,
}

/// Validated semantic outcome returned by a guest DDE callback. A data handle
/// is a guest token and must be resolved by the runtime before reaching DDEML.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DdeCallbackResult {
    NoData,
    Data(DdeDataToken),
    Scalar(u32),
}

/// The Win16 DDEML `CONVCONTEXT16` projection. The guest ABI uses a 16-bit
/// size field and does not contain the native security QoS structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DdeConvContext16 {
    pub flags: u16,
    pub country_id: u16,
    pub code_page: i16,
    pub language_id: u32,
    pub security: u32,
}

impl DdeConvContext16 {
    pub const SIZE: usize = 16;

    pub fn decode(bytes: &[u8]) -> Result<Self, DdeLayoutError> {
        if bytes.len() < Self::SIZE {
            return Err(DdeLayoutError::Truncated {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        let declared = u16::from_le_bytes([bytes[0], bytes[1]]);
        if usize::from(declared) != Self::SIZE {
            return Err(DdeLayoutError::InvalidDeclaredSize {
                expected: Self::SIZE,
                actual: declared,
            });
        }
        Ok(Self {
            flags: u16::from_le_bytes([bytes[2], bytes[3]]),
            country_id: u16::from_le_bytes([bytes[4], bytes[5]]),
            code_page: i16::from_le_bytes([bytes[6], bytes[7]]),
            language_id: u32::from_le_bytes(bytes[8..12].try_into().expect("fixed-width slice")),
            security: u32::from_le_bytes(bytes[12..16].try_into().expect("fixed-width slice")),
        })
    }

    /// Encode the callback-visible Win16 structure with its fixed ABI size.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..2].copy_from_slice(&(Self::SIZE as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.country_id.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.code_page.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.language_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.security.to_le_bytes());
        bytes
    }
}

/// Win16 CONVINFO layout: fixed DWORD and WORD fields followed by the
/// 16-byte CONVCONTEXT16. Runtime code resolves every handle field to a guest
/// token before constructing this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DdeConvInfo16 {
    pub size: u32,
    pub user_handle: u32,
    pub conversation_partner: u32,
    pub service_partner: u32,
    pub service_requested: u32,
    pub topic: u32,
    pub item: u32,
    pub format: u16,
    pub transaction_type: u16,
    pub status: u16,
    pub conversation_state: u16,
    pub last_error: u16,
    pub conversation_list: u32,
    pub context: DdeConvContext16,
}

impl DdeConvInfo16 {
    pub const SIZE: usize = 58;

    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        let mut offset = 0;
        for value in [
            self.size,
            self.user_handle,
            self.conversation_partner,
            self.service_partner,
            self.service_requested,
            self.topic,
            self.item,
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            offset += 4;
        }
        for value in [
            self.format,
            self.transaction_type,
            self.status,
            self.conversation_state,
            self.last_error,
        ] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            offset += 2;
        }
        bytes[offset..offset + 4].copy_from_slice(&self.conversation_list.to_le_bytes());
        offset += 4;
        bytes[offset..].copy_from_slice(&self.context.encode());
        bytes
    }

    /// DDEML copies no more than the caller-declared structure size.
    pub fn encode_prefix(self, capacity: usize) -> Vec<u8> {
        let encoded = self.encode();
        encoded[..capacity.min(Self::SIZE)].to_vec()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DdeLayoutError {
    Truncated { expected: usize, actual: usize },
    InvalidDeclaredSize { expected: usize, actual: u16 },
}

/// The callback result class is encoded in the high bits of `XTYP`.
pub mod callback_class {
    pub const MASK: u32 = 0xFC00;
    pub const BOOL: u32 = 0x1000;
    pub const DATA: u32 = 0x2000;
    pub const FLAGS: u32 = 0x4000;
    pub const NOTIFICATION: u32 = 0x8000;
    pub const BLOCK: u32 = u32::MAX;

    pub fn from_transaction_type(transaction_type: u32) -> Option<u32> {
        match transaction_type & MASK {
            BOOL => Some(BOOL),
            DATA => Some(DATA),
            FLAGS => Some(FLAGS),
            NOTIFICATION => Some(NOTIFICATION),
            _ => None,
        }
    }
}

/// DDEML transaction identifiers from the Windows 3.1 SDK `DDEML.H`.
pub mod transaction_type {
    pub const TYPE_MASK: u32 = 0x00f0;
    pub const CONNECT: u32 = 0x1062;
    pub const DISCONNECT: u32 = 0x80c2;
    pub const WILDCONNECT: u32 = 0x20e2;

    pub const fn base(value: u32) -> u32 {
        value & TYPE_MASK
    }
}

/// DDEML initialization flag values taken from the Windows 3.1 SDK `DDEML.H`.
pub mod initialization_flag {
    /// Enables monitor callbacks with version-specific MON* payload layouts.
    pub const APPCLASS_MONITOR: u32 = 0x0000_0001;
}

/// Win16 DDEML error values from the Windows 3.1 SDK `DDEML.H` contract
/// (`files/include/DDEML.H`, DMLERR_NO_ERROR through DMLERR_LAST, lines 312–335;
/// Windows 3.1 Programmer's Reference Volume 2, printed pages 179 and 183 for
/// DMLERR_SYS_ERROR's meaning and DdeInitialize's documented return set).
/// These are guest API values, not host diagnostic categories.
pub mod error {
    pub const NO_ERROR: u16 = 0;
    pub const ADVACKTIMEOUT: u16 = 0x4000;
    pub const BUSY: u16 = 0x4001;
    pub const DATAACKTIMEOUT: u16 = 0x4002;
    pub const DLL_NOT_INITIALIZED: u16 = 0x4003;
    pub const DLL_USAGE: u16 = 0x4004;
    pub const EXECACKTIMEOUT: u16 = 0x4005;
    pub const INVALIDPARAMETER: u16 = 0x4006;
    pub const LOW_MEMORY: u16 = 0x4007;
    pub const MEMORY_ERROR: u16 = 0x4008;
    pub const NOTPROCESSED: u16 = 0x4009;
    pub const NO_CONV_ESTABLISHED: u16 = 0x400a;
    pub const POKEACKTIMEOUT: u16 = 0x400b;
    pub const POSTMSG_FAILED: u16 = 0x400c;
    pub const REENTRANCY: u16 = 0x400d;
    pub const SERVER_DIED: u16 = 0x400e;
    pub const SYS_ERROR: u16 = 0x400f;
    pub const UNADVACKTIMEOUT: u16 = 0x4010;
    pub const UNFOUND_QUEUE_ID: u16 = 0x4011;
}

/// Data-handle creation flag which leaves ownership with the creating
/// application. Other handles are consumed by DDEML after use where its API
/// contract specifies automatic release.
pub mod data_flag {
    pub const HDATA_APPOWNED: u16 = 0x0001;
}
