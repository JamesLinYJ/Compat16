//! Checked value conversions for the Win16 Winsock 1.x ABI.
//!
//! All structures in this module are guest layouts. Native SOCKET values,
//! hostent pointers, and native pointers must stay in the Windows host adapter.

use std::fmt;

pub const FD_SETSIZE_16: usize = 64;
pub const SOCKADDR_MAX_16: usize = 256;
pub const WSADATA16_SIZE: usize = 398;
pub const HOSTENT16_SIZE: usize = 16;
pub const PROTOENT16_SIZE: usize = 10;
pub const SERVENT16_SIZE: usize = 14;

pub const WSAEINTR: i32 = 10004;
pub const WSAEBADF: i32 = 10009;
pub const WSAEACCES: i32 = 10013;
pub const WSAEFAULT: i32 = 10014;
pub const WSAEINVAL: i32 = 10022;
pub const WSAEMFILE: i32 = 10024;
pub const WSAEWOULDBLOCK: i32 = 10035;
pub const WSAEINPROGRESS: i32 = 10036;
pub const WSAEALREADY: i32 = 10037;
pub const WSAENOTSOCK: i32 = 10038;
pub const WSAEDESTADDRREQ: i32 = 10039;
pub const WSAEMSGSIZE: i32 = 10040;
pub const WSAEPROTOTYPE: i32 = 10041;
pub const WSAENOPROTOOPT: i32 = 10042;
pub const WSAEPROTONOSUPPORT: i32 = 10043;
pub const WSAESOCKTNOSUPPORT: i32 = 10044;
pub const WSAEOPNOTSUPP: i32 = 10045;
pub const WSAEPFNOSUPPORT: i32 = 10046;
pub const WSAEAFNOSUPPORT: i32 = 10047;
pub const WSAEADDRINUSE: i32 = 10048;
pub const WSAEADDRNOTAVAIL: i32 = 10049;
pub const WSAENETDOWN: i32 = 10050;
pub const WSAENETUNREACH: i32 = 10051;
pub const WSAENETRESET: i32 = 10052;
pub const WSAECONNABORTED: i32 = 10053;
pub const WSAECONNRESET: i32 = 10054;
pub const WSAENOBUFS: i32 = 10055;
pub const WSAEISCONN: i32 = 10056;
pub const WSAENOTCONN: i32 = 10057;
pub const WSAESHUTDOWN: i32 = 10058;
pub const WSAETIMEDOUT: i32 = 10060;
pub const WSAECONNREFUSED: i32 = 10061;
pub const WSAEHOSTUNREACH: i32 = 10065;
pub const WSASYSNOTREADY: i32 = 10091;
pub const WSAVERNOTSUPPORTED: i32 = 10092;
pub const WSANOTINITIALISED: i32 = 10093;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestNetworkLayoutError {
    Truncated { expected_at_least: usize, actual: usize },
    InvalidCount { count: usize, maximum: usize },
    InvalidFamily(u16),
    InvalidAddressLength(usize),
    AddressTooLarge(usize),
    InvalidFarPointer,
    CapacityExceeded { required: usize, available: usize },
}

impl fmt::Display for GuestNetworkLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { expected_at_least, actual } => write!(
                f, "Win16 network structure is truncated: expected at least {expected_at_least} bytes, received {actual}"
            ),
            Self::InvalidCount { count, maximum } => write!(
                f, "Win16 fd_set contains {count} sockets; the supported maximum is {maximum}"
            ),
            Self::InvalidFamily(family) => write!(f, "Win16 socket address family {family} is unsupported"),
            Self::InvalidAddressLength(length) => write!(f, "Win16 socket address length {length} is invalid"),
            Self::AddressTooLarge(length) => write!(f, "Win16 socket address length {length} exceeds the bounded guest layout"),
            Self::InvalidFarPointer => f.write_str("Win16 far pointer cannot address the requested network result"),
            Self::CapacityExceeded { required, available } => write!(
                f, "Win16 network result needs {required} bytes, but the guest buffer has {available}"
            ),
        }
    }
}

impl std::error::Error for GuestNetworkLayoutError {}

/// IPv4 address fields decoded from a Win16 `SOCKADDR_IN` (16 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketAddressV4 {
    pub port: u16,
    pub address: [u8; 4],
}

/// A validated socket address copy. Unknown families are preserved as bytes;
/// the host adapter decides whether its provider accepts that family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketAddress16 {
    Ipv4(SocketAddressV4),
    Other { family: u16, bytes: Vec<u8> },
}

impl SocketAddress16 {
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestNetworkLayoutError> {
        if bytes.len() < 2 {
            return Err(GuestNetworkLayoutError::Truncated { expected_at_least: 2, actual: bytes.len() });
        }
        if bytes.len() > SOCKADDR_MAX_16 {
            return Err(GuestNetworkLayoutError::AddressTooLarge(bytes.len()));
        }
        let family = u16::from_le_bytes([bytes[0], bytes[1]]);
        if family == 2 {
            if bytes.len() < 16 {
                return Err(GuestNetworkLayoutError::InvalidAddressLength(bytes.len()));
            }
            return Ok(Self::Ipv4(SocketAddressV4 {
                port: u16::from_be_bytes([bytes[2], bytes[3]]),
                address: [bytes[4], bytes[5], bytes[6], bytes[7]],
            }));
        }
        Ok(Self::Other { family, bytes: bytes.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ipv4(address) => {
                let mut output = vec![0u8; 16];
                output[0..2].copy_from_slice(&2u16.to_le_bytes());
                output[2..4].copy_from_slice(&address.port.to_be_bytes());
                output[4..8].copy_from_slice(&address.address);
                output
            }
            Self::Other { bytes, .. } => bytes.clone(),
        }
    }
}

/// The 16-bit Winsock `fd_set`: WORD count followed by WORD socket IDs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FdSet16(pub Vec<u16>);

impl FdSet16 {
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestNetworkLayoutError> {
        if bytes.len() < 2 {
            return Err(GuestNetworkLayoutError::Truncated { expected_at_least: 2, actual: bytes.len() });
        }
        let count = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if count > FD_SETSIZE_16 {
            return Err(GuestNetworkLayoutError::InvalidCount { count, maximum: FD_SETSIZE_16 });
        }
        let required = 2 + count * 2;
        if bytes.len() < required {
            return Err(GuestNetworkLayoutError::Truncated { expected_at_least: required, actual: bytes.len() });
        }
        let sockets = bytes[2..required]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Ok(Self(sockets))
    }

    pub fn encode(&self, capacity: usize) -> Result<Vec<u8>, GuestNetworkLayoutError> {
        if self.0.len() > FD_SETSIZE_16 {
            return Err(GuestNetworkLayoutError::InvalidCount { count: self.0.len(), maximum: FD_SETSIZE_16 });
        }
        let required = 2 + self.0.len() * 2;
        if capacity < required {
            return Err(GuestNetworkLayoutError::CapacityExceeded { required, available: capacity });
        }
        let mut bytes = Vec::with_capacity(required);
        bytes.extend_from_slice(&(self.0.len() as u16).to_le_bytes());
        for socket in &self.0 { bytes.extend_from_slice(&socket.to_le_bytes()); }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeValue16 {
    pub seconds: i32,
    pub microseconds: i32,
}

impl TimeValue16 {
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestNetworkLayoutError> {
        if bytes.len() < 8 {
            return Err(GuestNetworkLayoutError::Truncated { expected_at_least: 8, actual: bytes.len() });
        }
        Ok(Self {
            seconds: i32::from_le_bytes(bytes[0..4].try_into().expect("fixed width slice")),
            microseconds: i32::from_le_bytes(bytes[4..8].try_into().expect("fixed width slice")),
        })
    }
}

/// The Win16 WSADATA record uses a 16-bit far `lpVendorInfo`, independent of
/// the host architecture's WSADATA member ordering and native pointer width.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WsaData16 {
    pub version: u16,
    pub high_version: u16,
    pub description: Vec<u8>,
    pub system_status: Vec<u8>,
    pub max_sockets: u16,
    pub max_udp_datagram: u16,
}

impl WsaData16 {
    pub fn encode(&self) -> [u8; WSADATA16_SIZE] {
        let mut output = [0u8; WSADATA16_SIZE];
        output[0..2].copy_from_slice(&self.version.to_le_bytes());
        output[2..4].copy_from_slice(&self.high_version.to_le_bytes());
        copy_terminated(&self.description, &mut output[4..261]);
        copy_terminated(&self.system_status, &mut output[261..390]);
        output[390..392].copy_from_slice(&self.max_sockets.to_le_bytes());
        output[392..394].copy_from_slice(&self.max_udp_datagram.to_le_bytes());
        // lpVendorInfo is null. Its guest slot occupies the final four bytes.
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEntryOwned {
    pub name: Vec<u8>,
    pub aliases: Vec<Vec<u8>>,
    pub address_type: u16,
    pub address_length: u16,
    pub addresses: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolEntryOwned {
    pub name: Vec<u8>,
    pub aliases: Vec<Vec<u8>>,
    pub protocol: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceEntryOwned {
    pub name: Vec<u8>,
    pub aliases: Vec<Vec<u8>>,
    /// Winsock stores the port in network byte order in `servent`.
    pub port_network_order: u16,
    pub protocol: Vec<u8>,
}

/// A base selector plus its starting offset for building guest FAR pointers.
/// `offset + size` must fit in one 64-KiB segment; the runtime allocates this
/// backing range in guest memory and writes the returned bytes there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestFarBase16 {
    pub selector: u16,
    pub offset: u16,
}

/// Serialize host-owned name-service results into Win16 pointer-rich records.
/// Every pointer in the emitted block names another byte inside the same guest
/// allocation; none of the native host pointers are copied or exposed.
pub fn encode_host_entry_16(
    base: GuestFarBase16,
    entry: &HostEntryOwned,
) -> Result<Vec<u8>, GuestNetworkLayoutError> {
    let mut block = vec![0; HOSTENT16_SIZE];
    let name = append_z(&mut block, &entry.name, base)?;
    let aliases = append_pointer_vector(&mut block, &entry.aliases.iter().map(Vec::as_slice).collect::<Vec<_>>(), base)?;
    let addresses = append_address_vector(&mut block, &entry.addresses, base)?;
    put_far(&mut block, 0, name);
    put_far(&mut block, 4, aliases);
    block[8..10].copy_from_slice(&entry.address_type.to_le_bytes());
    block[10..12].copy_from_slice(&entry.address_length.to_le_bytes());
    put_far(&mut block, 12, addresses);
    Ok(block)
}

pub fn encode_protocol_entry_16(
    base: GuestFarBase16,
    entry: &ProtocolEntryOwned,
) -> Result<Vec<u8>, GuestNetworkLayoutError> {
    let mut block = vec![0; PROTOENT16_SIZE];
    let name = append_z(&mut block, &entry.name, base)?;
    let aliases = append_pointer_vector(&mut block, &entry.aliases.iter().map(Vec::as_slice).collect::<Vec<_>>(), base)?;
    put_far(&mut block, 0, name);
    put_far(&mut block, 4, aliases);
    block[8..10].copy_from_slice(&entry.protocol.to_le_bytes());
    Ok(block)
}

pub fn encode_service_entry_16(
    base: GuestFarBase16,
    entry: &ServiceEntryOwned,
) -> Result<Vec<u8>, GuestNetworkLayoutError> {
    let mut block = vec![0; SERVENT16_SIZE];
    let name = append_z(&mut block, &entry.name, base)?;
    let aliases = append_pointer_vector(&mut block, &entry.aliases.iter().map(Vec::as_slice).collect::<Vec<_>>(), base)?;
    let protocol = append_z(&mut block, &entry.protocol, base)?;
    put_far(&mut block, 0, name);
    put_far(&mut block, 4, aliases);
    block[8..10].copy_from_slice(&entry.port_network_order.to_le_bytes());
    put_far(&mut block, 10, protocol);
    Ok(block)
}

fn append_pointer_vector(
    block: &mut Vec<u8>,
    values: &[&[u8]],
    base: GuestFarBase16,
) -> Result<u32, GuestNetworkLayoutError> {
    let array_offset = block.len();
    block.resize(block.len() + (values.len() + 1) * 4, 0);
    let array_far = far_at(base, array_offset)?;
    for (index, value) in values.iter().enumerate() {
        let pointer = append_z(block, value, base)?;
        put_far(block, array_offset + index * 4, pointer);
    }
    Ok(array_far)
}

fn append_address_vector(
    block: &mut Vec<u8>,
    values: &[Vec<u8>],
    base: GuestFarBase16,
) -> Result<u32, GuestNetworkLayoutError> {
    let array_offset = block.len();
    block.resize(block.len() + (values.len() + 1) * 4, 0);
    let array_far = far_at(base, array_offset)?;
    for (index, value) in values.iter().enumerate() {
        let address_offset = block.len();
        block.extend_from_slice(value);
        let pointer = far_at(base, address_offset)?;
        put_far(block, array_offset + index * 4, pointer);
    }
    Ok(array_far)
}

fn append_z(
    block: &mut Vec<u8>,
    value: &[u8],
    base: GuestFarBase16,
) -> Result<u32, GuestNetworkLayoutError> {
    let offset = block.len();
    block.extend_from_slice(value.split(|byte| *byte == 0).next().unwrap_or_default());
    block.push(0);
    far_at(base, offset)
}

fn far_at(base: GuestFarBase16, relative: usize) -> Result<u32, GuestNetworkLayoutError> {
    let offset = usize::from(base.offset).checked_add(relative).ok_or(GuestNetworkLayoutError::InvalidFarPointer)?;
    let offset = u16::try_from(offset).map_err(|_| GuestNetworkLayoutError::InvalidFarPointer)?;
    Ok((u32::from(base.selector) << 16) | u32::from(offset))
}

fn put_far(block: &mut [u8], offset: usize, far: u32) {
    block[offset..offset + 4].copy_from_slice(&far.to_le_bytes());
}

fn copy_terminated(source: &[u8], destination: &mut [u8]) {
    if destination.is_empty() { return; }
    let content = source.split(|byte| *byte == 0).next().unwrap_or_default();
    let count = content.len().min(destination.len() - 1);
    destination[..count].copy_from_slice(&content[..count]);
}

