//! Shared guest machine contracts. Native addresses do not enter this crate.
#![forbid(unsafe_code)]

pub mod memory;
pub mod arena;
pub mod host_refs;
pub mod io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// Address in simulated guest RAM; never an address in host physical memory.
pub struct PhysAddr(pub u32);
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LinearAddr(pub u32);
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Selector(pub u16);
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OwnerId(pub u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GuestHandle(pub u16);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryError {
    AddressOverflow,
    OutOfBounds { address: u32, length: usize },
    ReadOnly { address: u32, length: usize },
    AllocationFailed,
    InvalidMapping,
    MappingIdentityExhausted,
    RoutingEpochExhausted,
    /// The backing provider cannot serialize an architectural locked update.
    AtomicityUnavailable,
    /// The backing store failed to transfer a prevalidated range. A partial
    /// transfer is not rolled back: callers must stop guest execution.
    StorageAccess {
        address: u32,
        length: usize,
        transferred: usize,
        write: bool,
        os_error: Option<i32>,
    },
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressOverflow => {
                f.write_str("guest memory address calculation overflowed the 32-bit address space")
            }
            Self::OutOfBounds { address, length } => write!(
                f,
                "guest memory range at 0x{address:08X} for {length} bytes (0x{length:X}) exceeds configured memory"
            ),
            Self::ReadOnly { address, length } => write!(
                f,
                "write of {length} bytes (0x{length:X}) at guest address 0x{address:08X} intersects read-only memory"
            ),
            Self::AllocationFailed => f.write_str("unable to allocate guest memory storage"),
            Self::InvalidMapping => f.write_str("invalid guest memory mapping request"),
            Self::MappingIdentityExhausted => f.write_str("guest memory mapping identities exhausted"),
            Self::RoutingEpochExhausted => f.write_str("guest memory routing identities exhausted"),
            Self::AtomicityUnavailable => f.write_str("guest memory provider cannot serialize an atomic update"),
            Self::StorageAccess { address, length, transferred, write, os_error } => {
                let operation = if *write { "write" } else { "read" };
                write!(f, "guest backing {operation} at 0x{address:08X} transferred {transferred} of {length} bytes")?;
                if let Some(code) = os_error {
                    write!(f, ": {}", std::io::Error::from_raw_os_error(*code))?;
                }
                Ok(())
            }
        }
    }
}
impl std::error::Error for MemoryError {}

/// One ordered byte range in a guest-memory atomic update. `offset` is always
/// relative to the receiving guest provider; it is never a host pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicMemoryRange {
    pub offset: u32,
    pub length: usize,
}

pub trait GuestMemory {
    fn len(&self) -> u32;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        let length32 = u32::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
        let end = address.0.checked_add(length32).ok_or(MemoryError::AddressOverflow)?;
        if end > self.len() {
            return Err(MemoryError::OutOfBounds { address: address.0, length });
        }
        Ok(())
    }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate_read(address, length)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError>;
    /// Validate the entire operation before changing any byte. A backing-store
    /// transfer failure must propagate, including its partial-transfer extent;
    /// it cannot be treated as a recoverable guest protocol error or undone by
    /// restoring a stale snapshot over externally mutable memory.
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError>;
    /// Atomically read, transform, and write the bytes covered by `ranges`.
    /// Ranges concatenate in guest operand order and must cover `value`.
    /// Implementations that cannot serialize the entire operation return
    /// `AtomicityUnavailable` before invoking `update`.
    fn atomic_update(
        &mut self,
        _ranges: &[AtomicMemoryRange],
        _value: &mut [u8],
        _update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        Err(MemoryError::AtomicityUnavailable)
    }
    fn read_u8(&self, address: PhysAddr) -> Result<u8, MemoryError> {
        let mut b = [0]; self.read(address, &mut b)?; Ok(b[0])
    }
    fn read_u16(&self, address: PhysAddr) -> Result<u16, MemoryError> {
        let mut b = [0; 2]; self.read(address, &mut b)?; Ok(u16::from_le_bytes(b))
    }
    fn read_u32(&self, address: PhysAddr) -> Result<u32, MemoryError> {
        let mut b = [0; 4]; self.read(address, &mut b)?; Ok(u32::from_le_bytes(b))
    }
    fn write_u8(&mut self, address: PhysAddr, value: u8) -> Result<(), MemoryError> {
        self.write(address, &[value])
    }
    fn write_u16(&mut self, address: PhysAddr, value: u16) -> Result<(), MemoryError> {
        self.write(address, &value.to_le_bytes())
    }
    fn write_u32(&mut self, address: PhysAddr, value: u32) -> Result<(), MemoryError> {
        self.write(address, &value.to_le_bytes())
    }
}

/// Preserve the complete memory contract when a subsystem borrows a guest
/// memory implementation through `&mut`, including custom access validators.
impl<T: GuestMemory + ?Sized> GuestMemory for &mut T {
    fn len(&self) -> u32 { (**self).len() }
    fn is_empty(&self) -> bool { (**self).is_empty() }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        (**self).validate_read(address, length)
    }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        (**self).validate_write(address, length)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        (**self).read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        (**self).write(address, bytes)
    }
    fn atomic_update(
        &mut self,
        ranges: &[AtomicMemoryRange],
        value: &mut [u8],
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        (**self).atomic_update(ranges, value, update)
    }
    fn read_u8(&self, address: PhysAddr) -> Result<u8, MemoryError> { (**self).read_u8(address) }
    fn read_u16(&self, address: PhysAddr) -> Result<u16, MemoryError> { (**self).read_u16(address) }
    fn read_u32(&self, address: PhysAddr) -> Result<u32, MemoryError> { (**self).read_u32(address) }
    fn write_u8(&mut self, address: PhysAddr, value: u8) -> Result<(), MemoryError> { (**self).write_u8(address, value) }
    fn write_u16(&mut self, address: PhysAddr, value: u16) -> Result<(), MemoryError> { (**self).write_u16(address, value) }
    fn write_u32(&mut self, address: PhysAddr, value: u32) -> Result<(), MemoryError> { (**self).write_u32(address, value) }
}

/// Architectural registers preserve upper halves for later 386 instructions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Registers {
    pub eax: u32, pub ebx: u32, pub ecx: u32, pub edx: u32,
    pub esp: u32, pub ebp: u32, pub esi: u32, pub edi: u32,
    pub eip: u32, pub eflags: u32,
    pub cs: u16, pub ds: u16, pub es: u16, pub ss: u16,
    pub fs: u16, pub gs: u16,
}

macro_rules! word_accessors {
    ($($get:ident, $set:ident, $field:ident);* $(;)?) => {$ (
        pub fn $get(&self) -> u16 { self.$field as u16 }
        pub fn $set(&mut self, value: u16) {
            self.$field = (self.$field & 0xffff_0000) | u32::from(value);
        }
    )*};
}
impl Registers {
    word_accessors! {
        ax, set_ax, eax; bx, set_bx, ebx; cx, set_cx, ecx; dx, set_dx, edx;
        sp, set_sp, esp; bp, set_bp, ebp; si, set_si, esi; di, set_di, edi;
        ip, set_ip, eip;
    }
    pub fn al(&self) -> u8 { self.eax as u8 }
    pub fn ah(&self) -> u8 { (self.eax >> 8) as u8 }
    pub fn set_al(&mut self, value: u8) { self.eax = (self.eax & !0xff) | u32::from(value); }
    pub fn set_ah(&mut self, value: u8) { self.eax = (self.eax & !0xff00) | (u32::from(value) << 8); }
    pub fn bl(&self) -> u8 { self.ebx as u8 }
    pub fn bh(&self) -> u8 { (self.ebx >> 8) as u8 }
    pub fn cl(&self) -> u8 { self.ecx as u8 }
    pub fn ch(&self) -> u8 { (self.ecx >> 8) as u8 }
    pub fn dl(&self) -> u8 { self.edx as u8 }
    pub fn dh(&self) -> u8 { (self.edx >> 8) as u8 }
    pub fn set_bl(&mut self, value: u8) { self.ebx = (self.ebx & !0xff) | u32::from(value); }
    pub fn set_bh(&mut self, value: u8) { self.ebx = (self.ebx & !0xff00) | (u32::from(value) << 8); }
    pub fn set_cl(&mut self, value: u8) { self.ecx = (self.ecx & !0xff) | u32::from(value); }
    pub fn set_ch(&mut self, value: u8) { self.ecx = (self.ecx & !0xff00) | (u32::from(value) << 8); }
    pub fn set_dl(&mut self, value: u8) { self.edx = (self.edx & !0xff) | u32::from(value); }
    pub fn set_dh(&mut self, value: u8) { self.edx = (self.edx & !0xff00) | (u32::from(value) << 8); }
    pub fn carry(&self) -> bool { self.eflags & 1 != 0 }
    pub fn set_carry(&mut self, set: bool) {
        self.eflags = (self.eflags & !1) | u32::from(set);
    }
}

pub fn real_address(segment: u16, offset: u16) -> PhysAddr {
    PhysAddr(u32::from(segment) * 16 + u32::from(offset))
}
