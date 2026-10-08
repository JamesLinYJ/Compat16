//! Platform-neutral COM identity and Win16 interface-reference bookkeeping.
//!
//! Guest pointers and host object keys are intentionally opaque values here.
//! Native COM pointers, guest memory, vtables, and method dispatch belong to
//! their respective host and Win16 runtime adapters.

use std::collections::BTreeMap;
use std::fmt;

/// COM GUID fields in their logical Windows layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Decode a GUID copied from a Win16/Win32 `GUID` structure.
    pub fn from_memory_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 16] = bytes.get(..16)?.try_into().ok()?;
        Some(Self {
            data1: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            data2: u16::from_le_bytes(bytes[4..6].try_into().ok()?),
            data3: u16::from_le_bytes(bytes[6..8].try_into().ok()?),
            data4: bytes[8..16].try_into().ok()?,
        })
    }

    /// Encode the Windows in-memory layout without retaining a borrowed buffer.
    pub fn to_memory_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    /// Parse the canonical ASCII form `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
    /// or the same form without braces. The input is expected to be an owned,
    /// checked guest string at the ABI boundary.
    pub fn parse_ascii(value: &[u8]) -> Result<Self, GuidParseError> {
        let value = match (value.first(), value.last()) {
            (Some(b'{'), Some(b'}')) => &value[1..value.len() - 1],
            _ => value,
        };
        if value.len() != 36 {
            return Err(GuidParseError::InvalidLength);
        }
        for separator in [8, 13, 18, 23] {
            if value[separator] != b'-' {
                return Err(GuidParseError::InvalidSeparator);
            }
        }

        let mut digits = [0u8; 32];
        let mut digit_index = 0;
        for (index, byte) in value.iter().copied().enumerate() {
            if [8, 13, 18, 23].contains(&index) {
                continue;
            }
            digits[digit_index] = hex_nibble(byte).ok_or(GuidParseError::InvalidDigit)?;
            digit_index += 1;
        }

        let byte_at = |index: usize| (digits[index] << 4) | digits[index + 1];
        let data1 = u32::from_be_bytes([byte_at(0), byte_at(2), byte_at(4), byte_at(6)]);
        let data2 = u16::from_be_bytes([byte_at(8), byte_at(10)]);
        let data3 = u16::from_be_bytes([byte_at(12), byte_at(14)]);
        let mut data4 = [0; 8];
        for index in 0..8 {
            data4[index] = (digits[16 + index * 2] << 4) | digits[17 + index * 2];
        }
        Ok(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Format the GUID as uppercase canonical ASCII, including braces and NUL.
    pub fn to_ascii_nul_terminated(self) -> [u8; 39] {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut output = [0; 39];
        output[0] = b'{';
        output[9] = b'-';
        output[14] = b'-';
        output[19] = b'-';
        output[24] = b'-';
        output[37] = b'}';
        output[38] = 0;

        let fields = [
            (self.data1 as u64, 8, 1),
            (self.data2 as u64, 4, 10),
            (self.data3 as u64, 4, 15),
        ];
        for (value, width, start) in fields {
            for digit in 0..width {
                let shift = (width - digit - 1) * 4;
                output[start + digit] = HEX[((value >> shift) & 0xf) as usize];
            }
        }
        for (index, byte) in self.data4.iter().copied().enumerate() {
            let start = if index < 2 {
                20 + index * 2
            } else {
                25 + (index - 2) * 2
            };
            output[start] = HEX[(byte >> 4) as usize];
            output[start + 1] = HEX[(byte & 0xf) as usize];
        }
        output
    }
}

/// Standard OLE interface identifiers also present in the checked-in Win16
/// export inventory (`COMPOBJ` interface variables, ordinals 38–54).
pub const IID_IUNKNOWN: Guid = Guid::new(0, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IMALLOC: Guid = Guid::new(2, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_ILOCK_BYTES: Guid = Guid::new(0x0000_000a, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_ISTORAGE: Guid = Guid::new(0x0000_000b, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_ISTREAM: Guid = Guid::new(0x0000_000c, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IBIND_CTX: Guid = Guid::new(0x0000_000e, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IMONIKER: Guid = Guid::new(0x0000_000f, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IDATA_OBJECT: Guid = Guid::new(0x0000_010e, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IPERSIST_STREAM: Guid = Guid::new(0x0000_0109, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IPERSIST_STORAGE: Guid = Guid::new(0x0000_010a, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IOLE_CLIENT_SITE: Guid = Guid::new(0x0000_0118, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
pub const IID_IRUNNING_OBJECT_TABLE: Guid =
    Guid::new(0x0000_0010, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);

impl fmt::Display for Guid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_ascii_nul_terminated();
        // The formatter only accepts UTF-8; every emitted byte is ASCII.
        formatter.write_str(std::str::from_utf8(&bytes[..38]).expect("GUID text is ASCII"))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Why a host adapter returned a COM object reference to the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceDisposition {
    /// The returned native reference is owned by this result and can back one
    /// guest reference without another native `AddRef`.
    Owned,
    /// The result is borrowed; the runtime must acquire a native reference
    /// before exposing it to guest code.
    Borrowed,
}

/// Opaque stable identity in the host COM-object table. It is not a pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ComObjectId(pub u64);

/// A guest COM interface pointer represented only by its guest FAR address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GuestComPointer(pub u32);

/// One interface view of a canonical COM identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GuestInterfaceRef {
    pub object: ComObjectId,
    pub iid: Guid,
}

/// Errors from guest-side COM pointer and reference bookkeeping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComReferenceError {
    NullObject,
    NullGuestPointer,
    ObjectAlreadyBound,
    ObjectNotBound,
    InterfaceAlreadyBound,
    GuestPointerAlreadyBound,
    GuestPointerNotBound,
    ReferenceCountOverflow,
    ReferenceCountUnderflow,
}

impl fmt::Display for ComReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NullObject => "COM object identity zero is reserved",
            Self::NullGuestPointer => "COM guest interface pointer is null",
            Self::ObjectAlreadyBound => "COM object identity is already bound",
            Self::ObjectNotBound => "COM object identity is not bound",
            Self::InterfaceAlreadyBound => "COM interface identity is already bound",
            Self::GuestPointerAlreadyBound => "COM guest interface pointer is already bound",
            Self::GuestPointerNotBound => "COM guest interface pointer is not bound",
            Self::ReferenceCountOverflow => "COM guest reference count overflowed",
            Self::ReferenceCountUnderflow => "COM guest reference count underflowed",
        })
    }
}

impl std::error::Error for ComReferenceError {}

/// Result of releasing one guest COM reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComRelease {
    pub object: ComObjectId,
    pub references_remaining: u32,
    /// Guest interface addresses to invalidate when the canonical identity's
    /// last reference is released.
    pub removed_pointers: Vec<GuestComPointer>,
}

/// Maps guest proxy addresses to canonical COM identities and owns the shared
/// guest-side reference count for all interface pointers of each identity.
#[derive(Clone, Debug, Default)]
pub struct GuestComReferences {
    by_pointer: BTreeMap<GuestComPointer, GuestInterfaceRef>,
    by_interface: BTreeMap<GuestInterfaceRef, GuestComPointer>,
    references: BTreeMap<ComObjectId, u32>,
}

impl GuestComReferences {
    /// Bind the first guest interface pointer for an owned host reference.
    pub fn bind_initial(
        &mut self,
        object: ComObjectId,
        iid: Guid,
        pointer: GuestComPointer,
    ) -> Result<(), ComReferenceError> {
        if object.0 == 0 {
            return Err(ComReferenceError::NullObject);
        }
        if pointer.0 == 0 {
            return Err(ComReferenceError::NullGuestPointer);
        }
        if self.references.contains_key(&object) {
            return Err(ComReferenceError::ObjectAlreadyBound);
        }
        let interface = GuestInterfaceRef { object, iid };
        self.ensure_pointer_available(pointer)?;
        self.references.insert(object, 1);
        self.by_pointer.insert(pointer, interface);
        self.by_interface.insert(interface, pointer);
        Ok(())
    }

    /// Add a new interface proxy returned by successful host `QueryInterface`.
    /// The successful native query contributes one owned COM reference.
    pub fn bind_queried_interface(
        &mut self,
        object: ComObjectId,
        iid: Guid,
        pointer: GuestComPointer,
    ) -> Result<u32, ComReferenceError> {
        if pointer.0 == 0 {
            return Err(ComReferenceError::NullGuestPointer);
        }
        let count = self
            .references
            .get(&object)
            .copied()
            .ok_or(ComReferenceError::ObjectNotBound)?;
        let interface = GuestInterfaceRef { object, iid };
        if self.by_interface.contains_key(&interface) {
            return Err(ComReferenceError::InterfaceAlreadyBound);
        }
        self.ensure_pointer_available(pointer)?;
        let next = count
            .checked_add(1)
            .ok_or(ComReferenceError::ReferenceCountOverflow)?;
        self.references.insert(object, next);
        self.by_pointer.insert(pointer, interface);
        self.by_interface.insert(interface, pointer);
        Ok(next)
    }

    /// Find an already allocated guest proxy for an interface view.
    pub fn pointer_for(&self, object: ComObjectId, iid: Guid) -> Option<GuestComPointer> {
        self.by_interface
            .get(&GuestInterfaceRef { object, iid })
            .copied()
    }

    /// Resolve a guest proxy pointer to its canonical object key and IID.
    pub fn interface_for_pointer(&self, pointer: GuestComPointer) -> Option<GuestInterfaceRef> {
        self.by_pointer.get(&pointer).copied()
    }

    /// Increment the canonical identity's count for guest `IUnknown::AddRef`.
    pub fn add_ref(&mut self, pointer: GuestComPointer) -> Result<u32, ComReferenceError> {
        let interface = self
            .interface_for_pointer(pointer)
            .ok_or(ComReferenceError::GuestPointerNotBound)?;
        let count = self
            .references
            .get(&interface.object)
            .copied()
            .ok_or(ComReferenceError::ObjectNotBound)?;
        let next = count
            .checked_add(1)
            .ok_or(ComReferenceError::ReferenceCountOverflow)?;
        self.references.insert(interface.object, next);
        Ok(next)
    }

    /// Release one guest reference. An empty `removed_pointers` means the
    /// object remains live; otherwise all guest proxy addresses are retired.
    pub fn release(&mut self, pointer: GuestComPointer) -> Result<ComRelease, ComReferenceError> {
        let interface = self
            .interface_for_pointer(pointer)
            .ok_or(ComReferenceError::GuestPointerNotBound)?;
        let count = self
            .references
            .get(&interface.object)
            .copied()
            .ok_or(ComReferenceError::ObjectNotBound)?;
        let next = count
            .checked_sub(1)
            .ok_or(ComReferenceError::ReferenceCountUnderflow)?;
        let mut removed_pointers = Vec::new();
        if next == 0 {
            self.references.remove(&interface.object);
            let interfaces: Vec<_> = self
                .by_interface
                .keys()
                .filter(|key| key.object == interface.object)
                .copied()
                .collect();
            for key in interfaces {
                if let Some(guest_pointer) = self.by_interface.remove(&key) {
                    self.by_pointer.remove(&guest_pointer);
                    removed_pointers.push(guest_pointer);
                }
            }
        } else {
            self.references.insert(interface.object, next);
        }
        Ok(ComRelease {
            object: interface.object,
            references_remaining: next,
            removed_pointers,
        })
    }

    /// Current guest reference count, shared across all interfaces of an object.
    pub fn reference_count(&self, object: ComObjectId) -> Option<u32> {
        self.references.get(&object).copied()
    }

    /// Forget an object during runtime teardown and return its guest proxy
    /// addresses so the runtime can release their guest-memory allocations.
    pub fn forget_object(&mut self, object: ComObjectId) -> Vec<GuestComPointer> {
        self.references.remove(&object);
        let interfaces: Vec<_> = self
            .by_interface
            .keys()
            .filter(|key| key.object == object)
            .copied()
            .collect();
        let mut pointers = Vec::with_capacity(interfaces.len());
        for interface in interfaces {
            if let Some(pointer) = self.by_interface.remove(&interface) {
                self.by_pointer.remove(&pointer);
                pointers.push(pointer);
            }
        }
        pointers
    }

    fn ensure_pointer_available(&self, pointer: GuestComPointer) -> Result<(), ComReferenceError> {
        if self.by_pointer.contains_key(&pointer) {
            Err(ComReferenceError::GuestPointerAlreadyBound)
        } else {
            Ok(())
        }
    }
}

/// A syntactically invalid GUID string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuidParseError {
    InvalidLength,
    InvalidSeparator,
    InvalidDigit,
}

impl fmt::Display for GuidParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "GUID text must contain 36 characters, optionally inside braces",
            Self::InvalidSeparator => "GUID text has an invalid separator",
            Self::InvalidDigit => "GUID text contains a non-hexadecimal digit",
        })
    }
}

impl std::error::Error for GuidParseError {}
