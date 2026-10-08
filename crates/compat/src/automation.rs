//! Fixed-width Win16 OLE Automation records.
//!
//! This module describes guest layouts only. It deliberately contains no
//! native COM structures or pointers; a host adapter must construct those
//! from validated values and copy results back field by field.

use crate::com::Guid;
use std::fmt;

#[path = "automation_wire.rs"]
mod automation_wire;

pub const VARIANT16_SIZE: usize = 16;
pub const VARIANT16_PAYLOAD_OFFSET: usize = 8;
pub const SAFEARRAY16_HEADER_SIZE: usize = 16;
pub const SAFEARRAYBOUND16_SIZE: usize = 8;
pub const DISPPARAMS16_SIZE: usize = 12;
pub const EXCEPINFO16_SIZE: usize = 32;

pub const VT_EMPTY: u16 = 0;
pub const VT_NULL: u16 = 1;
pub const VT_I2: u16 = 2;
pub const VT_I4: u16 = 3;
pub const VT_R4: u16 = 4;
pub const VT_R8: u16 = 5;
pub const VT_CY: u16 = 6;
pub const VT_DATE: u16 = 7;
pub const VT_BSTR: u16 = 8;
pub const VT_DISPATCH: u16 = 9;
pub const VT_ERROR: u16 = 10;
pub const VT_BOOL: u16 = 11;
pub const VT_VARIANT: u16 = 12;
pub const VT_UNKNOWN: u16 = 13;
pub const VT_I1: u16 = 16;
pub const VT_UI1: u16 = 17;
pub const VT_UI2: u16 = 18;
pub const VT_UI4: u16 = 19;
pub const VT_I8: u16 = 20;
pub const VT_UI8: u16 = 21;
pub const VT_INT: u16 = 22;
pub const VT_UINT: u16 = 23;
pub const VT_ARRAY: u16 = 0x2000;
pub const VT_BYREF: u16 = 0x4000;
pub const VT_TYPEMASK: u16 = 0x0fff;

/// SAFEARRAY feature flags carried by the 16-bit descriptor's `fFeatures`.
pub const FADF_AUTO: u16 = 0x0001;
pub const FADF_STATIC: u16 = 0x0002;
pub const FADF_EMBEDDED: u16 = 0x0004;
pub const FADF_FIXEDSIZE: u16 = 0x0010;
pub const FADF_HAVEVARTYPE: u16 = 0x0080;
pub const FADF_BSTR: u16 = 0x0100;
pub const FADF_UNKNOWN: u16 = 0x0200;
pub const FADF_DISPATCH: u16 = 0x0400;
pub const FADF_VARIANT: u16 = 0x0800;

/// Return the fixed guest element width for VARTYPEs supported by the
/// Win16 SAFEARRAY bridge. Pointer-sized Automation elements are four-byte
/// guest FAR values, never host pointers.
pub const fn safe_array_element_width(vartype: u16) -> Option<u16> {
    match vartype {
        VT_I1 | VT_UI1 => Some(1),
        VT_I2 | VT_UI2 | VT_BOOL => Some(2),
        VT_I4 | VT_UI4 | VT_INT | VT_UINT | VT_R4 | VT_ERROR => Some(4),
        VT_R8 | VT_CY | VT_DATE | VT_I8 | VT_UI8 => Some(8),
        VT_BSTR | VT_DISPATCH | VT_UNKNOWN => Some(4),
        VT_VARIANT => Some(16),
        _ => None,
    }
}

/// The 16 byte Win16 VARIANT record used by OLE2DISP.
///
/// The payload remains raw until its VARTYPE-specific marshaler has checked
/// the pointed-to guest data. In particular, `VT_BSTR`, `VT_DISPATCH`,
/// `VT_UNKNOWN`, `VT_ARRAY`, and `VT_BYREF` are guest FAR addresses, never
/// native pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Variant16 {
    pub vt: u16,
    pub reserved: [u16; 3],
    pub payload: [u8; 8],
}

impl Variant16 {
    pub const EMPTY: Self = Self {
        vt: VT_EMPTY,
        reserved: [0; 3],
        payload: [0; 8],
    };

    pub fn decode(bytes: &[u8]) -> Result<Self, AutomationAbiError> {
        if bytes.len() != VARIANT16_SIZE {
            return Err(AutomationAbiError::WrongSize {
                expected: VARIANT16_SIZE,
                actual: bytes.len(),
            });
        }
        let wire_bytes: &[u8; VARIANT16_SIZE] =
            bytes
                .try_into()
                .map_err(|_| AutomationAbiError::WrongSize {
                    expected: VARIANT16_SIZE,
                    actual: bytes.len(),
                })?;
        let wire: automation_wire::Variant16Wire = zerocopy::transmute!(*wire_bytes);
        Ok(Self {
            vt: wire.vartype.get(),
            reserved: wire.reserved.map(|word| word.get()),
            payload: wire.payload,
        })
    }

    pub fn encode(self) -> [u8; VARIANT16_SIZE] {
        zerocopy::transmute!(automation_wire::Variant16Wire {
            vartype: zerocopy::byteorder::little_endian::U16::new(self.vt),
            reserved: self
                .reserved
                .map(zerocopy::byteorder::little_endian::U16::new),
            payload: self.payload,
        })
    }

    pub fn signed_i16(self) -> Result<i16, AutomationAbiError> {
        self.payload
            .get(..2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(i16::from_le_bytes)
            .ok_or(AutomationAbiError::InvalidVariantPayload)
    }

    pub fn unsigned_u8(self) -> u8 {
        self.payload[0]
    }

    pub fn signed_i32(self) -> Result<i32, AutomationAbiError> {
        self.payload
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(i32::from_le_bytes)
            .ok_or(AutomationAbiError::InvalidVariantPayload)
    }

    pub fn f32(self) -> Result<f32, AutomationAbiError> {
        self.payload
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(f32::from_le_bytes)
            .ok_or(AutomationAbiError::InvalidVariantPayload)
    }

    pub fn f64(self) -> f64 {
        f64::from_le_bytes(self.payload)
    }

    pub fn guest_far(self) -> u32 {
        u32::from_le_bytes(self.payload[..4].try_into().unwrap())
    }
}

/// A Win16 BSTR allocation image: byte length prefix, ANSI/DBCS payload, and a
/// single-byte terminator. In 16-bit OLE, `OLECHAR16` is an ANSI character;
/// the guest BSTR value is the FAR address immediately after the four-byte
/// prefix. Native Win32 BSTRs use a separate UTF-16 representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BstrAllocation16 {
    pub bytes: Vec<u8>,
}

impl BstrAllocation16 {
    pub fn new(value: &[u8]) -> Result<Self, AutomationAbiError> {
        let byte_length =
            u32::try_from(value.len()).map_err(|_| AutomationAbiError::LengthOverflow)?;
        let capacity = 4_usize
            .checked_add(value.len())
            .and_then(|length| length.checked_add(1))
            .ok_or(AutomationAbiError::LengthOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| AutomationAbiError::AllocationFailed)?;
        bytes.extend_from_slice(&encode_bstr_byte_length(byte_length));
        bytes.extend_from_slice(value);
        bytes.push(0);
        Ok(Self { bytes })
    }

    pub fn value(&self) -> Result<Vec<u8>, AutomationAbiError> {
        let byte_length = usize::try_from(decode_bstr_byte_length(self.bytes.get(..4).ok_or(
            AutomationAbiError::WrongSize {
                expected: 4,
                actual: self.bytes.len(),
            },
        )?)?)
        .map_err(|_| AutomationAbiError::LengthOverflow)?;
        let end = 4_usize
            .checked_add(byte_length)
            .ok_or(AutomationAbiError::LengthOverflow)?;
        let terminator_end = end
            .checked_add(1)
            .ok_or(AutomationAbiError::LengthOverflow)?;
        if self.bytes.len() != terminator_end || self.bytes.get(end) != Some(&0) {
            return Err(AutomationAbiError::InvalidBstrAllocation);
        }
        let mut value = Vec::new();
        value
            .try_reserve_exact(byte_length)
            .map_err(|_| AutomationAbiError::AllocationFailed)?;
        value.extend_from_slice(&self.bytes[4..end]);
        Ok(value)
    }
}

/// Decode the fixed four-byte, little-endian Win16 BSTR byte-length prefix.
pub fn decode_bstr_byte_length(prefix: &[u8]) -> Result<u32, AutomationAbiError> {
    exact_size(prefix, 4)?;
    let bytes: &[u8; 4] = prefix
        .try_into()
        .map_err(|_| AutomationAbiError::WrongSize {
            expected: 4,
            actual: prefix.len(),
        })?;
    let wire: automation_wire::BstrLengthPrefix16Wire = zerocopy::transmute!(*bytes);
    Ok(wire.byte_length.get())
}

fn encode_bstr_byte_length(byte_length: u32) -> [u8; 4] {
    zerocopy::transmute!(automation_wire::BstrLengthPrefix16Wire {
        byte_length: zerocopy::byteorder::little_endian::U32::new(byte_length),
    })
}

/// Move a guest BSTR FAR value back to the prefix at the same selector.
pub const fn bstr_prefix_far(value: u32) -> Option<u32> {
    let selector = value & 0xffff_0000;
    let offset = value & 0xffff;
    if offset < 4 {
        None
    } else {
        Some(selector | (offset - 4))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeArrayBound16 {
    pub elements: u32,
    pub lower_bound: i32,
}

/// Decode exactly `dimensions` Win16 `SAFEARRAYBOUND` records from owned
/// guest bytes using the private, alignment-one wire layout.
pub fn decode_safe_array_bounds16(
    bytes: &[u8],
    dimensions: u16,
) -> Result<Vec<SafeArrayBound16>, AutomationAbiError> {
    if dimensions == 0 {
        return Err(AutomationAbiError::InvalidSafeArrayDimensions);
    }
    let required = usize::from(dimensions)
        .checked_mul(SAFEARRAYBOUND16_SIZE)
        .ok_or(AutomationAbiError::LengthOverflow)?;
    if bytes.len() != required {
        return Err(AutomationAbiError::WrongSize {
            expected: required,
            actual: bytes.len(),
        });
    }
    let mut bounds = Vec::new();
    bounds
        .try_reserve_exact(usize::from(dimensions))
        .map_err(|_| AutomationAbiError::AllocationFailed)?;
    for chunk in bytes.chunks_exact(SAFEARRAYBOUND16_SIZE) {
        let bound_bytes: &[u8; SAFEARRAYBOUND16_SIZE] =
            chunk
                .try_into()
                .map_err(|_| AutomationAbiError::WrongSize {
                    expected: required,
                    actual: bytes.len(),
                })?;
        let bound: automation_wire::SafeArrayBound16Wire = zerocopy::transmute!(*bound_bytes);
        bounds.push(SafeArrayBound16 {
            elements: bound.elements.get(),
            lower_bound: bound.lower_bound.get(),
        });
    }
    Ok(bounds)
}

/// Win16 SAFEARRAY descriptor metadata with bounds in the guest's stored order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeArray16 {
    pub dimensions: u16,
    pub features: u16,
    pub element_size: u16,
    pub locks: u16,
    pub handle: u32,
    pub data: u32,
    pub bounds: Vec<SafeArrayBound16>,
}

impl SafeArray16 {
    pub fn decode(bytes: &[u8]) -> Result<Self, AutomationAbiError> {
        if bytes.len() < SAFEARRAY16_HEADER_SIZE {
            return Err(AutomationAbiError::WrongSize {
                expected: SAFEARRAY16_HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        let header_bytes: &[u8; SAFEARRAY16_HEADER_SIZE] = bytes[..SAFEARRAY16_HEADER_SIZE]
            .try_into()
            .map_err(|_| AutomationAbiError::WrongSize {
                expected: SAFEARRAY16_HEADER_SIZE,
                actual: bytes.len(),
            })?;
        let header: automation_wire::SafeArray16HeaderWire = zerocopy::transmute!(*header_bytes);
        let dimensions = header.dimensions.get();
        if dimensions == 0 {
            return Err(AutomationAbiError::InvalidSafeArrayDimensions);
        }
        let bounds_bytes = usize::from(dimensions)
            .checked_mul(SAFEARRAYBOUND16_SIZE)
            .ok_or(AutomationAbiError::LengthOverflow)?;
        let required = SAFEARRAY16_HEADER_SIZE
            .checked_add(bounds_bytes)
            .ok_or(AutomationAbiError::LengthOverflow)?;
        if bytes.len() < required {
            return Err(AutomationAbiError::WrongSize {
                expected: required,
                actual: bytes.len(),
            });
        }
        let bounds =
            decode_safe_array_bounds16(&bytes[SAFEARRAY16_HEADER_SIZE..required], dimensions)?;
        Ok(Self {
            dimensions,
            features: header.features.get(),
            element_size: header.element_size.get(),
            locks: header.locks.get(),
            handle: header.handle.get(),
            data: header.data.get(),
            bounds,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, AutomationAbiError> {
        let length = SAFEARRAY16_HEADER_SIZE
            .checked_add(
                self.bounds
                    .len()
                    .checked_mul(SAFEARRAYBOUND16_SIZE)
                    .ok_or(AutomationAbiError::LengthOverflow)?,
            )
            .ok_or(AutomationAbiError::LengthOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| AutomationAbiError::AllocationFailed)?;
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Rewrites this descriptor while reusing already-reserved storage.
    /// Callers can reserve before allocating a guest block, then update the
    /// `data` FAR field without a second fallible host allocation.
    pub fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<(), AutomationAbiError> {
        if usize::from(self.dimensions) != self.bounds.len() || self.dimensions == 0 {
            return Err(AutomationAbiError::InvalidSafeArrayDimensions);
        }
        let length = SAFEARRAY16_HEADER_SIZE
            .checked_add(
                self.bounds
                    .len()
                    .checked_mul(SAFEARRAYBOUND16_SIZE)
                    .ok_or(AutomationAbiError::LengthOverflow)?,
            )
            .ok_or(AutomationAbiError::LengthOverflow)?;
        bytes
            .try_reserve_exact(length.saturating_sub(bytes.len()))
            .map_err(|_| AutomationAbiError::AllocationFailed)?;
        bytes.clear();
        let header: [u8; SAFEARRAY16_HEADER_SIZE] =
            zerocopy::transmute!(automation_wire::SafeArray16HeaderWire {
                dimensions: zerocopy::byteorder::little_endian::U16::new(self.dimensions),
                features: zerocopy::byteorder::little_endian::U16::new(self.features),
                element_size: zerocopy::byteorder::little_endian::U16::new(self.element_size),
                locks: zerocopy::byteorder::little_endian::U16::new(self.locks),
                handle: zerocopy::byteorder::little_endian::U32::new(self.handle),
                data: zerocopy::byteorder::little_endian::U32::new(self.data),
            });
        bytes.extend_from_slice(&header);
        for bound in &self.bounds {
            let wire: [u8; SAFEARRAYBOUND16_SIZE] =
                zerocopy::transmute!(automation_wire::SafeArrayBound16Wire {
                    elements: zerocopy::byteorder::little_endian::U32::new(bound.elements),
                    lower_bound: zerocopy::byteorder::little_endian::I32::new(bound.lower_bound),
                });
            bytes.extend_from_slice(&wire);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispParams16 {
    pub arguments: u32,
    pub named_dispids: u32,
    pub argument_count: u16,
    pub named_count: u16,
}

impl DispParams16 {
    pub fn decode(bytes: &[u8]) -> Result<Self, AutomationAbiError> {
        exact_size(bytes, DISPPARAMS16_SIZE)?;
        let wire_bytes: &[u8; DISPPARAMS16_SIZE] =
            bytes
                .try_into()
                .map_err(|_| AutomationAbiError::WrongSize {
                    expected: DISPPARAMS16_SIZE,
                    actual: bytes.len(),
                })?;
        let wire: automation_wire::DispParams16Wire = zerocopy::transmute!(*wire_bytes);
        Ok(Self {
            arguments: wire.arguments.get(),
            named_dispids: wire.named_dispids.get(),
            argument_count: wire.argument_count.get(),
            named_count: wire.named_count.get(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExcepInfo16 {
    pub code: u16,
    pub reserved: u16,
    pub source: u32,
    pub description: u32,
    pub help_file: u32,
    pub help_context: u32,
    pub reserved_pointer: u32,
    pub deferred_fill: u32,
    pub scode: i32,
}

impl ExcepInfo16 {
    pub fn decode(bytes: &[u8]) -> Result<Self, AutomationAbiError> {
        exact_size(bytes, EXCEPINFO16_SIZE)?;
        let wire_bytes: &[u8; EXCEPINFO16_SIZE] =
            bytes
                .try_into()
                .map_err(|_| AutomationAbiError::WrongSize {
                    expected: EXCEPINFO16_SIZE,
                    actual: bytes.len(),
                })?;
        let wire: automation_wire::ExcepInfo16Wire = zerocopy::transmute!(*wire_bytes);
        Ok(Self {
            code: wire.code.get(),
            reserved: wire.reserved.get(),
            source: wire.source.get(),
            description: wire.description.get(),
            help_file: wire.help_file.get(),
            help_context: wire.help_context.get(),
            reserved_pointer: wire.reserved_pointer.get(),
            deferred_fill: wire.deferred_fill.get(),
            scode: wire.scode.get(),
        })
    }

    pub fn encode(self) -> [u8; EXCEPINFO16_SIZE] {
        zerocopy::transmute!(automation_wire::ExcepInfo16Wire {
            code: zerocopy::byteorder::little_endian::U16::new(self.code),
            reserved: zerocopy::byteorder::little_endian::U16::new(self.reserved),
            source: zerocopy::byteorder::little_endian::U32::new(self.source),
            description: zerocopy::byteorder::little_endian::U32::new(self.description),
            help_file: zerocopy::byteorder::little_endian::U32::new(self.help_file),
            help_context: zerocopy::byteorder::little_endian::U32::new(self.help_context),
            reserved_pointer: zerocopy::byteorder::little_endian::U32::new(self.reserved_pointer),
            deferred_fill: zerocopy::byteorder::little_endian::U32::new(self.deferred_fill),
            scode: zerocopy::byteorder::little_endian::I32::new(self.scode),
        })
    }
}

/// OLE2NLS flag bits in its Win16 export ABI.
pub mod nls16_flags {
    pub const NORM_IGNORECASE: u32 = 0x0000_0001;
    pub const NORM_IGNORENONSPACE: u32 = 0x0000_0002;
    pub const NORM_IGNORESYMBOLS: u32 = 0x0000_0004;
    pub const NORM_IGNOREWIDTH: u32 = 0x0000_0008;
    pub const NORM_IGNOREKANATYPE: u32 = 0x0000_0040;
    pub const NORM_IGNOREJAPANACCENT: u32 = 0x0000_0080;
    pub const NORM_IGNOREKASHIDA: u32 = 0x0004_0000;

    pub const LCMAP_LOWERCASE: u32 = 0x0000_0100;
    pub const LCMAP_UPPERCASE: u32 = 0x0000_0200;
    pub const LCMAP_SORTKEY: u32 = 0x0000_0400;
    pub const LCMAP_HALFWIDTH: u32 = 0x0000_0800;
    pub const LCMAP_FULLWIDTH: u32 = 0x0000_1000;
    pub const LCMAP_HIRAGANA: u32 = 0x0000_2000;
    pub const LCMAP_KATAKANA: u32 = 0x0000_4000;
}

/// Translate only Win16 flags whose bit positions differ from Win32.
/// Unchanged and unrecognized bits reach the operating system for validation.
pub fn map_compare_flags16(flags: u32) -> Result<u32, AutomationAbiError> {
    use nls16_flags::*;
    const WIN_NORM_IGNOREKANATYPE: u32 = 0x0001_0000;
    const WIN_NORM_IGNOREWIDTH: u32 = 0x0002_0000;
    let moved = NORM_IGNOREWIDTH | NORM_IGNOREKANATYPE;
    let mut native = flags & !moved;
    if flags & NORM_IGNOREWIDTH != 0 {
        native |= WIN_NORM_IGNOREWIDTH;
    }
    if flags & NORM_IGNOREKANATYPE != 0 {
        native |= WIN_NORM_IGNOREKANATYPE;
    }
    // No primary source establishes a different target bit for JapanAccent.
    Ok(native)
}

/// Translate only Win16 LCMapStringA flags whose bit positions differ.
/// Unchanged and unrecognized bits reach the operating system for validation.
pub fn map_lcmap_flags16(flags: u32) -> Result<u32, AutomationAbiError> {
    use nls16_flags::*;
    const WIN_LCMAP_HALFWIDTH: u32 = 0x0040_0000;
    const WIN_LCMAP_FULLWIDTH: u32 = 0x0080_0000;
    const WIN_LCMAP_HIRAGANA: u32 = 0x0010_0000;
    const WIN_LCMAP_KATAKANA: u32 = 0x0020_0000;
    const WIN_NORM_IGNOREKANATYPE: u32 = 0x0001_0000;
    const WIN_NORM_IGNOREWIDTH: u32 = 0x0002_0000;
    let moved = LCMAP_HALFWIDTH
        | LCMAP_FULLWIDTH
        | LCMAP_HIRAGANA
        | LCMAP_KATAKANA
        | NORM_IGNOREWIDTH
        | NORM_IGNOREKANATYPE;
    let mut native = flags & !moved;
    if flags & LCMAP_HALFWIDTH != 0 {
        native |= WIN_LCMAP_HALFWIDTH;
    }
    if flags & LCMAP_FULLWIDTH != 0 {
        native |= WIN_LCMAP_FULLWIDTH;
    }
    if flags & LCMAP_HIRAGANA != 0 {
        native |= WIN_LCMAP_HIRAGANA;
    }
    if flags & LCMAP_KATAKANA != 0 {
        native |= WIN_LCMAP_KATAKANA;
    }
    if flags & NORM_IGNOREWIDTH != 0 {
        native |= WIN_NORM_IGNOREWIDTH;
    }
    if flags & NORM_IGNOREKANATYPE != 0 {
        native |= WIN_NORM_IGNOREKANATYPE;
    }
    Ok(native)
}

pub const IID_IDISPATCH: Guid = Guid {
    data1: 0x0002_0400,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
pub const IID_IENUMVARIANT: Guid = Guid {
    data1: 0x0002_0404,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
pub const IID_IERRORINFO: Guid = Guid {
    data1: 0x1cf2_b120,
    data2: 0x547d,
    data3: 0x101b,
    data4: [0x8e, 0x65, 0x08, 0x00, 0x2b, 0x2b, 0xd1, 0x19],
};
pub const IID_ICREATEERRORINFO: Guid = Guid {
    data1: 0x22f0_3340,
    data2: 0x547d,
    data3: 0x101b,
    data4: [0x8e, 0x65, 0x08, 0x00, 0x2b, 0x2b, 0xd1, 0x19],
};
pub const IID_ISUPPORTERRORINFO: Guid = Guid {
    data1: 0xdf0b_3d60,
    data2: 0x548f,
    data3: 0x101b,
    data4: [0x8e, 0x65, 0x08, 0x00, 0x2b, 0x2b, 0xd1, 0x19],
};
pub const IID_ICREATETYPEINFO: Guid = Guid {
    data1: 0x0002_0405,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
pub const IID_ICREATETYPELIB: Guid = Guid {
    data1: 0x0002_0406,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
pub const IID_ITYPECOMP: Guid = Guid {
    data1: 0x0002_0403,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
pub const IID_ITYPEINFO: Guid = Guid {
    data1: 0x0002_0401,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
pub const IID_ITYPELIB: Guid = Guid {
    data1: 0x0002_0402,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationAbiError {
    WrongSize { expected: usize, actual: usize },
    InvalidVariantPayload,
    InvalidBstrAllocation,
    AllocationFailed,
    InvalidSafeArrayDimensions,
    UnsupportedNlsFlags(u32),
    LengthOverflow,
}

impl fmt::Display for AutomationAbiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSize { expected, actual } => write!(
                formatter,
                "record size is {actual} bytes; expected {expected} bytes",
            ),
            Self::InvalidVariantPayload => formatter.write_str("VARIANT payload is invalid"),
            Self::InvalidBstrAllocation => formatter.write_str("BSTR allocation image is invalid"),
            Self::AllocationFailed => formatter.write_str("allocation failed"),
            Self::InvalidSafeArrayDimensions => {
                formatter.write_str("SAFEARRAY dimensions are invalid")
            }
            Self::UnsupportedNlsFlags(flags) => {
                write!(formatter, "Win16 NLS flags 0x{flags:08X} are unsupported")
            }
            Self::LengthOverflow => formatter.write_str("record length overflows its ABI range"),
        }
    }
}

impl std::error::Error for AutomationAbiError {}

fn exact_size(bytes: &[u8], expected: usize) -> Result<(), AutomationAbiError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(AutomationAbiError::WrongSize {
            expected,
            actual: bytes.len(),
        })
    }
}
