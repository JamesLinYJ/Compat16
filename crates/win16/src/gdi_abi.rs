//! Fixed-width Win16 GDI structures and checked byte codecs.
//!
//! Layout references: Microsoft Windows 3.1 Programmer's Reference, Volume 3,
//! entries `TEXTMETRIC`, `DEVMODE`, `LOGPEN`, `LOGFONT`, `LOGBRUSH`, and
//! `BITMAP`; a local external compatibility header was used as a secondary
//! ABI cross-check. These layouts remain project-owned.

#[path = "gdi_abi_wire.rs"]
mod wire;

/// Win16 `TEXTMETRIC`: eight signed words, nine bytes, then three signed words.
pub const TEXTMETRIC16_SIZE: usize = 31;

/// Win16 `DEVMODE` public structure size in Windows 3.1.
pub const DEVMODE16_SIZE: usize = 68;
/// `dmDeviceName` is the first fixed-width member of Win16 `DEVMODE`.
pub const DEVMODE16_DEVICE_NAME_OFFSET: usize = 0;
pub const DEVMODE16_DEVICE_NAME_SIZE: usize = 32;
pub const DEVMODE16_SPEC_VERSION_OFFSET: usize = 32;
pub const DEVMODE16_DRIVER_VERSION_OFFSET: usize = 34;
pub const DEVMODE16_SIZE_OFFSET: usize = 36;
pub const DEVMODE16_DRIVER_EXTRA_OFFSET: usize = 38;
pub const DEVMODE16_FIELDS_OFFSET: usize = 40;
pub const DEVMODE16_HEADER_SIZE: usize = 40;
pub const DEVMODE16_SETTINGS_OFFSET: usize = 44;

/// Fixed Windows 3.1 GDI object input structure sizes.
pub const LOGPEN16_SIZE: usize = 10;
pub const LOGFONT16_SIZE: usize = 50;
pub const LOGBRUSH16_SIZE: usize = 8;
pub const BITMAP16_SIZE: usize = 14;

/// `ExtTextOut` flag values whose pointer effects are interpreted by its
/// decoder. Other incoming option bits are retained without whitelisting.
/// The rectangle values follow the Windows 3.1 GDI `ExtTextOut` contract;
/// Microsoft documents paired `lpDx` values for `ETO_PDY` in the GDI API.
pub const ETO_OPAQUE: u16 = 0x0002;
pub const ETO_CLIPPED: u16 = 0x0004;
pub const ETO_PDY: u16 = 0x2000;
pub const ETO_RECT_FLAGS: u16 = ETO_OPAQUE | ETO_CLIPPED;

// Source for the paired displacement array semantics of ETO_PDY:
// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-exttextouta

/// Pointer-free Win16 `LOGPEN` copied from a guest structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogPen16 {
    pub style: u16,
    pub width_x: i16,
    pub width_y: i16,
    pub color: u32,
}

impl LogPen16 {
    pub const SIZE: usize = LOGPEN16_SIZE;

    pub fn encode(self) -> [u8; Self::SIZE] {
        zerocopy::transmute!(wire::LogPen16Wire {
            style: wire::U16::new(self.style), width_x: wire::I16::new(self.width_x),
            width_y: wire::I16::new(self.width_y), color: wire::U32::new(self.color),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GdiAbiError> {
        let bytes = gdi_wire_bytes::<{ Self::SIZE }>(bytes)?;
        let wire: wire::LogPen16Wire = zerocopy::transmute!(bytes);
        Ok(Self {
            style: wire.style.get(),
            width_x: wire.width_x.get(),
            width_y: wire.width_y.get(),
            color: wire.color.get(),
        })
    }
}

/// Pointer-free Win16 `LOGFONT`; the face name is a fixed 32-byte field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogFont16 {
    pub dimensions: [i16; 5],
    pub styles: [u8; 8],
    pub face_name: [u8; 32],
}

impl LogFont16 {
    pub const SIZE: usize = LOGFONT16_SIZE;

    pub fn encode(self) -> [u8; Self::SIZE] {
        zerocopy::transmute!(wire::LogFont16Wire {
            dimensions: self.dimensions.map(wire::I16::new), styles: self.styles,
            face_name: self.face_name,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GdiAbiError> {
        let bytes = gdi_wire_bytes::<{ Self::SIZE }>(bytes)?;
        let wire: wire::LogFont16Wire = zerocopy::transmute!(bytes);
        Ok(Self {
            dimensions: wire.dimensions.map(|value| value.get()),
            styles: wire.styles,
            face_name: wire.face_name,
        })
    }
}

/// Pointer-free Win16 `LOGBRUSH` copied from a guest structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogBrush16 {
    pub style: u16,
    pub color: u32,
    pub hatch: i16,
}

impl LogBrush16 {
    pub const SIZE: usize = LOGBRUSH16_SIZE;

    pub fn encode(self) -> [u8; Self::SIZE] {
        zerocopy::transmute!(wire::LogBrush16Wire {
            style: wire::U16::new(self.style), color: wire::U32::new(self.color),
            hatch: wire::I16::new(self.hatch),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GdiAbiError> {
        let bytes = gdi_wire_bytes::<{ Self::SIZE }>(bytes)?;
        let wire: wire::LogBrush16Wire = zerocopy::transmute!(bytes);
        Ok(Self {
            style: wire.style.get(),
            color: wire.color.get(),
            hatch: wire.hatch.get(),
        })
    }
}

/// Win16 `BITMAP` fields. `bits` remains the guest FAR value from `bmBits`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bitmap16 {
    pub bitmap_type: i16,
    pub width: i16,
    pub height: i16,
    pub width_bytes: i16,
    pub planes: u8,
    pub bits_per_pixel: u8,
    pub bits: u32,
}

impl Bitmap16 {
    pub const SIZE: usize = BITMAP16_SIZE;

    pub fn encode(self) -> [u8; Self::SIZE] {
        zerocopy::transmute!(wire::Bitmap16Wire {
            bitmap_type: wire::I16::new(self.bitmap_type), width: wire::I16::new(self.width),
            height: wire::I16::new(self.height), width_bytes: wire::I16::new(self.width_bytes),
            planes: self.planes, bits_per_pixel: self.bits_per_pixel, bits: wire::U32::new(self.bits),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GdiAbiError> {
        let bytes = gdi_wire_bytes::<{ Self::SIZE }>(bytes)?;
        let wire: wire::Bitmap16Wire = zerocopy::transmute!(bytes);
        Ok(Self {
            bitmap_type: wire.bitmap_type.get(),
            width: wire.width.get(),
            height: wire.height.get(),
            width_bytes: wire.width_bytes.get(),
            planes: wire.planes,
            bits_per_pixel: wire.bits_per_pixel,
            bits: wire.bits.get(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GdiAbiError {
    IncompleteStructure,
}

// Win16 PRINT.H's DM_* field mask values, also used by the corresponding
// Windows 3.1 Programmer's Reference DEVMODE description.
pub const DEVMODE16_DM_ORIENTATION: u32 = 0x0000_0001;
pub const DEVMODE16_DM_PAPERSIZE: u32 = 0x0000_0002;
pub const DEVMODE16_DM_PAPERLENGTH: u32 = 0x0000_0004;
pub const DEVMODE16_DM_PAPERWIDTH: u32 = 0x0000_0008;
pub const DEVMODE16_DM_SCALE: u32 = 0x0000_0010;
pub const DEVMODE16_DM_COPIES: u32 = 0x0000_0100;
pub const DEVMODE16_DM_DEFAULTSOURCE: u32 = 0x0000_0200;
pub const DEVMODE16_DM_PRINTQUALITY: u32 = 0x0000_0400;
pub const DEVMODE16_DM_COLOR: u32 = 0x0000_0800;
pub const DEVMODE16_DM_DUPLEX: u32 = 0x0000_1000;
pub const DEVMODE16_DM_YRESOLUTION: u32 = 0x0000_2000;
pub const DEVMODE16_DM_TTOPTION: u32 = 0x0000_4000;
/// Win3.1 settings whose public fields have a verified Win16-to-native map.
pub const DEVMODE16_SUPPORTED_FIELDS: u32 = DEVMODE16_DM_ORIENTATION
    | DEVMODE16_DM_PAPERSIZE
    | DEVMODE16_DM_PAPERLENGTH
    | DEVMODE16_DM_PAPERWIDTH
    | DEVMODE16_DM_SCALE
    | DEVMODE16_DM_COPIES
    | DEVMODE16_DM_DEFAULTSOURCE
    | DEVMODE16_DM_PRINTQUALITY
    | DEVMODE16_DM_COLOR
    | DEVMODE16_DM_DUPLEX
    | DEVMODE16_DM_YRESOLUTION
    | DEVMODE16_DM_TTOPTION;

/// The scalar Win16 text metrics without any host ABI padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMetric16 {
    pub dimensions: [i16; 8],
    pub styles: [u8; 9],
    pub extra: [i16; 3],
}

impl TextMetric16 {
    /// Converts native GDI's 32-bit metric values to Win16 signed words.
    /// This uses the same saturating narrowing policy as font enumeration.
    pub fn from_host(dimensions: [i32; 8], styles: [u8; 9], extra: [i32; 3]) -> Self {
        Self {
            dimensions: dimensions.map(narrow_i16),
            styles,
            extra: extra.map(narrow_i16),
        }
    }

    /// Encodes the Windows 3.1 `TEXTMETRIC` byte layout in little-endian order.
    pub fn encode(self) -> [u8; TEXTMETRIC16_SIZE] {
        let wire = wire::TextMetric16Wire {
            dimensions: self.dimensions.map(wire::I16::new),
            styles: self.styles,
            extra: self.extra.map(wire::I16::new),
        };
        zerocopy::transmute!(wire)
    }
}

/// Owned, pointer-free Win16 `DEVMODE` values after guest-range validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevMode16 {
    pub device_name: [u8; DEVMODE16_DEVICE_NAME_SIZE],
    pub spec_version: u16,
    pub driver_version: u16,
    pub fields: u32,
    /// Orientation, paper size/length/width, scale, copies, default source,
    /// print quality, color, duplex, Y resolution, and TrueType option.
    pub settings: [i16; 12],
    /// Public bytes after the verified Windows 3.1 structure. Their layout is
    /// preserved, but this layer does not infer semantics for later fields.
    pub public_extension: Vec<u8>,
    /// Driver-private bytes immediately following `dmSize` public bytes.
    pub driver_extra: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevMode16Error {
    InvalidPublicSize,
    IncompleteBytes,
    AllocationFailed,
}

/// Decodes an owned byte range containing exactly `dmSize + dmDriverExtra`
/// bytes. The caller must first validate the guest selector over that range.
/// Public fields absent from a partial structure are zero-filled; selected
/// fields must be wholly present. Bytes beyond the verified Windows 3.1
/// public layout are preserved without assigning them guessed meanings.
/// This variable-length contract stays on checked field reads; the fixed
/// zerocopy wire records do not validate `dmSize`, selected-field coverage,
/// driver-private tail length, or extension preservation.
pub fn decode_devmode16(bytes: &[u8]) -> Result<DevMode16, DevMode16Error> {
    if bytes.len() < DEVMODE16_HEADER_SIZE {
        return Err(DevMode16Error::IncompleteBytes);
    }

    let public_size = usize::from(read_u16(bytes, DEVMODE16_SIZE_OFFSET)?);
    let extra_size = usize::from(read_u16(bytes, DEVMODE16_DRIVER_EXTRA_OFFSET)?);
    if public_size < DEVMODE16_HEADER_SIZE
        || (public_size > DEVMODE16_HEADER_SIZE && public_size < DEVMODE16_SETTINGS_OFFSET)
    {
        return Err(DevMode16Error::InvalidPublicSize);
    }
    let total_size = public_size.checked_add(extra_size)
        .ok_or(DevMode16Error::InvalidPublicSize)?;
    if bytes.len() != total_size {
        return Err(DevMode16Error::IncompleteBytes);
    }

    let mut device_name = [0_u8; DEVMODE16_DEVICE_NAME_SIZE];
    device_name.copy_from_slice(
        &bytes[DEVMODE16_DEVICE_NAME_OFFSET
            ..DEVMODE16_DEVICE_NAME_OFFSET + DEVMODE16_DEVICE_NAME_SIZE],
    );
    let spec_version = read_u16(bytes, DEVMODE16_SPEC_VERSION_OFFSET)?;
    let driver_version = read_u16(bytes, DEVMODE16_DRIVER_VERSION_OFFSET)?;
    let fields = if public_size >= DEVMODE16_SETTINGS_OFFSET {
        read_u32(bytes, DEVMODE16_FIELDS_OFFSET)?
    } else {
        0
    };

    // `dmFields` identifies values the caller expects the driver to consume.
    // Reject a truncated selected member as an ordinary invalid DEVMODE,
    // rather than silently translating its zero-filled placeholder.
    for (index, mask) in [
        DEVMODE16_DM_ORIENTATION,
        DEVMODE16_DM_PAPERSIZE,
        DEVMODE16_DM_PAPERLENGTH,
        DEVMODE16_DM_PAPERWIDTH,
        DEVMODE16_DM_SCALE,
        DEVMODE16_DM_COPIES,
        DEVMODE16_DM_DEFAULTSOURCE,
        DEVMODE16_DM_PRINTQUALITY,
        DEVMODE16_DM_COLOR,
        DEVMODE16_DM_DUPLEX,
        DEVMODE16_DM_YRESOLUTION,
        DEVMODE16_DM_TTOPTION,
    ].into_iter().enumerate() {
        let end = DEVMODE16_SETTINGS_OFFSET + index * 2 + 2;
        if fields & mask != 0 && end > public_size {
            return Err(DevMode16Error::InvalidPublicSize);
        }
    }

    let mut settings = [0_i16; 12];
    for (index, setting) in settings.iter_mut().enumerate() {
        let offset = DEVMODE16_SETTINGS_OFFSET + index * 2;
        if offset + 2 <= public_size {
            *setting = i16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        }
    }

    let mut public_extension = Vec::new();
    if public_size > DEVMODE16_SIZE {
        let extension = &bytes[DEVMODE16_SIZE..public_size];
        public_extension.try_reserve_exact(extension.len())
            .map_err(|_| DevMode16Error::AllocationFailed)?;
        public_extension.extend_from_slice(extension);
    }

    let mut driver_extra = Vec::new();
    driver_extra.try_reserve_exact(extra_size)
        .map_err(|_| DevMode16Error::AllocationFailed)?;
    driver_extra.extend_from_slice(&bytes[public_size..total_size]);

    Ok(DevMode16 {
        device_name, spec_version, driver_version, fields, settings,
        public_extension, driver_extra,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DevMode16Error> {
    let pair = bytes.get(offset..offset + 2).ok_or(DevMode16Error::IncompleteBytes)?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DevMode16Error> {
    let word = bytes.get(offset..offset + 4).ok_or(DevMode16Error::IncompleteBytes)?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn require_size(bytes: &[u8], expected: usize) -> Result<(), GdiAbiError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(GdiAbiError::IncompleteStructure)
    }
}

fn gdi_wire_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], GdiAbiError> {
    require_size(bytes, N)?;
    let mut wire = [0_u8; N];
    wire.copy_from_slice(bytes);
    Ok(wire)
}

fn narrow_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}
