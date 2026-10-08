//! Copied AND/XOR bitmap inputs for native image construction.

/// Requested Win16 icon dimensions when extracting one group-icon entry.
///
/// The host maps these semantic sizes to the current Windows metrics so a
/// resource group can select and create the corresponding large or small
/// image without exposing native display dimensions to the guest runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostIconSize {
    Large,
    Small,
}

#[derive(Clone, Debug)]
pub struct Win16HostImageMasks {
    pub width: i16,
    pub height: i16,
    pub planes: u8,
    pub bits_per_pixel: u8,
    pub and_mask: Vec<u8>,
    pub xor_mask: Vec<u8>,
}

impl Win16HostImageMasks {
    /// SDK 3.1 CreateIcon/CreateCursor use CreateBitmap-style WORD-aligned
    /// scanlines. Image codecs for file formats do not express these masks.
    /// This extent calculation is shared by guest preflight and native FFI.
    /// Host sizing contract: https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createbitmap
    pub fn lengths(width: i16, height: i16, planes: u8, bits_per_pixel: u8)
        -> Option<(usize, usize)>
    {
        if width <= 0 || height <= 0 || planes == 0 || bits_per_pixel == 0 { return None; }
        let row = |bits: usize| bits.checked_add(15)?.checked_div(16)?.checked_mul(2);
        let width = width as usize;
        let height = height as usize;
        let and = row(width)?.checked_mul(height)?;
        let xor = row(width.checked_mul(usize::from(planes))?
            .checked_mul(usize::from(bits_per_pixel))?)?.checked_mul(height)?;
        Some((and, xor))
    }

    pub fn valid(&self) -> bool {
        Self::lengths(self.width, self.height, self.planes, self.bits_per_pixel)
            == Some((self.and_mask.len(), self.xor_mask.len()))
    }
}
