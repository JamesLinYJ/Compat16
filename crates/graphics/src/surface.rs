use std::fmt;

/// Maximum backing pixels for one software surface (64 MiB at 32 bits/pixel).
pub const MAX_SURFACE_PIXELS: u64 = 16_777_216;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Color {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl Color {
    pub const BLACK: Self = Self::rgb(0, 0, 0);
    pub const WHITE: Self = Self::rgb(255, 255, 255);

    pub const fn rgb(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }

    /// Packed as `0x00RRGGBB`; this is not a Windows `COLORREF` value.
    pub const fn rgb24(self) -> u32 {
        ((self.red as u32) << 16) | ((self.green as u32) << 8) | self.blue as u32
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub const fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self { left, top, right, bottom }
    }

    pub fn is_empty(self) -> bool {
        self.left >= self.right || self.top >= self.bottom
    }

    pub fn intersect(self, other: Self) -> Self {
        Self::new(
            self.left.max(other.left),
            self.top.max(other.top),
            self.right.min(other.right),
            self.bottom.min(other.bottom),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RasterOp {
    SrcCopy,
    Unsupported(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphicsError {
    InvalidDimensions,
    SurfaceTooLarge,
    AllocationFailed,
    InvalidRectangle,
    UnsupportedRasterOperation(u32),
}

impl fmt::Display for GraphicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions => {
                f.write_str("Surface width and height must both be greater than zero.")
            }
            Self::SurfaceTooLarge => write!(
                f,
                "Surface exceeds the maximum supported size of {MAX_SURFACE_PIXELS} pixels."
            ),
            Self::AllocationFailed => f.write_str("Could not allocate storage for the surface."),
            Self::InvalidRectangle => {
                f.write_str("Rectangle coordinates or extents are outside the supported range.")
            }
            Self::UnsupportedRasterOperation(operation) => write!(
                f,
                "Raster operation 0x{operation:08X} is not supported."
            ),
        }
    }
}

impl std::error::Error for GraphicsError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DibError {
    Truncated,
    InvalidHeader,
    InvalidDimensions,
    InvalidPlanes(u16),
    UnsupportedBitDepth(u16),
    UnsupportedCompression(u32),
    PaletteTooLarge,
    InvalidPaletteIndex(u32),
    InconsistentImageSize,
    ArithmeticOverflow,
    ImageTooLarge,
    AllocationFailed,
}

impl fmt::Display for DibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("DIB data ends before the complete image is available."),
            Self::InvalidHeader => f.write_str("DIB header is invalid or too short."),
            Self::InvalidDimensions => {
                f.write_str("DIB width or height is invalid or exceeds the supported range.")
            }
            Self::InvalidPlanes(planes) => {
                write!(f, "DIB declares {planes} color planes; exactly one plane is required.")
            }
            Self::UnsupportedBitDepth(bits) => {
                write!(f, "DIB pixel depth of {bits} bits is not supported.")
            }
            Self::UnsupportedCompression(compression) => write!(
                f,
                "DIB compression method 0x{compression:08X} is not supported."
            ),
            Self::PaletteTooLarge => f.write_str("DIB palette exceeds the supported size."),
            Self::InvalidPaletteIndex(index) => write!(
                f,
                "DIB pixel references palette index {index}, which is outside the palette."
            ),
            Self::InconsistentImageSize => {
                f.write_str("DIB image size does not match its dimensions and pixel format.")
            }
            Self::ArithmeticOverflow => {
                f.write_str("DIB dimensions overflow the supported size calculations.")
            }
            Self::ImageTooLarge => f.write_str("DIB image exceeds the supported size limit."),
            Self::AllocationFailed => f.write_str("Could not allocate storage for the DIB image."),
        }
    }
}

impl std::error::Error for DibError {}

/// An owned, top-left-origin RGB surface. Pixel rows are tightly packed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Surface {
    width: u32,
    height: u32,
    pixels: Vec<Color>,
}

impl Surface {
    pub fn new(width: u32, height: u32, fill: Color) -> Result<Self, GraphicsError> {
        if width == 0 || height == 0 {
            return Err(GraphicsError::InvalidDimensions);
        }
        let count = u64::from(width)
            .checked_mul(u64::from(height))
            .ok_or(GraphicsError::SurfaceTooLarge)?;
        if count > MAX_SURFACE_PIXELS {
            return Err(GraphicsError::SurfaceTooLarge);
        }
        let count = usize::try_from(count).map_err(|_| GraphicsError::SurfaceTooLarge)?;
        let mut pixels = Vec::new();
        pixels.try_reserve_exact(count).map_err(|_| GraphicsError::AllocationFailed)?;
        pixels.resize(count, fill);
        Ok(Self { width, height, pixels })
    }

    pub fn from_pixels(width: u32, height: u32, pixels: Vec<Color>) -> Result<Self, GraphicsError> {
        if width == 0 || height == 0 {
            return Err(GraphicsError::InvalidDimensions);
        }
        let count = u64::from(width)
            .checked_mul(u64::from(height))
            .ok_or(GraphicsError::SurfaceTooLarge)?;
        if count > MAX_SURFACE_PIXELS {
            return Err(GraphicsError::SurfaceTooLarge);
        }
        if usize::try_from(count).ok() != Some(pixels.len()) {
            return Err(GraphicsError::InvalidDimensions);
        }
        Ok(Self { width, height, pixels })
    }

    pub fn from_dib(bytes: &[u8]) -> Result<Self, DibError> {
        parse_dib(bytes)
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width as i32, self.height as i32)
    }

    pub fn pixels(&self) -> &[Color] {
        &self.pixels
    }

    pub fn pixel(&self, x: u32, y: u32) -> Option<Color> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.pixels.get((y * self.width + x) as usize).copied()
    }

    pub fn set_pixel(&mut self, x: u32, y: u32, color: Color) -> bool {
        if x >= self.width || y >= self.height {
            return false;
        }
        if let Some(pixel) = self.pixels.get_mut((y * self.width + x) as usize) {
            *pixel = color;
            true
        } else {
            false
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self, GraphicsError> {
        let mut pixels = Vec::new();
        pixels
            .try_reserve_exact(self.pixels.len())
            .map_err(|_| GraphicsError::AllocationFailed)?;
        pixels.extend_from_slice(&self.pixels);
        Ok(Self { width: self.width, height: self.height, pixels })
    }

    /// Copies pixels using SRCCOPY and clips in both surfaces and to `clip`.
    /// Width and height are unsigned; a zero extent is a successful no-op.
    pub fn bit_blt(
        &mut self,
        x_dest: i32,
        y_dest: i32,
        source: &Self,
        x_source: i32,
        y_source: i32,
        width: u32,
        height: u32,
        clip: Option<Rect>,
        operation: RasterOp,
    ) -> Result<Rect, GraphicsError> {
        if let RasterOp::Unsupported(value) = operation {
            return Err(GraphicsError::UnsupportedRasterOperation(value));
        }
        if width == 0 || height == 0 {
            return Ok(Rect::default());
        }
        let clip = clip.unwrap_or_else(|| self.bounds()).intersect(self.bounds());
        let Some(rect) = clipped_blit(
            self.width, self.height, x_dest, y_dest,
            source.width, source.height, x_source, y_source,
            width, height, clip,
        ) else {
            return Ok(Rect::default());
        };

        let x_offset = i64::from(rect.left) - i64::from(x_dest);
        let y_offset = i64::from(rect.top) - i64::from(y_dest);
        let dest_x = usize::try_from(rect.left).map_err(|_| GraphicsError::InvalidRectangle)?;
        let dest_y = usize::try_from(rect.top).map_err(|_| GraphicsError::InvalidRectangle)?;
        let source_x = usize::try_from(x_offset + i64::from(x_source))
            .map_err(|_| GraphicsError::InvalidRectangle)?;
        let source_y = usize::try_from(y_offset + i64::from(y_source))
            .map_err(|_| GraphicsError::InvalidRectangle)?;
        let row_len = (rect.right - rect.left) as usize;
        for row in 0..(rect.bottom - rect.top) as usize {
            let dest_start = (dest_y + row) * self.width as usize + dest_x;
            let source_start = (source_y + row) * source.width as usize + source_x;
            self.pixels[dest_start..dest_start + row_len]
                .copy_from_slice(&source.pixels[source_start..source_start + row_len]);
        }
        Ok(rect)
    }

    /// Copies a rectangle within this surface with memmove-style overlap rules.
    pub fn bit_blt_within(
        &mut self,
        x_dest: i32,
        y_dest: i32,
        x_source: i32,
        y_source: i32,
        width: u32,
        height: u32,
        clip: Option<Rect>,
        operation: RasterOp,
    ) -> Result<Rect, GraphicsError> {
        if let RasterOp::Unsupported(value) = operation {
            return Err(GraphicsError::UnsupportedRasterOperation(value));
        }
        if width == 0 || height == 0 {
            return Ok(Rect::default());
        }
        let clip = clip.unwrap_or_else(|| self.bounds()).intersect(self.bounds());
        let Some(rect) = clipped_blit(
            self.width, self.height, x_dest, y_dest,
            self.width, self.height, x_source, y_source,
            width, height, clip,
        ) else {
            return Ok(Rect::default());
        };

        let x_offset = i64::from(rect.left) - i64::from(x_dest);
        let y_offset = i64::from(rect.top) - i64::from(y_dest);
        let dest_x = usize::try_from(rect.left).map_err(|_| GraphicsError::InvalidRectangle)?;
        let dest_y = usize::try_from(rect.top).map_err(|_| GraphicsError::InvalidRectangle)?;
        let source_x = usize::try_from(x_offset + i64::from(x_source))
            .map_err(|_| GraphicsError::InvalidRectangle)?;
        let source_y = usize::try_from(y_offset + i64::from(y_source))
            .map_err(|_| GraphicsError::InvalidRectangle)?;
        let row_len = (rect.right - rect.left) as usize;
        let row_count = (rect.bottom - rect.top) as usize;

        if dest_y > source_y {
            for row in (0..row_count).rev() {
                let dest_start = (dest_y + row) * self.width as usize + dest_x;
                let source_start = (source_y + row) * self.width as usize + source_x;
                self.pixels.copy_within(source_start..source_start + row_len, dest_start);
            }
        } else {
            for row in 0..row_count {
                let dest_start = (dest_y + row) * self.width as usize + dest_x;
                let source_start = (source_y + row) * self.width as usize + source_x;
                self.pixels.copy_within(source_start..source_start + row_len, dest_start);
            }
        }
        Ok(rect)
    }
}

fn clipped_blit(
    dest_width: u32,
    dest_height: u32,
    x_dest: i32,
    y_dest: i32,
    source_width: u32,
    source_height: u32,
    x_source: i32,
    y_source: i32,
    width: u32,
    height: u32,
    clip: Rect,
) -> Option<Rect> {
    if clip.is_empty() {
        return None;
    }
    let (dx, dy, sx, sy) = (
        i64::from(x_dest), i64::from(y_dest),
        i64::from(x_source), i64::from(y_source),
    );
    let (w, h) = (i64::from(width), i64::from(height));
    let left_offset = 0i64
        .max(-dx)
        .max(-sx)
        .max(i64::from(clip.left) - dx);
    let top_offset = 0i64
        .max(-dy)
        .max(-sy)
        .max(i64::from(clip.top) - dy);
    let right_offset = w
        .min(i64::from(dest_width) - dx)
        .min(i64::from(source_width) - sx)
        .min(i64::from(clip.right) - dx);
    let bottom_offset = h
        .min(i64::from(dest_height) - dy)
        .min(i64::from(source_height) - sy)
        .min(i64::from(clip.bottom) - dy);
    if left_offset >= right_offset || top_offset >= bottom_offset {
        return None;
    }
    Some(Rect::new(
        i32::try_from(dx + left_offset).ok()?,
        i32::try_from(dy + top_offset).ok()?,
        i32::try_from(dx + right_offset).ok()?,
        i32::try_from(dy + bottom_offset).ok()?,
    ))
}

fn parse_dib(bytes: &[u8]) -> Result<Surface, DibError> {
    const BITMAPINFOHEADER_SIZE: usize = 40;
    const BI_RGB: u32 = 0;
    if bytes.len() < BITMAPINFOHEADER_SIZE {
        return Err(DibError::Truncated);
    }

    let header_size = usize::try_from(read_u32(bytes, 0)?).map_err(|_| DibError::ArithmeticOverflow)?;
    if header_size < BITMAPINFOHEADER_SIZE || header_size > bytes.len() {
        return Err(DibError::InvalidHeader);
    }
    let width_signed = read_i32(bytes, 4)?;
    let height_signed = read_i32(bytes, 8)?;
    if width_signed <= 0 || height_signed == 0 || height_signed == i32::MIN {
        return Err(DibError::InvalidDimensions);
    }
    let width = u32::try_from(width_signed).map_err(|_| DibError::InvalidDimensions)?;
    let height = height_signed.unsigned_abs();
    if read_u16(bytes, 12)? != 1 {
        return Err(DibError::InvalidPlanes(read_u16(bytes, 12)?));
    }
    let bit_count = read_u16(bytes, 14)?;
    if !matches!(bit_count, 1 | 4 | 8 | 24 | 32) {
        return Err(DibError::UnsupportedBitDepth(bit_count));
    }
    let compression = read_u32(bytes, 16)?;
    if compression != BI_RGB {
        return Err(DibError::UnsupportedCompression(compression));
    }
    let image_size = u64::from(read_u32(bytes, 20)?);
    let colors_used = read_u32(bytes, 32)?;

    let max_palette = match bit_count {
        1 => 2,
        4 => 16,
        8 => 256,
        _ => 0,
    };
    let palette_count = if max_palette != 0 {
        if colors_used == 0 { max_palette } else { colors_used }
    } else {
        colors_used
    };
    if max_palette != 0 && palette_count > max_palette {
        return Err(DibError::PaletteTooLarge);
    }
    let palette_bytes = u64::from(palette_count)
        .checked_mul(4)
        .ok_or(DibError::ArithmeticOverflow)?;
    let pixel_offset = u64::try_from(header_size)
        .map_err(|_| DibError::ArithmeticOverflow)?
        .checked_add(palette_bytes)
        .ok_or(DibError::ArithmeticOverflow)?;
    if pixel_offset > bytes.len() as u64 {
        return Err(DibError::Truncated);
    }

    let row_bits = u64::from(width)
        .checked_mul(u64::from(bit_count))
        .ok_or(DibError::ArithmeticOverflow)?;
    let stride = row_bits
        .checked_add(31)
        .ok_or(DibError::ArithmeticOverflow)?
        .checked_div(32)
        .and_then(|units| units.checked_mul(4))
        .ok_or(DibError::ArithmeticOverflow)?;
    let required_pixel_bytes = stride
        .checked_mul(u64::from(height))
        .ok_or(DibError::ArithmeticOverflow)?;
    if image_size != 0 && image_size < required_pixel_bytes {
        return Err(DibError::InconsistentImageSize);
    }
    let available_image_bytes = if image_size == 0 { required_pixel_bytes } else { image_size };
    let pixel_end = pixel_offset
        .checked_add(available_image_bytes)
        .ok_or(DibError::ArithmeticOverflow)?;
    if pixel_end > bytes.len() as u64 {
        return Err(DibError::Truncated);
    }

    let count = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(DibError::ArithmeticOverflow)?;
    if count > MAX_SURFACE_PIXELS {
        return Err(DibError::ImageTooLarge);
    }
    let count = usize::try_from(count).map_err(|_| DibError::ImageTooLarge)?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(count).map_err(|_| DibError::AllocationFailed)?;
    pixels.resize(count, Color::BLACK);

    let palette_start = header_size;
    let mut palette = Vec::new();
    if max_palette != 0 {
        let count = usize::try_from(palette_count).map_err(|_| DibError::PaletteTooLarge)?;
        palette.try_reserve_exact(count).map_err(|_| DibError::AllocationFailed)?;
        for index in 0..count {
            let offset = palette_start
                .checked_add(index.checked_mul(4).ok_or(DibError::ArithmeticOverflow)?)
                .ok_or(DibError::ArithmeticOverflow)?;
            let end = offset.checked_add(4).ok_or(DibError::ArithmeticOverflow)?;
            let entry = bytes.get(offset..end).ok_or(DibError::Truncated)?;
            palette.push(Color::rgb(entry[2], entry[1], entry[0]));
        }
    }

    let top_down = height_signed < 0;
    let pixel_offset = usize::try_from(pixel_offset).map_err(|_| DibError::ArithmeticOverflow)?;
    let stride = usize::try_from(stride).map_err(|_| DibError::ArithmeticOverflow)?;
    for y in 0..height as usize {
        let stored_y = if top_down { y } else { height as usize - 1 - y };
        let row = pixel_offset
            .checked_add(stored_y.checked_mul(stride).ok_or(DibError::ArithmeticOverflow)?)
            .ok_or(DibError::ArithmeticOverflow)?;
        for x in 0..width as usize {
            let color = match bit_count {
                1 => {
                    let offset = row.checked_add(x / 8).ok_or(DibError::ArithmeticOverflow)?;
                    let byte = *bytes.get(offset).ok_or(DibError::Truncated)?;
                    let index = usize::from((byte >> (7 - x % 8)) & 1);
                    *palette.get(index).ok_or(DibError::InvalidPaletteIndex(index as u32))?
                }
                4 => {
                    let offset = row.checked_add(x / 2).ok_or(DibError::ArithmeticOverflow)?;
                    let byte = *bytes.get(offset).ok_or(DibError::Truncated)?;
                    let index = usize::from(if x % 2 == 0 { byte >> 4 } else { byte & 0x0f });
                    *palette.get(index).ok_or(DibError::InvalidPaletteIndex(index as u32))?
                }
                8 => {
                    let offset = row.checked_add(x).ok_or(DibError::ArithmeticOverflow)?;
                    let index = usize::from(*bytes.get(offset).ok_or(DibError::Truncated)?);
                    *palette.get(index).ok_or(DibError::InvalidPaletteIndex(index as u32))?
                }
                24 => {
                    let offset = row.checked_add(x.checked_mul(3).ok_or(DibError::ArithmeticOverflow)?)
                        .ok_or(DibError::ArithmeticOverflow)?;
                    let end = offset.checked_add(3).ok_or(DibError::ArithmeticOverflow)?;
                    let pixel = bytes.get(offset..end).ok_or(DibError::Truncated)?;
                    Color::rgb(pixel[2], pixel[1], pixel[0])
                }
                32 => {
                    let offset = row.checked_add(x.checked_mul(4).ok_or(DibError::ArithmeticOverflow)?)
                        .ok_or(DibError::ArithmeticOverflow)?;
                    let end = offset.checked_add(4).ok_or(DibError::ArithmeticOverflow)?;
                    let pixel = bytes.get(offset..end).ok_or(DibError::Truncated)?;
                    Color::rgb(pixel[2], pixel[1], pixel[0])
                }
                _ => unreachable!("bit depth validated above"),
            };
            pixels[y * width as usize + x] = color;
        }
    }

    Ok(Surface { width, height, pixels })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DibError> {
    let value = bytes.get(offset..offset.checked_add(2).ok_or(DibError::ArithmeticOverflow)?)
        .ok_or(DibError::Truncated)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DibError> {
    let value = bytes.get(offset..offset.checked_add(4).ok_or(DibError::ArithmeticOverflow)?)
        .ok_or(DibError::Truncated)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, DibError> {
    Ok(read_u32(bytes, offset)? as i32)
}

#[cfg(test)]
mod tests;
