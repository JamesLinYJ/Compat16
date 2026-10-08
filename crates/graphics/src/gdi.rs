use crate::handle::{HandleError, HandleTable};
use crate::surface::{Color, DibError, GraphicsError, RasterOp, Rect, Surface};
use std::fmt;

/// Guest-visible handle for a device context.
pub use crate::handle::DeviceContextHandle;
/// Guest-visible handle for a bitmap object.
pub use crate::handle::BitmapHandle;

#[derive(Debug)]
struct BitmapObject {
    surface: Surface,
    selected_by: Option<DeviceContextHandle>,
}

#[derive(Debug, Default)]
struct DeviceContext {
    selected_bitmap: Option<BitmapHandle>,
    clip: Option<Rect>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GdiError {
    InvalidDeviceContext(DeviceContextHandle),
    InvalidBitmap(BitmapHandle),
    BitmapAlreadySelected(BitmapHandle),
    BitmapStillSelected(BitmapHandle),
    NoSelectedBitmap(DeviceContextHandle),
    HandleExhausted,
    Graphics(GraphicsError),
    Dib(DibError),
}

static HANDLE_EXHAUSTED_SOURCE: HandleError = HandleError::Exhausted;

impl fmt::Display for GdiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeviceContext(dc) => {
                write!(f, "GDI device context 0x{:04X} is invalid or no longer exists.", dc.raw())
            }
            Self::InvalidBitmap(bitmap) => {
                write!(f, "GDI bitmap 0x{:04X} is invalid or no longer exists.", bitmap.raw())
            }
            Self::BitmapAlreadySelected(bitmap) => write!(
                f,
                "GDI bitmap 0x{:04X} is already selected into another device context.",
                bitmap.raw()
            ),
            Self::BitmapStillSelected(bitmap) => write!(
                f,
                "GDI cannot delete bitmap 0x{:04X} while it is selected into a device context.",
                bitmap.raw()
            ),
            Self::NoSelectedBitmap(dc) => write!(
                f,
                "GDI device context 0x{:04X} has no bitmap selected.",
                dc.raw()
            ),
            Self::HandleExhausted => {
                f.write_str("GDI could not allocate an object because its 16-bit handle table is full.")
            }
            Self::Graphics(error) => write!(f, "GDI drawing operation failed: {error}"),
            Self::Dib(error) => write!(f, "GDI could not create a bitmap from DIB data: {error}"),
        }
    }
}

impl std::error::Error for GdiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HandleExhausted => Some(&HANDLE_EXHAUSTED_SOURCE),
            Self::Graphics(error) => Some(error),
            Self::Dib(error) => Some(error),
            _ => None,
        }
    }
}

impl From<HandleError> for GdiError {
    fn from(_: HandleError) -> Self { Self::HandleExhausted }
}
impl From<GraphicsError> for GdiError {
    fn from(value: GraphicsError) -> Self { Self::Graphics(value) }
}
impl From<DibError> for GdiError {
    fn from(value: DibError) -> Self { Self::Dib(value) }
}

/// In-memory GDI object tables. Bitmaps may be selected into at most one DC.
#[derive(Debug, Default)]
pub struct Gdi {
    device_contexts: HandleTable<DeviceContextHandle, DeviceContext>,
    bitmaps: HandleTable<BitmapHandle, BitmapObject>,
}

impl Gdi {
    pub fn new() -> Self { Self::default() }

    pub fn create_device_context(&mut self) -> Result<DeviceContextHandle, GdiError> {
        self.device_contexts.insert(DeviceContext::default()).map_err(Into::into)
    }

    pub fn create_bitmap(
        &mut self,
        width: u32,
        height: u32,
        fill: Color,
    ) -> Result<BitmapHandle, GdiError> {
        let surface = Surface::new(width, height, fill)?;
        self.create_bitmap_surface(surface)
    }

    pub fn create_dibitmap(&mut self, dib: &[u8]) -> Result<BitmapHandle, GdiError> {
        self.create_bitmap_surface(Surface::from_dib(dib)?)
    }

    pub fn create_bitmap_surface(&mut self, surface: Surface) -> Result<BitmapHandle, GdiError> {
        self.bitmaps
            .insert(BitmapObject { surface, selected_by: None })
            .map_err(Into::into)
    }

    /// Selects or deselects a bitmap and returns the previous selection.
    pub fn select_bitmap(
        &mut self,
        dc: DeviceContextHandle,
        bitmap: Option<BitmapHandle>,
    ) -> Result<Option<BitmapHandle>, GdiError> {
        let old = self
            .device_contexts
            .get(dc)
            .ok_or(GdiError::InvalidDeviceContext(dc))?
            .selected_bitmap;

        if let Some(new_bitmap) = bitmap {
            let object = self.bitmaps.get(new_bitmap).ok_or(GdiError::InvalidBitmap(new_bitmap))?;
            if let Some(owner) = object.selected_by {
                if owner != dc {
                    return Err(GdiError::BitmapAlreadySelected(new_bitmap));
                }
            }
        }
        if old == bitmap {
            return Ok(old);
        }

        if let Some(old_bitmap) = old {
            let object = self.bitmaps.get_mut(old_bitmap).ok_or(GdiError::InvalidBitmap(old_bitmap))?;
            object.selected_by = None;
        }
        if let Some(new_bitmap) = bitmap {
            let object = self.bitmaps.get_mut(new_bitmap).ok_or(GdiError::InvalidBitmap(new_bitmap))?;
            object.selected_by = Some(dc);
        }
        self.device_contexts
            .get_mut(dc)
            .ok_or(GdiError::InvalidDeviceContext(dc))?
            .selected_bitmap = bitmap;
        Ok(old)
    }

    pub fn delete_bitmap(&mut self, bitmap: BitmapHandle) -> Result<(), GdiError> {
        let object = self.bitmaps.get(bitmap).ok_or(GdiError::InvalidBitmap(bitmap))?;
        if object.selected_by.is_some() {
            return Err(GdiError::BitmapStillSelected(bitmap));
        }
        self.bitmaps.remove(bitmap).ok_or(GdiError::InvalidBitmap(bitmap))?;
        Ok(())
    }

    pub fn delete_device_context(&mut self, dc: DeviceContextHandle) -> Result<(), GdiError> {
        let context = self
            .device_contexts
            .remove(dc)
            .ok_or(GdiError::InvalidDeviceContext(dc))?;
        if let Some(bitmap) = context.selected_bitmap {
            if let Some(object) = self.bitmaps.get_mut(bitmap) {
                object.selected_by = None;
            }
        }
        Ok(())
    }

    pub fn selected_bitmap(
        &self,
        dc: DeviceContextHandle,
    ) -> Result<Option<BitmapHandle>, GdiError> {
        Ok(self
            .device_contexts
            .get(dc)
            .ok_or(GdiError::InvalidDeviceContext(dc))?
            .selected_bitmap)
    }

    pub fn set_clip_rect(
        &mut self,
        dc: DeviceContextHandle,
        clip: Option<Rect>,
    ) -> Result<(), GdiError> {
        self.device_contexts
            .get_mut(dc)
            .ok_or(GdiError::InvalidDeviceContext(dc))?
            .clip = clip;
        Ok(())
    }

    pub fn bitmap_surface(&self, bitmap: BitmapHandle) -> Result<&Surface, GdiError> {
        self.bitmaps
            .get(bitmap)
            .map(|object| &object.surface)
            .ok_or(GdiError::InvalidBitmap(bitmap))
    }

    pub fn bitmap_surface_mut(&mut self, bitmap: BitmapHandle) -> Result<&mut Surface, GdiError> {
        self.bitmaps
            .get_mut(bitmap)
            .map(|object| &mut object.surface)
            .ok_or(GdiError::InvalidBitmap(bitmap))
    }

    pub fn device_context_surface(
        &self,
        dc: DeviceContextHandle,
    ) -> Result<&Surface, GdiError> {
        let bitmap = self
            .device_contexts
            .get(dc)
            .ok_or(GdiError::InvalidDeviceContext(dc))?
            .selected_bitmap
            .ok_or(GdiError::NoSelectedBitmap(dc))?;
        self.bitmap_surface(bitmap)
    }

    /// Performs SRCCOPY between selected DC bitmaps and returns the copied area.
    pub fn bit_blt(
        &mut self,
        dest_dc: DeviceContextHandle,
        x_dest: i32,
        y_dest: i32,
        source_dc: DeviceContextHandle,
        x_source: i32,
        y_source: i32,
        width: u32,
        height: u32,
        operation: RasterOp,
    ) -> Result<Rect, GdiError> {
        if let RasterOp::Unsupported(value) = operation {
            return Err(GraphicsError::UnsupportedRasterOperation(value).into());
        }
        let dest_context = self
            .device_contexts
            .get(dest_dc)
            .ok_or(GdiError::InvalidDeviceContext(dest_dc))?;
        let source_context = self
            .device_contexts
            .get(source_dc)
            .ok_or(GdiError::InvalidDeviceContext(source_dc))?;
        let dest_bitmap = dest_context
            .selected_bitmap
            .ok_or(GdiError::NoSelectedBitmap(dest_dc))?;
        let source_bitmap = source_context
            .selected_bitmap
            .ok_or(GdiError::NoSelectedBitmap(source_dc))?;
        // BitBlt clips against the destination DC; the source DC's clip is not
        // used to trim its input pixels.
        let dest_clip = dest_context.clip;

        if dest_bitmap == source_bitmap {
            let surface = &mut self
                .bitmaps
                .get_mut(dest_bitmap)
                .ok_or(GdiError::InvalidBitmap(dest_bitmap))?
                .surface;
            return surface
                .bit_blt_within(
                    x_dest, y_dest, x_source, y_source, width, height, dest_clip, operation,
                )
                .map_err(Into::into);
        }

        // Snapshotting the source avoids unsafe aliasing while keeping all GDI
        // state in one portable owner. Allocation failure remains explicit.
        let source = self
            .bitmaps
            .get(source_bitmap)
            .ok_or(GdiError::InvalidBitmap(source_bitmap))?
            .surface
            .try_clone()?;
        let dest = self
            .bitmaps
            .get_mut(dest_bitmap)
            .ok_or(GdiError::InvalidBitmap(dest_bitmap))?;
        dest.surface
            .bit_blt(
                x_dest, y_dest, &source, x_source, y_source, width, height, dest_clip, operation,
            )
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
