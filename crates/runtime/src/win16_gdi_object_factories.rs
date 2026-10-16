//! Win16 GDI object factories and guest/native handle ownership.

use guest_core::memory::Memory;
use win16_abi::{
    Point16, Win16ApiRequest, Win16Error,
    gdi_abi::{Bitmap16, LogBrush16, LogFont16, LogPen16},
    gdi_dib::{BITMAPCOREHEADER16_SIZE, core_to_info_header, info_layout, packed_dib_layout},
    window_geometry::Rect16,
};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DrawingPoint, Win16DrawingRect,
    Win16GdiObjectOperation as Operation, Win16HostBitmapInfo, Win16HostDib, Win16HostLogBrush,
    Win16HostLogFont, Win16HostLogPen,
};

const BS_SOLID16: u16 = 0;
const BS_NULL16: u16 = 1;
const BS_HATCHED16: u16 = 2;
const BS_PATTERN16: u16 = 3;
const BS_DIBPATTERN16: u16 = 5;
const CBM_INIT16: u32 = 0x04;

impl Win16State {
    pub(super) fn create_pen(
        &mut self,
        style: i16,
        width: i16,
        color: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.create_object(
            Operation::CreatePen {
                style,
                width,
                color,
            },
            host,
        )
    }

    pub(super) fn create_pen_indirect(
        &mut self,
        logpen: LogPen16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.create_object(
            Operation::CreatePenIndirect {
                logpen: Win16HostLogPen {
                    style: logpen.style,
                    width_x: logpen.width_x,
                    width_y: logpen.width_y,
                    color: logpen.color,
                },
            },
            host,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn create_font(
        &mut self,
        height: i16,
        width: i16,
        escapement: i16,
        orientation: i16,
        weight: i16,
        italic: u16,
        underline: u16,
        strikeout: u16,
        char_set: u16,
        out_precision: u16,
        clip_precision: u16,
        quality: u16,
        pitch_and_family: u16,
        face_name: Option<Vec<u8>>,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.create_object(
            Operation::CreateFont {
                height,
                width,
                escapement,
                orientation,
                weight,
                italic,
                underline,
                strikeout,
                char_set,
                out_precision,
                clip_precision,
                quality,
                pitch_and_family,
                face_name,
            },
            host,
        )
    }

    pub(super) fn create_font_indirect(
        &mut self,
        logfont: LogFont16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.create_object(
            Operation::CreateFontIndirect {
                logfont: Win16HostLogFont {
                    height: logfont.dimensions[0],
                    width: logfont.dimensions[1],
                    escapement: logfont.dimensions[2],
                    orientation: logfont.dimensions[3],
                    weight: logfont.dimensions[4],
                    italic: logfont.styles[0],
                    underline: logfont.styles[1],
                    strikeout: logfont.styles[2],
                    char_set: logfont.styles[3],
                    out_precision: logfont.styles[4],
                    clip_precision: logfont.styles[5],
                    quality: logfont.styles[6],
                    pitch_and_family: logfont.styles[7],
                    face_name: logfont.face_name,
                },
            },
            host,
        )
    }

    pub(super) fn create_bitmap(
        &mut self,
        memory: &Memory,
        width: i16,
        height: i16,
        planes: u16,
        bits_per_pixel: u16,
        bits_far: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(length) = bitmap_bits_length(width, height, planes, bits_per_pixel, None) else {
            // Negative dimensions cannot describe a Win16 bitmap. GDI's
            // documented result is a null handle; no bit buffer is consumed.
            return Ok(0);
        };
        let bits = self.read_optional_bits(memory, bits_far, length)?;
        self.create_object(
            Operation::CreateBitmap {
                width,
                height,
                planes,
                bits_per_pixel,
                bits,
            },
            host,
        )
    }

    pub(super) fn create_bitmap_indirect(
        &mut self,
        memory: &Memory,
        bitmap: Bitmap16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(length) = bitmap_bits_length(
            bitmap.width,
            bitmap.height,
            u16::from(bitmap.planes),
            u16::from(bitmap.bits_per_pixel),
            Some(bitmap.width_bytes),
        ) else {
            return Ok(0);
        };
        let bits = self.read_optional_bits(memory, bitmap.bits, length)?;
        self.create_object(
            Operation::CreateBitmapIndirect {
                bitmap: Win16HostBitmapInfo {
                    kind: bitmap.bitmap_type,
                    width: bitmap.width,
                    height: bitmap.height,
                    width_bytes: bitmap.width_bytes,
                    planes: bitmap.planes,
                    bits_per_pixel: bitmap.bits_per_pixel,
                },
                bits,
            },
            host,
        )
    }

    pub(super) fn create_brush_indirect(
        &mut self,
        memory: &Memory,
        logbrush: LogBrush16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let (pattern_bitmap, dib_pattern) = match logbrush.style {
            BS_HATCHED16 if !(0..=5).contains(&logbrush.hatch) => return Ok(0),
            BS_PATTERN16 => {
                let Some(token) = self.guest_gdi.object(logbrush.hatch as u16) else {
                    return Ok(0);
                };
                (Some(token), None)
            }
            BS_DIBPATTERN16 => {
                let Some(bytes) = self.copy_global_bytes(logbrush.hatch as u16, memory)? else {
                    return Ok(0);
                };
                let usage = logbrush.color as u16;
                let Some(dib) = split_packed_dib(bytes, usage)? else {
                    return Ok(0);
                };
                (None, Some(dib))
            }
            BS_SOLID16 | BS_NULL16 | BS_HATCHED16 => (None, None),
            // Only these Win16 styles have checked scalar/handle semantics.
            // In particular, native BS_DIBPATTERNPT interprets lbHatch as a
            // pointer; a guest WORD must never reach that native parameter.
            _ => return Ok(0),
        };
        self.create_object(
            Operation::CreateBrushIndirect {
                logbrush: Win16HostLogBrush {
                    style: logbrush.style,
                    color: logbrush.color,
                    hatch: u32::from(logbrush.hatch as u16),
                },
                pattern_bitmap,
                dib_pattern,
            },
            host,
        )
    }

    pub(super) fn create_compatible_bitmap(
        &mut self,
        dc: u16,
        width: i16,
        height: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(native_dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        self.create_object(
            Operation::CreateCompatibleBitmap {
                dc: native_dc,
                width,
                height,
            },
            host,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn create_dibitmap(
        &mut self,
        memory: &Memory,
        dc_handle: u16,
        header_far: u32,
        init_flags: u32,
        bits_far: u32,
        info_far: u32,
        color_usage: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(dc_handle) else {
            return Ok(0);
        };
        let header = match self.copy_dib_header(memory, header_far)? {
            Some((mut header, _)) if header.len() == BITMAPCOREHEADER16_SIZE => {
                // Win3.0 CreateDIBitmap explicitly accepts CORE headers.
                // Widen only the independent creation header for native GDI;
                // the initialization info and its table keep their own format.
                // https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/
                let Ok(converted) = core_to_info_header(&header) else {
                    return Ok(0);
                };
                header
                    .try_reserve_exact(converted.len() - header.len())
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "allocate native bitmap creation header",
                            error,
                        )
                    })?;
                header.clear();
                header.extend_from_slice(&converted);
                Some(header)
            }
            Some((header, _)) if header.len() >= 40 => Some(header),
            Some(_) => return Ok(0),
            None if header_far == 0 => None,
            None => return Ok(0),
        };
        if header.is_none() {
            // CreateDIBitmap requires the header. Let native GDI receive its
            // original nullness without touching other pointers it will not
            // be able to interpret.
            return self.create_object(
                Operation::CreateDibitmap {
                    dc,
                    header,
                    init_flags,
                    bits: None,
                    info: None,
                    color_usage: u32::from(color_usage),
                },
                host,
            );
        }

        let (info, bits) = if init_flags & CBM_INIT16 == 0 {
            // The native contract says lpvBits/lpbmi are ignored when
            // initialization is disabled; do not inspect their guest memory.
            (None, None)
        } else {
            let info = match self.copy_dib_info(memory, info_far, color_usage)? {
                Some(info) => Some(info),
                None if info_far == 0 => None,
                None => return Ok(0),
            };
            let layout = match info.as_ref().map(|info| info.layout) {
                Some(layout) => Some(layout),
                None => header
                    .as_deref()
                    .and_then(|bytes| info_layout(bytes, color_usage).ok()),
            };
            let bits = if bits_far == 0 {
                None
            } else {
                let Some(layout) = layout else {
                    return Ok(0);
                };
                self.copy_dib_bits(memory, bits_far, layout.bits_bytes)?
            };
            (info.map(|info| info.bytes), bits)
        };
        self.create_object(
            Operation::CreateDibitmap {
                dc,
                header,
                init_flags,
                bits,
                info,
                color_usage: u32::from(color_usage),
            },
            host,
        )
    }

    /// Creates one of the Win16 region resources in the common GDI object
    /// table. Point and rectangle inputs are already owned guest copies.
    pub(super) fn create_region(
        &mut self,
        request: Win16ApiRequest,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let operation = match request {
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreateEllipticRgn {
                left,
                top,
                right,
                bottom,
            }) => Operation::CreateEllipticRgn {
                rect: drawing_rect(left, top, right, bottom),
            },
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateEllipticRgnIndirect { rect },
            ) => Operation::CreateEllipticRgnIndirect {
                rect: rect.map(rect_to_host),
            },
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreatePolygonRgn {
                points,
                count,
                fill_mode,
            }) => {
                let Ok(expected_points) = usize::try_from(count) else {
                    return Ok(0);
                };
                if points.len() != expected_points {
                    return Ok(0);
                }
                Operation::CreatePolygonRgn {
                    points: points_to_host(points)?,
                    count,
                    fill_mode,
                }
            }
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreateRectRgn {
                left,
                top,
                right,
                bottom,
            }) => Operation::CreateRectRgn {
                rect: drawing_rect(left, top, right, bottom),
            },
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateRectRgnIndirect { rect },
            ) => Operation::CreateRectRgnIndirect {
                rect: rect.map(rect_to_host),
            },
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateRoundRectRgn {
                    left,
                    top,
                    right,
                    bottom,
                    ellipse_width,
                    ellipse_height,
                },
            ) => Operation::CreateRoundRectRgn {
                rect: drawing_rect(left, top, right, bottom),
                ellipse_width,
                ellipse_height,
            },
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreatePolyPolygonRgn {
                    points,
                    polygon_counts,
                    polygon_count,
                    fill_mode,
                    valid,
                },
            ) => {
                if !valid {
                    return Ok(0);
                }
                let Ok(expected_polygons) = usize::try_from(polygon_count) else {
                    return Ok(0);
                };
                if polygon_counts.len() != expected_polygons {
                    return Ok(0);
                }
                let Some(expected_points) =
                    polygon_counts.iter().try_fold(0_usize, |total, count| {
                        usize::try_from(*count)
                            .ok()
                            .and_then(|count| total.checked_add(count))
                    })
                else {
                    return Ok(0);
                };
                if points.len() != expected_points {
                    return Ok(0);
                }
                Operation::CreatePolyPolygonRgn {
                    points: points_to_host(points)?,
                    polygon_counts,
                    polygon_count,
                    fill_mode,
                    valid,
                }
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "non-region request reached Win16 region factory",
                ));
            }
        };
        self.create_object(operation, host)
    }

    fn create_object(
        &mut self,
        operation: Operation,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(object) = host.win16_create_gdi_object(operation)? else {
            return Ok(0);
        };
        if let Some(handle) = self.guest_gdi.allocate_object(object) {
            return Ok(handle);
        }
        if !host.win16_delete_object(object)? {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "new Win16 GDI object could not be released after guest handle exhaustion",
            ));
        }
        Ok(0)
    }

    fn read_optional_bits(
        &self,
        memory: &Memory,
        far: u32,
        length: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        if length == 0 {
            let mut sentinel = Vec::new();
            sentinel.try_reserve_exact(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 bitmap input sentinel",
                    error,
                )
            })?;
            sentinel.push(0);
            return Ok(Some(sentinel));
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.read_text_bytes(memory, pointer, length).map(Some)
    }

    /// Copies an HGLOBAL-owned byte block while holding the same guest global
    /// allocation identity used by GlobalLock. Native consumers receive only
    /// this owned snapshot, never the guest FAR address.
    pub(super) fn copy_global_bytes(
        &mut self,
        guest_handle: u16,
        memory: &Memory,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let Some(&handle) = self.global_handles.get(&guest_handle) else {
            return Ok(None);
        };
        let info = match self.heap.info(handle) {
            Ok(info) if !info.discarded && info.size != 0 => info,
            Ok(_) | Err(Win16Error::InvalidHandle) => return Ok(None),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let pointer = match self.heap.lock(handle, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(
                Win16Error::InvalidHandle
                | Win16Error::SelectorTableFull
                | Win16Error::OutOfMemory
                | Win16Error::LockCountOverflow,
            ) => return Ok(None),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let length = usize::try_from(info.size).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 global byte block exceeds host address space",
                error,
            )
        })?;
        let copied = self.read_text_bytes(memory, pointer, length);
        let unlocked = self.heap.unlock(handle, &mut self.selectors);
        match (copied, unlocked) {
            (Ok(bytes), Ok(_)) => Ok(Some(bytes)),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(crate::runtime_error(error)),
        }
    }
}

fn drawing_rect(left: i16, top: i16, right: i16, bottom: i16) -> Win16DrawingRect {
    Win16DrawingRect {
        left: i32::from(left),
        top: i32::from(top),
        right: i32::from(right),
        bottom: i32::from(bottom),
    }
}

fn rect_to_host(rect: Rect16) -> Win16DrawingRect {
    drawing_rect(rect.left, rect.top, rect.right, rect.bottom)
}

fn points_to_host(points: Vec<Point16>) -> Result<Vec<Win16DrawingPoint>, RuntimeError> {
    let mut result = Vec::new();
    result.try_reserve_exact(points.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate owned native Win16 region points",
            error,
        )
    })?;
    result.extend(points.into_iter().map(|point| Win16DrawingPoint {
        x: i32::from(point.x),
        y: i32::from(point.y),
    }));
    Ok(result)
}

fn split_packed_dib(
    packed: Vec<u8>,
    color_usage: u16,
) -> Result<Option<Win16HostDib>, RuntimeError> {
    let Ok(layout) = packed_dib_layout(&packed, color_usage) else {
        return Ok(None);
    };
    let info = &packed[..layout.info_bytes()];
    let bits = &packed[layout.bits_offset..layout.total_bytes];
    let mut owned_info = Vec::new();
    owned_info.try_reserve_exact(info.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate owned Win16 DIB information bytes",
            error,
        )
    })?;
    owned_info.extend_from_slice(info);
    let mut owned_bits = Vec::new();
    owned_bits.try_reserve_exact(bits.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate owned Win16 DIB image bytes",
            error,
        )
    })?;
    owned_bits.extend_from_slice(bits);
    Ok(Some(Win16HostDib {
        info: owned_info,
        bits: owned_bits,
    }))
}

fn bitmap_bits_length(
    width: i16,
    height: i16,
    planes: u16,
    bits_per_pixel: u16,
    declared_width_bytes: Option<i16>,
) -> Option<usize> {
    if width < 0 || height < 0 {
        return None;
    }
    let row_bits = i64::from(width)
        .checked_mul(i64::from(planes))?
        .checked_mul(i64::from(bits_per_pixel))?;
    let word_aligned_row_bytes = row_bits.checked_add(15)?.checked_div(16)?.checked_mul(2)?;
    let row_bytes = match declared_width_bytes {
        Some(value) if value < 0 => return None,
        Some(value) => word_aligned_row_bytes.max(i64::from(value)),
        None => word_aligned_row_bytes,
    };
    usize::try_from(row_bytes.checked_mul(i64::from(height))?).ok()
}

#[cfg(test)]
#[path = "win16_gdi_brush_tests.rs"]
mod brush_tests;
