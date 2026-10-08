//! Win16 drawing exports, guest-handle translation, and return-width packing.

use guest_core::memory::Memory;
use win16_abi::{SegmentedPointer, Win16ApiRequest};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingPoint, Win16DrawingRect, Win16DrawingResult as HostResult,
};

#[path = "win16_drawing_dib.rs"]
mod dib;
#[path = "win16_drawing_extended.rs"]
mod extended;
#[path = "win16_drawing/geometry.rs"]
mod geometry_requests;
#[path = "win16_drawing/objects.rs"]
mod object_requests;
#[path = "win16_drawing_primitives.rs"]
mod primitives;
#[path = "win16_drawing/text.rs"]
mod text_requests;

/// Entry point shared with the GDI device decoder. DIB byte layout and host
/// conversion stay in this drawing adapter rather than being reimplemented.
pub(super) fn stretch_dibits(
    state: &Win16State,
    memory: &Memory,
    host: &mut impl RuntimeHost,
    guest_dc: u16,
    destination_x: i16,
    destination_y: i16,
    destination_width: i16,
    destination_height: i16,
    source_x: i16,
    source_y: i16,
    source_width: i16,
    source_height: i16,
    info_far: u32,
    bits_far: u32,
    usage: u16,
    rop: u32,
) -> Result<u32, RuntimeError> {
    dib::stretch_dibits(
        state,
        memory,
        host,
        guest_dc,
        destination_x,
        destination_y,
        destination_width,
        destination_height,
        source_x,
        source_y,
        source_width,
        source_height,
        info_far,
        bits_far,
        usage,
        rop,
    )
}

impl Win16State {
    /// Executes a decoded Win16 GDI call. The request owns any string bytes;
    /// this layer resolves guest HDCs to opaque host identities and converts
    /// native results to the export's Win16 WORD/DWORD return representation.
    pub(super) fn drawing(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            request @ Win16ApiRequest::GdiText(_) => {
                self.drawing_text_requests(request, memory, host)
            }
            request @ Win16ApiRequest::GdiDrawing(_) => {
                self.drawing_geometry_requests(request, memory, host)
            }
            request @ Win16ApiRequest::GdiObjects(_) => {
                self.drawing_object_requests(request, memory, host)
            }
            request => self.drawing_extended(request, memory, host),
        }
    }

    fn preflight_drawing_output(
        &self,
        memory: &Memory,
        far_pointer: u32,
        length: usize,
    ) -> Result<SegmentedPointer, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far_pointer)
            .map_err(crate::runtime_error)?;
        self.preflight_text_write(memory, pointer, length)?;
        Ok(pointer)
    }

    fn optional_drawing_output(
        &self,
        memory: &Memory,
        far_pointer: u32,
        length: usize,
    ) -> Result<Option<SegmentedPointer>, RuntimeError> {
        if far_pointer == 0 {
            Ok(None)
        } else {
            self.preflight_drawing_output(memory, far_pointer, length)
                .map(Some)
        }
    }

    fn write_drawing_point(
        &self,
        memory: &mut Memory,
        pointer: SegmentedPointer,
        point: Win16DrawingPoint,
    ) -> Result<(), RuntimeError> {
        let mut bytes = [0_u8; 4];
        bytes[0..2].copy_from_slice(&(point.x as i16).to_le_bytes());
        bytes[2..4].copy_from_slice(&(point.y as i16).to_le_bytes());
        self.write_text_bytes(memory, pointer, &bytes)
    }

    fn write_drawing_size(
        &self,
        memory: &mut Memory,
        pointer: SegmentedPointer,
        width: i32,
        height: i32,
    ) -> Result<(), RuntimeError> {
        let mut bytes = [0_u8; 4];
        bytes[0..2].copy_from_slice(&(width as i16).to_le_bytes());
        bytes[2..4].copy_from_slice(&(height as i16).to_le_bytes());
        self.write_text_bytes(memory, pointer, &bytes)
    }

    fn write_drawing_rect(
        &self,
        memory: &mut Memory,
        pointer: SegmentedPointer,
        rect: Win16DrawingRect,
    ) -> Result<(), RuntimeError> {
        let mut bytes = [0_u8; 8];
        bytes[0..2].copy_from_slice(&(rect.left as i16).to_le_bytes());
        bytes[2..4].copy_from_slice(&(rect.top as i16).to_le_bytes());
        bytes[4..6].copy_from_slice(&(rect.right as i16).to_le_bytes());
        bytes[6..8].copy_from_slice(&(rect.bottom as i16).to_le_bytes());
        self.write_text_bytes(memory, pointer, &bytes)
    }

    fn write_drawing_points(
        &self,
        memory: &mut Memory,
        pointer: SegmentedPointer,
        points: &[Win16DrawingPoint],
    ) -> Result<(), RuntimeError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(points.len().saturating_mul(4))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 drawing point output",
                    error,
                )
            })?;
        for point in points {
            bytes.extend_from_slice(&(point.x as i16).to_le_bytes());
            bytes.extend_from_slice(&(point.y as i16).to_le_bytes());
        }
        self.write_text_bytes(memory, pointer, &bytes)
    }

    fn transform_points(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_dc: u16,
        count: i16,
        points: Vec<win16_abi::Point16>,
        output_far: u32,
        dp_to_lp: bool,
    ) -> Result<u32, RuntimeError> {
        if count <= 0 {
            return Ok(0);
        }
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let length = point_array_size(count)?;
        let output = self.preflight_drawing_output(memory, output_far, length)?;
        let points = checked_points(count, points, "DPtoLP/LPtoDP")?
            .into_iter()
            .map(point_to_host)
            .collect();
        let operation = if dp_to_lp {
            Operation::DpToLp { dc, points }
        } else {
            Operation::LpToDp { dc, points }
        };
        match host.win16_gdi(operation)? {
            HostResult::Points { success, points } => {
                if success {
                    self.write_drawing_points(memory, output, &points)?;
                }
                Ok(u32::from(u16::from(success)))
            }
            _ => Err(wrong_result("DPtoLP/LPtoDP")),
        }
    }

    pub(super) fn drawing_primitives(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        primitives::execute(self, request, memory, host)
    }
}

fn counted_text(
    count: i16,
    text: Vec<u8>,
    operation: &'static str,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    if count < 0 {
        return Ok(None);
    }
    let expected = usize::try_from(count).map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            format!("Win16 {operation} received an invalid nonnegative count"),
        )
    })?;
    if text.len() != expected {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("Win16 {operation} byte count does not match its decoded count"),
        ));
    }
    Ok(Some(text))
}

fn pack_words(low: i32, high: i32) -> u32 {
    u32::from(low as u16) | (u32::from(high as u16) << 16)
}

fn drawing_rect(left: i16, top: i16, right: i16, bottom: i16) -> Win16DrawingRect {
    Win16DrawingRect {
        left: i32::from(left),
        top: i32::from(top),
        right: i32::from(right),
        bottom: i32::from(bottom),
    }
}

fn rect_to_host(rect: win16_abi::window_geometry::Rect16) -> Win16DrawingRect {
    drawing_rect(rect.left, rect.top, rect.right, rect.bottom)
}

fn point_to_host(point: win16_abi::Point16) -> Win16DrawingPoint {
    Win16DrawingPoint {
        x: i32::from(point.x),
        y: i32::from(point.y),
    }
}

fn point_array_size(count: i16) -> Result<usize, RuntimeError> {
    usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::GuestFault,
                "Win16 drawing point count is outside the guest address space",
            )
        })
}

fn checked_points(
    count: i16,
    points: Vec<win16_abi::Point16>,
    operation: &'static str,
) -> Result<Vec<win16_abi::Point16>, RuntimeError> {
    if count < 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("negative Win16 {operation} count reached drawing runtime"),
        ));
    }
    if points.len() != count as usize {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("Win16 {operation} point count does not match its decoded array"),
        ));
    }
    Ok(points)
}

fn wrong_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("Win16 host drawing returned the wrong result for {operation}"),
    )
}
