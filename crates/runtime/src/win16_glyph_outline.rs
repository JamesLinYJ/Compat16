//! GetGlyphOutline's copied MAT2 input and checked SDK 3.1 output records.

use super::{GDI_ERROR, Win16State, preflight_guest_output, write_guest_output, wrong_result};
use crate::{
    DiagnosticKind, RuntimeError, RuntimeHost, Win16GdiServicesOperation, Win16GdiServicesResult,
};
use guest_core::memory::Memory;
use win16_abi::Win16GdiServicesRequest;
use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

// WINDOWS.H (SDK 3.1): UINT/int/POINT components are WORDs, but each FIXED
// retains a WORD fraction and a signed WORD integer. These records must not
// use the host's wider GLYPHMETRICS or reinterpret a FAR pointer as MAT2.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct Metrics16 {
    black_box_x: U16,
    black_box_y: U16,
    origin_x: I16,
    origin_y: I16,
    cell_inc_x: I16,
    cell_inc_y: I16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct Matrix16 {
    fixed: [U32; 4],
}

impl Win16State {
    pub(super) fn execute_glyph_outline(
        &mut self,
        request: Win16GdiServicesRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Win16GdiServicesRequest::GetGlyphOutline {
            dc,
            character,
            format,
            metrics,
            byte_count,
            buffer,
            matrix,
        } = request
        else {
            return Err(wrong_result("GetGlyphOutline request"));
        };
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(GDI_ERROR);
        };
        if metrics == 0 || matrix == 0 {
            return Ok(GDI_ERROR);
        }
        let matrix_pointer = self
            .selectors
            .pointer_from_far(matrix)
            .map_err(crate::runtime_error)?;
        let mut input = [0_u8; 16];
        self.selectors
            .read(memory, matrix_pointer, &mut input)
            .map_err(crate::runtime_error)?;
        let input = Matrix16::read_from_bytes(&input).map_err(|_| wrong_result("MAT2 layout"))?;
        let metrics_target = preflight_guest_output(&self.selectors, memory, metrics, 12)?;
        let copy_buffer = buffer != 0
            && byte_count != 0
            && !crate::win16_host_gdi_services::glyph_metrics_only(format);
        // Both NULL and zero capacity are size queries. GGO_METRICS ignores
        // the data pointer entirely, even if it is not a valid guest address.
        let buffer_target = if copy_buffer {
            let pointer = self
                .selectors
                .pointer_from_far(buffer)
                .map_err(crate::runtime_error)?;
            self.preflight_text_write(memory, pointer, byte_count as usize)?;
            Some(pointer)
        } else {
            None
        };
        let Win16GdiServicesResult::GlyphOutline {
            result,
            metrics,
            bytes,
        } = host.win16_gdi_services(Win16GdiServicesOperation::GetGlyphOutline {
            dc,
            character,
            format,
            matrix: input.fixed.map(|value| value.get()),
            byte_count,
            copy_buffer,
        })?
        else {
            return Err(wrong_result("GetGlyphOutline"));
        };
        if result == GDI_ERROR {
            return Ok(result);
        }
        let Some(metrics) = metrics else {
            return Err(wrong_result("GetGlyphOutline metrics"));
        };
        if (copy_buffer && (bytes.len() != result as usize || bytes.len() > byte_count as usize))
            || (!copy_buffer && !bytes.is_empty())
        {
            return Err(wrong_result("GetGlyphOutline output length"));
        }
        // SDK fields retain their low WORD bits, as in the historical
        // GLYPHMETRICS thunk; do not saturate large native extents or origins.
        let encoded: [u8; 12] = zerocopy::transmute!(Metrics16 {
            black_box_x: U16::new(metrics.black_box_x as u16),
            black_box_y: U16::new(metrics.black_box_y as u16),
            origin_x: I16::new(metrics.origin_x as i16),
            origin_y: I16::new(metrics.origin_y as i16),
            cell_inc_x: I16::new(metrics.cell_inc_x),
            cell_inc_y: I16::new(metrics.cell_inc_y),
        });
        // Prepare all actual writes before publishing either output. The
        // shared selector walker supports DWORD-sized buffers spanning a
        // checked, contiguous allocation, while leaving excess capacity alone.
        let buffer_write = if let Some(target) = buffer_target.filter(|_| !bytes.is_empty()) {
            Some(self.prepare_text_write(memory, target, bytes.len())?)
        } else {
            None
        };
        let mut previous_metrics = [0_u8; 12];
        self.selectors
            .read(memory, metrics_target, &mut previous_metrics)
            .map_err(crate::runtime_error)?;
        let metrics_write = self.prepare_text_write(memory, metrics_target, encoded.len())?;
        metrics_write.commit(memory, &encoded)?;
        if let Some(write) = buffer_write {
            if let Err(error) = write.commit(memory, &bytes) {
                write_guest_output(&self.selectors, memory, metrics_target, &previous_metrics)
                    .map_err(|rollback| RuntimeError::with_source(DiagnosticKind::InternalInvariant,
                        format!("GetGlyphOutline data write failed ({error}) and metrics rollback failed"), rollback))?;
                return Err(error);
            }
        }
        Ok(result)
    }
}
