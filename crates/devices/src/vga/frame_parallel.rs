//! Complete VGA row groups executed by the engine's shared work owner.

use parallel_work::BoundedExecutor;

use super::{SvgaMode, VgaState, SVGA_PARALLEL_MIN_PIXELS, render_svga_row};

pub(super) fn render_svga_chunks(
    work: &BoundedExecutor,
    state: &VgaState,
    mode: SvgaMode,
    display_start: usize,
    bytes_per_scanline: usize,
    palette: Option<&[u32; 256]>,
    pixels: &mut [u32],
) {
    let width = usize::from(mode.width);
    // The adapter and its borrow guard stay on the caller. Only immutable
    // register/VRAM data and disjoint output row ranges reach the scoped jobs.
    work.for_each_chunk_aligned(pixels, SVGA_PARALLEL_MIN_PIXELS, width,
        |offset, chunk| {
            let first_y = offset / width;
            for (row_index, row) in chunk.chunks_mut(width).enumerate() {
                render_svga_row(state, mode, display_start, bytes_per_scanline,
                    palette, first_y + row_index, row);
            }
        });
}
