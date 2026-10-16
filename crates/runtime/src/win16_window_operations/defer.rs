//! Guest HDWP ownership. Native batches exist only inside the final USER call.

use std::collections::HashMap;

use super::*;
use crate::Win16DeferredWindowPos;
use win16_abi::Win16UserGeometryRequest as Request;

// Windows 3.1 WINDOWS.H defines 0x0001..0x0400 and SWP_DEFERERASE.
// Reject other bits rather than accidentally enabling newer host semantics
// such as SWP_ASYNCWINDOWPOS, which would escape this synchronous owner.
const SWP_VALID_16: u16 = 0x27ff;
const SWP_NOZORDER: u16 = 0x0004;

#[derive(Default)]
pub(in crate::win16_runtime) struct DeferredWindowBatches {
    batches: HashMap<u16, Vec<Win16DeferredWindowPos>>,
    next_handle: u16,
}

impl DeferredWindowBatches {
    fn begin(&mut self, count: i16) -> u16 {
        let Ok(count) = usize::try_from(count) else { return 0; };
        let mut positions = Vec::new();
        if positions.try_reserve_exact(count).is_err()
            || self.batches.try_reserve(1).is_err()
        {
            return 0;
        }
        for _ in 0..u16::MAX {
            self.next_handle = self.next_handle.wrapping_add(1).max(1);
            if let std::collections::hash_map::Entry::Vacant(slot) =
                self.batches.entry(self.next_handle)
            {
                slot.insert(positions);
                return self.next_handle;
            }
        }
        0
    }

    fn append(&mut self, batch: u16, position: Option<Win16DeferredWindowPos>) -> u16 {
        let Some(positions) = self.batches.get_mut(&batch) else { return 0; };
        if let Some(position) = position {
            // Native Begin accepts an int count. Growth and guest argument
            // failure invalidate the entire sequence, including prior entries.
            if positions.len() < i32::MAX as usize && positions.try_reserve(1).is_ok() {
                positions.push(position);
                return batch;
            }
        }
        self.batches.remove(&batch);
        0
    }

    fn take(&mut self, batch: u16) -> Option<Vec<Win16DeferredWindowPos>> {
        self.batches.remove(&batch)
    }

    pub(in crate::win16_runtime) fn clear(&mut self) {
        self.batches.clear();
    }
}

impl Win16State {
    pub(super) fn begin_defer_window_pos_api(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Request,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        if self.window_teardown_state != super::super::WindowTeardownState::Live {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, return_kind);
        }
        let value = match request {
            Request::BeginDeferWindowPos { count } => self.deferred_window_batches.begin(count),
            Request::DeferWindowPos { batch, window, insert_after, x, y, width, height, flags } => {
                let position = if flags & !SWP_VALID_16 != 0 {
                    None
                } else {
                    let window = self.window_handles.get(&window).copied();
                    // An ignored insertion handle must never be resolved.
                    let insert_after = if flags & SWP_NOZORDER != 0 {
                        Some(Win16WindowInsertAfter::Top)
                    } else {
                        self.window_insert_after(insert_after)
                    };
                    window.zip(insert_after).map(|(window, insert_after)| Win16DeferredWindowPos {
                        window, insert_after, x, y, width, height, flags,
                    })
                };
                self.deferred_window_batches.append(batch, position)
            }
            Request::EndDeferWindowPos { batch } => {
                // Consume before any host entry or guest callback. The normal
                // window continuation owns retries of completion, so it never
                // re-enters the native Begin/Defer/End sequence on replay.
                if let Some(positions) = self.deferred_window_batches.take(batch) {
                    return self.submit_call(
                        registers, memory, host,
                        Win16WindowCall::EndDeferWindowPos { positions },
                        Win16WindowCallOutput::Boolean, return_to, return_kind, None,
                    );
                }
                0
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "non-deferred request reached Win16 deferred window positioning")),
        };
        self.complete_return(registers, return_to.0, return_to.1,
            return_to.2, u32::from(value), return_kind)
    }
}
