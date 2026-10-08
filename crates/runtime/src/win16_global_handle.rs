//! KERNEL GlobalHandle translates an owned Win16 segment identity to its
//! HGLOBAL and current selector; the returned DWORD is handle:selector in
//! the historical LOWORD/HIWORD order.

use super::Win16State;

impl Win16State {
    pub(super) fn global_handle_of(&self, input: u16) -> u32 {
        if input == 0 { return 0; }
        if let Some((selector, _)) = self.module_memory_info(input) {
            let handle = self.loaded_segment_handles.get(&selector).copied().unwrap_or(selector);
            return u32::from(handle) | (u32::from(selector) << 16);
        }
        for (&handle, selector) in &self.global_selectors {
            let raw = selector.raw().0;
            if input == raw || input == handle {
                return u32::from(handle) | (u32::from(raw) << 16);
            }
        }
        if self.task_handles.values().any(|&handle| handle == input)
            || self.psp_selector.raw().0 == input {
            return u32::from(input) | (u32::from(input) << 16);
        }
        if let Some(&handle) = self.loaded_segment_handles.get(&input) {
            return u32::from(handle) | (u32::from(input) << 16);
        }
        0
    }
}
