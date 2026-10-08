//! Validate host USER results before committing exact guest output ranges.

use guest_core::memory::Memory;
use win16_abi::{Access, Rect16, SegmentedPointer};

use super::{ControlWriteBack, Win16State};
use crate::{
    DiagnosticKind as Kind, RuntimeError,
    Win16HostDialogControlResult as ControlResult,
    Win16HostWindow,
};

impl Win16State {
    pub(super) fn finish_dialog_control(
        &mut self,
        output: Option<ControlWriteBack>,
        result: ControlResult,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        use ControlResult as ResultValue;
        let value = match (output, result) {
            (Some(ControlWriteBack::Window { parent, native_parent }), ResultValue::Item(window))
            | (Some(ControlWriteBack::Window { parent, native_parent }), ResultValue::NextItem(window)) => {
                match window {
                    Some(window) if self.window_handles.get(&parent) == Some(&native_parent) => {
                        let child = self.map_window_handle(window, false)?;
                        self.link_window_parent(child, parent)?;
                        u32::from(child)
                    }
                    Some(_) | None => 0,
                }
            }
            (None, ResultValue::Item(window)) | (None, ResultValue::NextItem(window)) => {
                match window {
                    Some(window) => u32::from(self.map_window_handle(window, false)?),
                    None => 0,
                }
            }
            (None, ResultValue::ControlId(id)) => u32::from(id),
            (None, ResultValue::Text { value, bytes }) => {
                super::control_text::finish(self, memory, None, value, bytes)?
            }
            (Some(ControlWriteBack::Text { range, capacity }),
                ResultValue::Text { value, bytes }) => {
                super::control_text::finish(self, memory, Some((range, capacity)), value, bytes)?
            }
            (Some(ControlWriteBack::IntegerTranslated { range }),
                ResultValue::Integer { value, translated, .. }) => {
                if let Some(range) = range {
                    super::super::guest_ranges::commit_guest_output(
                        self,
                        memory,
                        &range,
                        &(if translated { 1_u16 } else { 0 }).to_le_bytes(),
                    )?;
                }
                u32::from(value)
            }
            (None, ResultValue::Integer { value, .. }) => u32::from(value),
            (None, ResultValue::ButtonState(value)) => u32::from(value),
            (None, ResultValue::Succeeded(value)) => u32::from(value),
            (Some(ControlWriteBack::DirectoryPath { range, capacity }),
                ResultValue::DirectoryList { selected, path_spec }) => {
                if let (Some(range), Some(bytes)) = (range, path_spec) {
                    if bytes.len() > usize::from(capacity) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "Win16 DlgDirList output exceeds its checked path buffer"));
                    }
                    super::super::guest_ranges::commit_guest_output(self, memory, &range, &bytes)?;
                }
                selected as u16 as u32
            }
            (Some(ControlWriteBack::DirectoryPath { .. }), ResultValue::Succeeded(value)) => {
                u32::from(value)
            }
            (Some(ControlWriteBack::DirectorySelection { range, capacity }),
                ResultValue::DirectorySelect { selected, text }) => {
                if text.len() > usize::from(capacity) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 DlgDirSelect output exceeds its checked path buffer"));
                }
                // An empty result means USER left this output untouched; a
                // nested guest callback may already have written the range.
                if !text.is_empty() {
                    super::super::guest_ranges::commit_guest_output(self, memory, &range, &text)?;
                }
                u32::from(selected)
            }
            (Some(ControlWriteBack::Rect { range }), ResultValue::Rect(rect)) => {
                if let Some(rect) = rect {
                    let rect16 = Rect16 {
                        left: rect.left as i16,
                        top: rect.top as i16,
                        right: rect.right as i16,
                        bottom: rect.bottom as i16,
                    };
                    super::super::guest_ranges::commit_guest_output(
                        self, memory, &range, &rect16.encode(),
                    )?;
                }
                u32::from(rect.is_some())
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 dialog-control result does not match its output contract")),
        };
        Ok(value)
    }

    pub(super) fn dialog_window(&self, guest: u16) -> Option<Win16HostWindow> {
        self.window_handles.get(&guest).copied()
    }

    pub(super) fn checked_pointer(
        &self,
        far: u32,
        access: Access,
        length: usize,
        memory: &Memory,
    ) -> Result<SegmentedPointer, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, access, length, memory)
            .map_err(crate::runtime_error)?;
        Ok(pointer)
    }

    pub(super) fn selector_tail_capacity(
        &self,
        pointer: SegmentedPointer,
    ) -> Result<u16, RuntimeError> {
        let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let remaining = descriptor.limit.checked_sub(u32::from(pointer.offset()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 USER output pointer lies past its selector limit"))?;
        Ok(remaining.min(u32::from(u16::MAX)) as u16)
    }

    pub(in crate::win16_runtime) fn read_rect16(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
    ) -> Result<Rect16, RuntimeError> {
        let mut bytes = [0; Rect16::SIZE];
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        Ok(Rect16::decode(&bytes))
    }
}
