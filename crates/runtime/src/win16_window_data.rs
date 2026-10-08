//! Win16 USER window-word and window-long state.
//!
//! The field offsets follow the Microsoft Windows 3.1 SDK `WINDOWS.H` and
//! Guide to Programming. Guest FAR procedures and `cbWndExtra` storage stay
//! in this runtime; native `Get/SetWindowLongPtr` is used only by the typed
//! host adapter for ordinary native scalar fields.

use guest_core::{Registers, memory::Memory};
use win16_abi::{
    Win16ReturnKind, Win16WindowDataRequest,
    exports::window_data::{
        DWL_DLGPROC, DWL_MSGRESULT, DWL_USER, GWL_EXSTYLE, GWL_STYLE,
        GWL_WNDPROC, GWW_HINSTANCE, GWW_HWNDPARENT, GWW_ID,
    },
};

use super::{Win16State, windows::WindowReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostClass, Win16WindowCall, Win16WindowDataCall,
    Win16WindowDataField, Win16WindowOperation,
    Win16WindowTarget, Win16HostWindow,
};

// The Win16 SDK DLGWINDOWEXTRA is 30 bytes. It documents three DWORD slots:
// DWL_MSGRESULT and DWL_DLGPROC belong to USER; DWL_USER is one app DWORD.
// The remaining 18 bytes are reserved for dialog-manager use.
const DLGWINDOWEXTRA_BYTES: usize = 30;
const DIALOG_RESULT_RANGE: std::ops::Range<usize> =
    DWL_MSGRESULT as usize..DWL_MSGRESULT as usize + 4;
const DIALOG_PROC_RANGE: std::ops::Range<usize> =
    DWL_DLGPROC as usize..DWL_DLGPROC as usize + 4;
const DIALOG_USER_RANGE: std::ops::Range<usize> =
    DWL_USER as usize..DWL_USER as usize + 4;

#[derive(Debug)]
pub(super) struct Win16WindowDataState {
    class: Option<Win16HostClass>,
    /// `None` means that no guest `cbWndExtra` contract is known. An empty
    /// vector means a known class explicitly requested zero extra bytes.
    extra_bytes: Option<Vec<u8>>,
    instance: u16,
    is_dialog: bool,
    /// Previously installed guest FAR procedures stay rooted while the HWND
    /// lives so SetWindowLong's returned subclass-chain values remain callable.
    procedure_roots: Vec<u32>,
    reported_missing_contract: bool,
}

impl Win16WindowDataState {
    fn new(
        class: Option<Win16HostClass>,
        instance: u16,
        is_dialog: bool,
        extra_len: Option<usize>,
    ) -> Result<Self, RuntimeError> {
        let length = if is_dialog {
            Some(extra_len.unwrap_or(0).max(DLGWINDOWEXTRA_BYTES))
        } else {
            extra_len
        };
        let extra_bytes = length.map(zeroed_bytes).transpose()?;
        Ok(Self {
            class,
            extra_bytes,
            instance,
            is_dialog,
            procedure_roots: Vec::new(),
            reported_missing_contract: false,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum DataWidth {
    Word,
    Long,
}

impl DataWidth {
    fn return_kind(self) -> Win16ReturnKind {
        match self {
            Self::Word => Win16ReturnKind::Word,
            Self::Long => Win16ReturnKind::Dword,
        }
    }

    fn bytes(self) -> usize {
        match self {
            Self::Word => 2,
            Self::Long => 4,
        }
    }

    fn mask(self) -> u32 {
        match self {
            Self::Word => u32::from(u16::MAX),
            Self::Long => u32::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Win16WindowDataContinuation {
    pub(super) window: u16,
    /// Native identity captured before the host call. Synchronous callbacks
    /// can destroy this window and reuse its guest HWND before completion.
    pub(super) native_window: Win16HostWindow,
    pub(super) return_kind: Win16ReturnKind,
    pub(super) return_mask: u32,
    pub(super) parent_result: bool,
}

impl Win16State {
    pub(super) fn window_is_dialog(&self, window: u16) -> bool {
        self.window_data.get(&window).is_some_and(|state| state.is_dialog)
    }

    /// Install the guest window's extra-data contract before its first guest
    /// callback. `extra_len` must come from the Win16 class record, never the
    /// host's native class allocation.
    pub(super) fn initialize_window_data(
        &mut self,
        window: u16,
        class: Option<Win16HostClass>,
        instance: u16,
        dialog: bool,
        extra_len: Option<usize>,
    ) -> Result<(), RuntimeError> {
        if window == 0 || !self.window_handles.contains_key(&window) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 window data was initialized before its guest HWND mapping"));
        }
        if let Some(existing) = self.window_data.get_mut(&window) {
            if existing.class.is_none() {
                existing.class = class;
            } else if class.is_some() && existing.class != class {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 window data was assigned to a different guest class"));
            }
            if dialog {
                existing.is_dialog = true;
                let required = extra_len.unwrap_or(0).max(DLGWINDOWEXTRA_BYTES);
                if existing.extra_bytes.is_none() {
                    existing.extra_bytes = Some(zeroed_bytes(required)?);
                } else if let Some(bytes) = existing.extra_bytes.as_mut() {
                    if bytes.len() < required {
                        let previous = bytes.len();
                        bytes.try_reserve_exact(required - previous)
                            .map_err(|_| RuntimeError::new(Kind::ResourceExhausted,
                                "Win16 dialog extra-data storage cannot grow"))?;
                        bytes.resize(required, 0);
                    }
                }
            } else if existing.extra_bytes.is_none() {
                existing.extra_bytes = extra_len.map(zeroed_bytes).transpose()?;
            }
            return Ok(());
        }

        self.window_data.insert(window, Win16WindowDataState::new(
            class, instance, dialog, extra_len,
        )?);
        Ok(())
    }

    /// Dialog APIs own a fixed 30-byte Win16 DLGWINDOWEXTRA area, independent
    /// of the native Win32 dialog class's private data layout.
    pub(super) fn initialize_dialog_window_data(
        &mut self,
        window: u16,
        instance: u16,
    ) -> Result<(), RuntimeError> {
        self.initialize_window_data(window, None, instance, true,
            Some(DLGWINDOWEXTRA_BYTES))
    }

    /// Clear the dialog manager's per-message result immediately before
    /// entering a guest DLGPROC, matching the Win16/Win32 dialog callback rule.
    pub(super) fn reset_dialog_message_result(&mut self, window: u16) {
        if let Some(state) = self.window_data.get_mut(&window) {
            if state.is_dialog {
                if let Some(bytes) = state.extra_bytes.as_mut() {
                    if let Some(result) = bytes.get_mut(DIALOG_RESULT_RANGE) {
                        result.fill(0);
                    }
                }
            }
        }
    }

    /// Read the guest DWL_MSGRESULT bit pattern after a DLGPROC returns.
    pub(super) fn dialog_message_result(&self, window: u16) -> Option<u32> {
        let state = self.window_data.get(&window)?;
        if !state.is_dialog { return None; }
        let bytes = state.extra_bytes.as_ref()?.get(DIALOG_RESULT_RANGE)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Keep prior window/dialog procedures alive while guest code may still
    /// pass their FAR value to CallWindowProc.
    pub(super) fn window_procedure_roots(&self) -> impl Iterator<Item = u32> + '_ {
        self.window_data.values()
            .flat_map(|state| state.procedure_roots.iter().copied())
    }

    /// Handle USER.133–136. Positive indexes are byte offsets into checked,
    /// guest-owned `cbWndExtra`/DLGWINDOWEXTRA data. Negative system fields
    /// use typed runtime or host operations; guest FAR values never enter the
    /// native LongPtr calls.
    pub(super) fn begin_window_data(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16WindowDataRequest,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (window, index, width, replacement) = match request {
            Win16WindowDataRequest::GetWindowWord { window, index } =>
                (window, index, DataWidth::Word, None),
            Win16WindowDataRequest::SetWindowWord { window, index, value } =>
                (window, index, DataWidth::Word, Some(u32::from(value))),
            Win16WindowDataRequest::GetWindowLong { window, index } =>
                (window, index, DataWidth::Long, None),
            Win16WindowDataRequest::SetWindowLong { window, index, value } =>
                (window, index, DataWidth::Long, Some(value as u32)),
        };
        let return_kind = width.return_kind();
        let zero = |this: &mut Self, registers: &mut Registers| {
            this.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, return_kind)
        };

        if window == 0 || !self.window_handles.contains_key(&window) {
            return zero(self, registers);
        }

        if index >= 0 {
            let Some(value) = self.access_guest_extra(
                window, index as usize, width, replacement, host,
            )? else {
                return zero(self, registers);
            };
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, value & width.mask(), return_kind);
        }

        // The Win16 structure exposes HINSTANCE as a WORD. Long access at the
        // same byte offset observes or changes only that declared 16-bit field.
        if index == GWW_HINSTANCE {
            let Some(state) = self.window_data.get(&window) else {
                self.report_missing_contract(host, window, index, replacement, width)?;
                return zero(self, registers);
            };
            let old = state.instance;
            if let Some(value) = replacement {
                let new_instance = value as u16;
                if let Some(state) = self.window_data.get_mut(&window) {
                    state.instance = new_instance;
                }
                if let Some(procedure) = self.window_procedures.get_mut(&window) {
                    procedure.instance = new_instance;
                }
                if let Some((_, instance)) = self.dialog_procedures.get_mut(&window) {
                    *instance = new_instance;
                }
            }
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, u32::from(old), return_kind);
        }

        if index == GWL_WNDPROC {
            if !matches!(width, DataWidth::Long) {
                return zero(self, registers);
            }
            let Some(procedure) = self.window_procedures.get(&window).copied() else {
                if replacement.is_none() {
                    let native_window = self.window_handles[&window];
                    return self.begin_window_operation(registers, memory, host,
                        Win16WindowOperation::QueryProcedure { window: native_window },
                        WindowReturn::QueryProcedure { window, native_window }, return_to);
                }
                let api = if replacement.is_some() {
                    "SetWindowLong"
                } else {
                    "GetWindowLong"
                };
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
                    "Win16 {api}(GWL_WNDPROC) for guest HWND 0x{window:04X} requires a native control subclass bridge; returned zero",
                )));
                return zero(self, registers);
            };
            let old = procedure.address;
            if let Some(value) = replacement {
                self.retain_procedure_root(window, old)?;
                if let Some(procedure) = self.window_procedures.get_mut(&window) {
                    procedure.address = value;
                }
            }
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, old, return_kind);
        }

        if index == GWW_HWNDPARENT {
            let target = self.window_target(window);
            let Some(native_window) = self.window_handles.get(&window).copied() else {
                return zero(self, registers);
            };
            let call = match replacement {
                Some(value) => Win16WindowDataCall::SetParent {
                    window: target,
                    parent: self.window_target(value as u16),
                },
                None => Win16WindowDataCall::GetParent { window: target },
            };
            return self.submit_data_call(registers, memory, host, call,
                Win16WindowDataContinuation {
                    window, native_window, return_kind,
                    return_mask: u32::from(u16::MAX),
                    parent_result: true,
                }, return_to);
        }

        let native_field = match index {
            GWW_ID => Some((Win16WindowDataField::ControlId, u32::from(u16::MAX))),
            GWL_STYLE => Some((Win16WindowDataField::Style, width.mask())),
            GWL_EXSTYLE => Some((Win16WindowDataField::ExStyle, width.mask())),
            _ => None,
        };
        if let Some((field, field_mask)) = native_field {
            let target = self.window_target(window);
            let Some(native_window) = self.window_handles.get(&window).copied() else {
                return zero(self, registers);
            };
            let call = match replacement {
                Some(value) => Win16WindowDataCall::Set {
                    window: target,
                    field,
                    value: value & field_mask,
                    mask: field_mask,
                },
                None => Win16WindowDataCall::Get { window: target, field },
            };
            return self.submit_data_call(registers, memory, host, call,
                Win16WindowDataContinuation {
                    window, native_window, return_kind, return_mask: field_mask,
                    parent_result: false,
                }, return_to);
        }

        // Unknown negative indexes are ordinary USER failures (zero), not a
        // reason to stop the guest. The ABI has no richer status result.
        let _ = memory;
        zero(self, registers)
    }

    fn submit_data_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: Win16WindowDataCall,
        continuation: Win16WindowDataContinuation,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::WindowCall(Win16WindowCall::WindowData(call)),
            WindowReturn::WindowData(continuation),
            return_to,
        )
    }

    fn window_target(&self, guest: u16) -> Win16WindowTarget {
        if guest == 0 {
            Win16WindowTarget::Null
        } else {
            self.window_handles.get(&guest).copied()
                .map(Win16WindowTarget::Mapped)
                .unwrap_or(Win16WindowTarget::Invalid)
        }
    }

    fn access_guest_extra(
        &mut self,
        window: u16,
        offset: usize,
        width: DataWidth,
        replacement: Option<u32>,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u32>, RuntimeError> {
        let (length, is_dialog) = match self.window_data.get(&window) {
            Some(state) => match state.extra_bytes.as_ref() {
                Some(bytes) => (bytes.len(), state.is_dialog),
                None => {
                    self.report_missing_contract(host, window, offset as i16,
                        replacement, width)?;
                    return Ok(None);
                }
            },
            None => {
                self.report_missing_contract(host, window, offset as i16,
                    replacement, width)?;
                return Ok(None);
            }
        };
        let Some(end) = offset.checked_add(width.bytes()) else { return Ok(None) };
        // Bytes 0..11 contain the documented dialog fields, including the
        // application DWORD at DWL_USER. The manager owns [12,30); classes
        // with a larger cbWndExtra expose their remaining bytes to the guest.
        if is_dialog && offset < 30 && end > DIALOG_USER_RANGE.end {
            let api = match (replacement.is_some(), width) {
                (false, DataWidth::Word) => "GetWindowWord",
                (true, DataWidth::Word) => "SetWindowWord",
                (false, DataWidth::Long) => "GetWindowLong",
                (true, DataWidth::Long) => "SetWindowLong",
            };
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
                "Win16 {api} index {offset} addresses reserved DLGWINDOWEXTRA bytes for guest HWND 0x{window:04X}; returned zero",
            )));
            return Ok(None);
        }
        if end > length { return Ok(None); }

        let old = self.read_extra_value(window, offset, width)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 guest extra-data range changed after validation"))?;
        if let Some(value) = replacement {
            let encoded = value.to_le_bytes();
            let proc_before = self.dialog_procedures.get(&window).map(|(address, _)| *address);
            let dialog = self.window_data.get(&window)
                .is_some_and(|state| state.is_dialog);
            {
                let bytes = self.window_data.get_mut(&window)
                    .and_then(|state| state.extra_bytes.as_mut())
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "Win16 guest extra-data storage disappeared during write"))?;
                bytes.get_mut(offset..end).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 guest extra-data range changed during write"))?
                    .copy_from_slice(&encoded[..width.bytes()]);
            }
            if dialog && ranges_overlap(offset..end, DIALOG_PROC_RANGE.clone()) {
                let mut proc_bytes = proc_before.unwrap_or_else(|| {
                    let mut bytes = [0_u8; 4];
                    if let Some(area) = self.window_data.get(&window)
                        .and_then(|state| state.extra_bytes.as_ref())
                    {
                        if let Some(source) = area.get(DIALOG_PROC_RANGE.clone()) {
                            bytes.copy_from_slice(source);
                        }
                    }
                    u32::from_le_bytes(bytes)
                }).to_le_bytes();
                for (source_index, destination) in (offset..end).enumerate() {
                    if DIALOG_PROC_RANGE.contains(&destination) {
                        proc_bytes[destination - DIALOG_PROC_RANGE.start] = encoded[source_index];
                    }
                }
                let new_procedure = u32::from_le_bytes(proc_bytes);
                if proc_before != Some(new_procedure) {
                    if let Some(old_procedure) = proc_before {
                        self.retain_procedure_root(window, old_procedure)?;
                    }
                    let instance = self.window_data.get(&window)
                        .map_or(0, |state| state.instance);
                    self.dialog_procedures.insert(window, (new_procedure, instance));
                }
            }
        }
        Ok(Some(old))
    }

    fn read_extra_value(&mut self, window: u16, offset: usize, width: DataWidth)
        -> Option<u32> {
        let dialog_procedure = self.window_data.get(&window)
            .filter(|state| state.is_dialog)
            .and_then(|_| self.dialog_procedures.get(&window).map(|(address, _)| *address));
        if let Some(procedure) = dialog_procedure {
            let encoded = procedure.to_le_bytes();
            if let Some(bytes) = self.window_data.get_mut(&window)
                .and_then(|state| state.extra_bytes.as_mut())
            {
                bytes.get_mut(DIALOG_PROC_RANGE.clone())?.copy_from_slice(&encoded);
            }
        }
        let bytes = self.window_data.get(&window)?.extra_bytes.as_ref()?.get(
            offset..offset.checked_add(width.bytes())?,
        )?;
        match width {
            DataWidth::Word => Some(u32::from(u16::from_le_bytes(bytes.try_into().ok()?))),
            DataWidth::Long => Some(u32::from_le_bytes(bytes.try_into().ok()?)),
        }
    }

    fn retain_procedure_root(&mut self, window: u16, address: u32)
        -> Result<(), RuntimeError> {
        if address == 0 { return Ok(()); }
        let state = self.window_data.get_mut(&window).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 callback root has no guest window-data state"))?;
        if !state.procedure_roots.contains(&address) {
            state.procedure_roots.try_reserve(1).map_err(|_| RuntimeError::new(
                Kind::ResourceExhausted, "Win16 callback identity roots cannot grow"))?;
            state.procedure_roots.push(address);
        }
        Ok(())
    }

    fn report_missing_contract(
        &mut self,
        host: &mut impl RuntimeHost,
        window: u16,
        index: i16,
        replacement: Option<u32>,
        width: DataWidth,
    ) -> Result<(), RuntimeError> {
        if let Some(state) = self.window_data.get_mut(&window) {
            if state.reported_missing_contract { return Ok(()); }
            state.reported_missing_contract = true;
        }
        let api = match (replacement.is_some(), width) {
            (false, DataWidth::Word) => "GetWindowWord",
            (true, DataWidth::Word) => "SetWindowWord",
            (false, DataWidth::Long) => "GetWindowLong",
            (true, DataWidth::Long) => "SetWindowLong",
        };
        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
            "Win16 {api} index {index} for guest HWND 0x{window:04X} has no known guest window-data contract; returned zero",
        )));
        Ok(())
    }

}

fn zeroed_bytes(length: usize) -> Result<Vec<u8>, RuntimeError> {
    if length > i16::MAX as usize {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 window extra-data length exceeds its signed class field"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 window extra-data storage cannot grow"))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn ranges_overlap(first: std::ops::Range<usize>, second: std::ops::Range<usize>) -> bool {
    first.start < second.end && second.start < first.end
}
