//! Shared Win16 memory and record conversion helpers for common dialogs.

use guest_core::memory::Memory;
use win16_abi::{
    GlobalHandle, SegmentedPointer, SelectorRef, gdi_abi::LogFont16,
};

use super::{ranges::GuestOutputRange, Win16State};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDevMode,
    Win16HostLogFont, Win16HostWindow,
};

pub(super) const MAX_COMMON_DIALOG_BYTES: usize = 64 * 1024;

/// HGLOBAL identity and its exact selector span, retained across native calls.
/// GlobalHandle carries the heap generation; the range retains every selector
/// generation, descriptor extent, rights set and physical span.
#[derive(Clone, Debug)]
pub(in crate::win16_runtime) struct GuestGlobalCapture {
    guest_handle: u16,
    identity: GlobalHandle,
    selector: SelectorRef,
    size: usize,
    range: GuestOutputRange,
}

impl GuestGlobalCapture {
    pub(super) fn guest_handle(&self) -> u16 { self.guest_handle }
    pub(super) fn identity(&self) -> GlobalHandle { self.identity }

    pub(super) fn is_live(
        &self,
        state: &Win16State,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        if state.global_handles.get(&self.guest_handle).copied() != Some(self.identity)
            || state.global_selectors.get(&self.guest_handle).copied() != Some(self.selector)
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 common-dialog HGLOBAL identity changed while suspended"));
        }
        // The runtime-owned handle map still names this generation. Its
        // disappearance is bookkeeping corruption; guest GlobalFree/ReAlloc
        // is handled by the map-identity check above and remains recoverable.
        let info = state.heap.info(self.identity).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "retained PRINTDLG HGLOBAL identity disappeared", error))?;
        if info.discarded || usize::try_from(info.size).ok() != Some(self.size) {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 common-dialog HGLOBAL was discarded or resized while suspended"));
        }
        let descriptor = state.selectors.describe(self.selector).map_err(|error|
            RuntimeError::with_source(Kind::InternalInvariant,
                "runtime retained a stale PRINTDLG HGLOBAL selector", error))?;
        if !descriptor.present || descriptor.base != info.base {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 common-dialog HGLOBAL selector no longer identifies its block"));
        }
        self.range.is_live(state, memory)
    }

    pub(super) fn read(
        &self,
        state: &Win16State,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.is_live(state, memory)?;
        self.range.read(state, memory)
    }
}

impl Win16State {
    pub(super) fn common_dialog_owner(
        &self,
        owner: u16,
    ) -> Result<Option<Win16HostWindow>, RuntimeError> {
        if owner == 0 { return Ok(None); }
        self.window_handles.get(&owner).copied().map(Some).ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault, "Win16 common-dialog owner HWND is not mapped")
        })
    }

    pub(super) fn capture_guest_global(
        &self,
        guest_handle: u16,
        memory: &Memory,
    ) -> Result<GuestGlobalCapture, RuntimeError> {
        let identity = self.global_handles.get(&guest_handle).copied().ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault,
                "Win16 common-dialog non-NULL HGLOBAL is not allocated")
        })?;
        let info = self.heap.info(identity).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "runtime HGLOBAL table contains a stale generation", error))?;
        if info.discarded || info.size == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 common-dialog non-NULL HGLOBAL is discarded or empty"));
        }
        let selector = self.global_selectors.get(&guest_handle).copied().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "live Win16 HGLOBAL has no selector identity")
        })?;
        let descriptor = self.selectors.describe(selector).map_err(|error|
            RuntimeError::with_source(Kind::InternalInvariant,
                "runtime HGLOBAL table contains a stale selector identity", error))?;
        if !descriptor.present || descriptor.base != info.base {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 common-dialog HGLOBAL selector is not backed by its allocation"));
        }
        let size = usize::try_from(info.size).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "Win16 PRINTDLG global block size exceeds address space", error))?;
        if size > MAX_COMMON_DIALOG_BYTES {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 PRINTDLG global block exceeds the 64 KiB bound"));
        }
        let range = GuestOutputRange::capture(
            self, memory, SegmentedPointer::new(selector, 0), size,
        )?;
        Ok(GuestGlobalCapture { guest_handle, identity, selector, size, range })
    }

    pub(super) fn write_guest_global(
        &mut self,
        guest_handle: u16,
        expected: Option<GlobalHandle>,
        bytes: &[u8],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if bytes.len() > MAX_COMMON_DIALOG_BYTES {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 PRINTDLG result block exceeds the 64 KiB bound"));
        }
        let size = u32::try_from(bytes.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "Win16 PRINTDLG result size exceeds DWORD", error))?;
        let allocated = guest_handle == 0;
        let handle = if allocated {
            if expected.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "null PRINTDLG output handle retained a heap identity"));
            }
            let handle = self.global_alloc(0x0042, size, memory, host)?;
            if handle == 0 {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "cannot allocate Win16 PRINTDLG global output block"));
            }
            handle
        } else {
            let expected = expected.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "non-NULL PRINTDLG output handle has no captured identity"))?;
            if self.global_handles.get(&guest_handle).copied() != Some(expected) {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 PRINTDLG output HGLOBAL identity changed while suspended"));
            }
            if self.global_size(guest_handle)? < size {
                let resized = self.kernel_global_realloc(guest_handle, size, 0, memory, host)?;
                if resized == 0 {
                    return Err(RuntimeError::new(Kind::ResourceExhausted,
                        "cannot resize Win16 PRINTDLG global output block"));
                }
            }
            guest_handle
        };
        let far = self.global_lock(handle, memory)?;
        let write_result = if far == 0 {
            Err(RuntimeError::new(Kind::GuestFault,
                "Win16 PRINTDLG global output block could not be locked"))
        } else {
            self.selectors.pointer_from_far(far).map_err(crate::runtime_error)
                .and_then(|pointer| self.preflight_text_write(memory, pointer, bytes.len())
                    .and_then(|()| self.write_text_bytes(memory, pointer, bytes)))
        };
        let unlock_result = if far == 0 { Ok(0) } else { self.global_unlock(handle) };
        match (write_result, unlock_result) {
            (Ok(()), Ok(_)) => Ok(handle),
            (Err(error), _) => {
                if allocated { let _ = self.global_free(handle); }
                Err(error)
            }
            (Ok(()), Err(error)) => {
                if allocated { let _ = self.global_free(handle); }
                Err(error)
            }
        }
    }

    pub(super) fn optional_output_range(
        &self,
        memory: &Memory,
        far: u32,
        capacity: u32,
    ) -> Result<Option<GuestOutputRange>, RuntimeError> {
        if far == 0 { return Ok(None); }
        let capacity = checked_capacity(capacity)?;
        if capacity == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, capacity).map(Some)
    }

    pub(super) fn read_multisz(
        &self,
        memory: &Memory,
        far: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if far == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 filter list begins outside its selector"))?;
        let count = usize::try_from(available).unwrap_or(usize::MAX)
            .min(MAX_COMMON_DIALOG_BYTES);
        let bytes = self.read_text_bytes(memory, pointer, count)?;
        let end = bytes.windows(2).position(|pair| pair == [0, 0]).ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault,
                "Win16 filter list is not double NUL terminated within its selector")
        })?;
        Ok(Some(bytes[..end + 2].to_vec()))
    }
}

pub(super) fn host_log_font(value: LogFont16) -> Win16HostLogFont {
    let [height, width, escapement, orientation, weight] = value.dimensions;
    let [italic, underline, strikeout, char_set, out_precision, clip_precision, quality,
        pitch_and_family] = value.styles;
    Win16HostLogFont { height, width, escapement, orientation, weight, italic, underline,
        strikeout, char_set, out_precision, clip_precision, quality, pitch_and_family,
        face_name: value.face_name }
}

pub(super) fn guest_log_font(value: Win16HostLogFont) -> win16_abi::user_service_abi::LogFont16 {
    // Reuse USER's zerocopy LOGFONT wire codec for the same fixed Win16 layout.
    win16_abi::user_service_abi::LogFont16 {
        height: value.height, width: value.width, escapement: value.escapement,
        orientation: value.orientation, weight: value.weight,
        italic: value.italic, underline: value.underline, strike_out: value.strikeout,
        char_set: value.char_set, out_precision: value.out_precision,
        clip_precision: value.clip_precision, quality: value.quality,
        pitch_and_family: value.pitch_and_family,
        face_name: value.face_name,
    }
}

pub(super) fn encode_devmode16(value: &Win16HostDevMode) -> Result<Vec<u8>, RuntimeError> {
    let public_size = win16_abi::gdi_abi::DEVMODE16_SIZE
        .checked_add(value.public_extension.len())
        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
            "Win16 DEVMODE public size overflow"))?;
    let extra_size = value.driver_extra.len();
    if public_size > usize::from(u16::MAX) || extra_size > usize::from(u16::MAX) {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "Win16 DEVMODE output exceeds its 16-bit size fields"));
    }
    let total = public_size.checked_add(extra_size).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 DEVMODE total size overflow"))?;
    if total > MAX_COMMON_DIALOG_BYTES {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "Win16 DEVMODE output exceeds the 64 KiB bound"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 DEVMODE output bytes", error))?;
    bytes.resize(total, 0);
    bytes[..32].copy_from_slice(&value.device_name);
    bytes[32..34].copy_from_slice(&value.spec_version.to_le_bytes());
    bytes[34..36].copy_from_slice(&value.driver_version.to_le_bytes());
    bytes[36..38].copy_from_slice(&(public_size as u16).to_le_bytes());
    bytes[38..40].copy_from_slice(&(extra_size as u16).to_le_bytes());
    bytes[40..44].copy_from_slice(&value.fields.to_le_bytes());
    for (index, setting) in value.settings.iter().enumerate() {
        let offset = 44 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&setting.to_le_bytes());
    }
    bytes[win16_abi::gdi_abi::DEVMODE16_SIZE..public_size]
        .copy_from_slice(&value.public_extension);
    bytes[public_size..].copy_from_slice(&value.driver_extra);
    Ok(bytes)
}

pub(super) fn validate_dev_names(bytes: &[u8]) -> Result<(), RuntimeError> {
    if bytes.len() < 8 || bytes.len() > MAX_COMMON_DIALOG_BYTES {
        return Err(RuntimeError::new(Kind::GuestFault,
            "Win16 PRINTDLG DEVNAMES block has an invalid size"));
    }
    for offset in [0, 2, 4] {
        let start = usize::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]));
        if start < 8 || start >= bytes.len() || !bytes[start..].contains(&0) {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 PRINTDLG DEVNAMES string offset is outside its global block"));
        }
    }
    Ok(())
}

pub(super) fn checked_capacity(capacity: u32) -> Result<usize, RuntimeError> {
    let capacity = usize::try_from(capacity).unwrap_or(usize::MAX);
    if capacity > MAX_COMMON_DIALOG_BYTES {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "Win16 common-dialog buffer exceeds the 64 KiB bound"));
    }
    Ok(capacity)
}
