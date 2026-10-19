//! Pointer-free values crossing the Win16 GDI device-context host boundary.

use win16_abi::gdi_abi::{
    DevMode16, DEVMODE16_SUPPORTED_FIELDS, WOW_DEVMODE_PUBLIC_SIZE,
    decode_wow_devmode_extra,
};

/// Owned Win16 device settings after runtime has copied and checked the guest
/// `DEVMODE` range. Windows GDI receives a separately constructed native
/// `DEVMODEW`; this value never contains a guest or host pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDevMode {
    pub public_size: u16,
    pub device_name: [u8; 32],
    pub spec_version: u16,
    pub driver_version: u16,
    pub fields: u32,
    /// Orientation through TrueType option in Win16 `DEVMODE` member order.
    pub settings: [i16; 12],
    /// Preserved public bytes beyond the verified Windows 3.1 layout.
    pub public_extension: Vec<u8>,
    /// Owned bytes following the declared Win16 public structure.
    pub driver_extra: Vec<u8>,
}

impl Win16HostDevMode {
    /// Later field bits are backed by the checked WOW public extension. A
    /// recognized but malformed trailer must never fall back to legacy input.
    pub fn has_mapped_fields(&self) -> bool {
        if !self.public_extension.is_empty() { return false; }
        match decode_wow_devmode_extra(self.public_size, &self.driver_extra) {
            Ok(Some(extra)) => usize::from(extra.native_public_size) == WOW_DEVMODE_PUBLIC_SIZE,
            Ok(None) => self.fields & !DEVMODE16_SUPPORTED_FIELDS == 0,
            Err(_) => false,
        }
    }
}

impl From<DevMode16> for Win16HostDevMode {
    fn from(value: DevMode16) -> Self {
        Self {
            public_size: value.public_size,
            device_name: value.device_name,
            spec_version: value.spec_version,
            driver_version: value.driver_version,
            fields: value.fields,
            settings: value.settings,
            public_extension: value.public_extension,
            driver_extra: value.driver_extra,
        }
    }
}

/// Copied native font metrics in field groups shared with font enumeration.
/// The runtime serializes these through the `TEXTMETRIC16` codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostTextMetrics {
    pub dimensions: [i32; 8],
    pub styles: [u8; 9],
    pub extra: [i32; 3],
}

/// Guest-byte result converted from native `GetTextFaceW` output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostTextFace {
    pub result: i32,
    pub bytes: Vec<u8>,
}

/// Owned outline metrics. `fixed` contains the packed Win16 prefix through
/// underscore size; the runtime supplies otmSize and relative name offsets.
/// Names are UTF-16 words without terminators, copied out of native storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostOutlineTextMetrics {
    pub fixed: [u8; 106],
    pub names: [Vec<u16>; 4],
}

/// Public Windows mapping-mode constants. Fixed modes already have a logical
/// unit, so native outline metrics can be narrowed into the Win16 layout.
/// `MM_ISOTROPIC` (7) and `MM_ANISOTROPIC` (8) stay rejected until an extent
/// path is tested. Callers do not prefill the guest buffer with a debug pattern.
pub fn win16_outline_text_map_mode_supported(mode: i32) -> bool {
    matches!(mode, 1..=6)
}

#[cfg(test)]
mod tests {
    use super::win16_outline_text_map_mode_supported;

    #[test]
    fn wow_devmode_modern_fields_require_a_complete_supported_envelope() {
        use super::Win16HostDevMode;
        use win16_abi::gdi_abi::encode_wow_devmode_extra;
        let mut mode = Win16HostDevMode {
            public_size: 68, device_name: [0; 32], spec_version: 0x030a,
            driver_version: 1, fields: 0x8000, settings: [0; 12],
            public_extension: vec![], driver_extra: vec![],
        };
        assert!(!mode.has_mapped_fields());
        mode.driver_extra = encode_wow_devmode_extra(0x0401, &[0; 88], &[1, 2]).unwrap();
        assert!(mode.has_mapped_fields());
        mode.public_size = 64;
        assert!(!mode.has_mapped_fields());
        mode.public_size = 68;
        let end = mode.driver_extra.len();
        mode.driver_extra[end - 4..end - 2].copy_from_slice(&3_u16.to_le_bytes());
        assert!(!mode.has_mapped_fields());
        // Even basic fields cannot make a recognized damaged trailer valid.
        mode.fields = 1;
        assert!(!mode.has_mapped_fields());
        mode.driver_extra.clear();
        assert!(mode.has_mapped_fields());
        mode.public_extension.push(0);
        assert!(!mode.has_mapped_fields());
    }

    #[test]
    fn outline_text_metrics_keeps_fixed_modes_and_rejects_untested_extents() {
        for mode in 1..=6 {
            assert!(win16_outline_text_map_mode_supported(mode), "{mode}");
        }
        for mode in [0, 7, 8, 9, -1, i32::MIN, i32::MAX] {
            assert!(!win16_outline_text_map_mode_supported(mode), "{mode}");
        }
    }
}
