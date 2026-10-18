//! Checked WOW DEVMODE projection using the SDK's native A/W layouts.
//!
//! WOWDM31 preserves the ANSI public extension and the native driver's private
//! bytes behind the Win3.1 prefix. SDK offset assertions identify the shared
//! numeric spans; fixed names are transcoded separately. DEVMODEA is only an
//! internal byte layout: every call to Windows still receives DEVMODEW.
use super::{guest_text::GuestTextCodec, win16_gdi::NativeDevMode};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostDevMode};
use std::mem::{offset_of, size_of};
use win16_abi::gdi_abi::{
    DEVMODE16_SIZE, WOW_DEVMODE_PUBLIC_SIZE, WowDevModeExtra, encode_wow_devmode_extra,
};
use windows_sys::Win32::Graphics::Gdi::{DEVMODEA, DEVMODEW};

const A_SPEC: usize = offset_of!(DEVMODEA, dmSpecVersion);
const W_SPEC: usize = offset_of!(DEVMODEW, dmSpecVersion);
const A_FORM: usize = offset_of!(DEVMODEA, dmFormName);
const W_FORM: usize = offset_of!(DEVMODEW, dmFormName);
const A_TAIL: usize = A_FORM + 32;
const W_TAIL: usize = W_FORM + 64;

const _: () = {
    assert!(A_SPEC == 32 && W_SPEC == 64);
    assert!(size_of::<DEVMODEA>() == WOW_DEVMODE_PUBLIC_SIZE);
    assert!(offset_of!(DEVMODEA, dmSize) == 36);
    assert!(offset_of!(DEVMODEA, dmDriverExtra) == 38);
    assert!(offset_of!(DEVMODEA, dmFields) == 40);
    assert!(offset_of!(DEVMODEA, Anonymous1) == 44);
    assert!(offset_of!(DEVMODEA, dmTTOption) + 2 == DEVMODE16_SIZE);
    assert!(A_FORM - A_SPEC == W_FORM - W_SPEC);
    assert!(size_of::<DEVMODEA>() - A_TAIL == size_of::<DEVMODEW>() - W_TAIL);
};

pub(super) const WOW_EXTRA_OVERHEAD: usize = size_of::<DEVMODEA>() - DEVMODE16_SIZE + 12;

pub(super) struct Projection {
    pub value: Win16HostDevMode,
    pub truncated: bool,
    pub used_default_char: bool,
}

pub(super) fn printer_input(
    value: &runtime::Win16HostDevMode,
    codec: GuestTextCodec,
) -> Result<NativeDevMode, RuntimeError> {
    let wrapped =
        win16_abi::gdi_abi::decode_wow_devmode_extra(value.public_size, &value.driver_extra)
            .map_err(|_| RuntimeError::new(Kind::InvalidInput, "malformed WOW DEVMODE trailer"))?;
    if !value.has_mapped_fields() || (wrapped.is_none() && !value.driver_extra.is_empty()) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 printer DEVMODE has no verified native field/private-data mapping",
        ));
    }
    super::win16_gdi::native_devmode(value, codec)
}

pub(super) fn project(bytes: &[u8], codec: GuestTextCodec) -> Result<Projection, RuntimeError> {
    if bytes.len() < size_of::<DEVMODEW>() {
        return Err(bad_native());
    }
    // SAFETY: The checked prefix is a pointer-free SDK structure whose fields
    // are integers, fixed arrays and integer unions accepting all bit patterns.
    let native = unsafe { bytes.as_ptr().cast::<DEVMODEW>().read_unaligned() };
    let public_size = usize::from(native.dmSize);
    let extra_size = usize::from(native.dmDriverExtra);
    if public_size != size_of::<DEVMODEW>()
        || public_size
            .checked_add(extra_size)
            .is_none_or(|n| n > bytes.len())
    {
        return Err(bad_native());
    }
    let mut ansi = zeroed(size_of::<DEVMODEA>())?;
    ansi[A_SPEC..A_FORM].copy_from_slice(&bytes[W_SPEC..W_FORM]);
    ansi[A_TAIL..].copy_from_slice(&bytes[W_TAIL..public_size]);
    let device = fixed_to_guest(&native.dmDeviceName, codec)?;
    ansi[..device.bytes.len()].copy_from_slice(&device.bytes);
    let form = fixed_to_guest(&native.dmFormName, codec)?;
    ansi[A_FORM..A_FORM + form.bytes.len()].copy_from_slice(&form.bytes);
    ansi[36..38].copy_from_slice(&(size_of::<DEVMODEA>() as u16).to_le_bytes());
    let extra = encode_wow_devmode_extra(
        native.dmSpecVersion,
        &ansi[DEVMODE16_SIZE..],
        &bytes[public_size..public_size + extra_size],
    )
    .map_err(|_| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "native DEVMODE cannot fit the Win16 WOW envelope",
        )
    })?;
    if DEVMODE16_SIZE + extra.len() > 64 * 1024 {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "WOW DEVMODE exceeds the Win16 64 KiB block bound",
        ));
    }
    let mut device_name = [0; 32];
    device_name.copy_from_slice(&ansi[..32]);
    let settings = std::array::from_fn(|i| {
        let offset = 44 + i * 2;
        i16::from_le_bytes([ansi[offset], ansi[offset + 1]])
    });
    Ok(Projection {
        value: Win16HostDevMode {
            public_size: DEVMODE16_SIZE as u16,
            device_name,
            spec_version: native.dmSpecVersion.min(0x030a),
            driver_version: native.dmDriverVersion,
            fields: native.dmFields,
            settings,
            public_extension: Vec::new(),
            driver_extra: extra,
        },
        truncated: device.truncated || form.truncated,
        used_default_char: device.used_default_char == Some(true)
            || form.used_default_char == Some(true),
    })
}

pub(super) fn restore(
    value: &Win16HostDevMode,
    extra: WowDevModeExtra<'_>,
    codec: GuestTextCodec,
) -> Result<NativeDevMode, RuntimeError> {
    if usize::from(extra.native_public_size) != size_of::<DEVMODEA>()
        || !value.public_extension.is_empty()
    {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "WOW DEVMODE uses an unsupported native public layout",
        ));
    }
    let mut ansi = zeroed(size_of::<DEVMODEA>())?;
    ansi[..32].copy_from_slice(&value.device_name);
    ansi[32..34].copy_from_slice(&extra.native_spec_version.to_le_bytes());
    ansi[34..36].copy_from_slice(&value.driver_version.to_le_bytes());
    ansi[36..38].copy_from_slice(&extra.native_public_size.to_le_bytes());
    ansi[38..40].copy_from_slice(&(extra.driver_extra.len() as u16).to_le_bytes());
    ansi[40..44].copy_from_slice(&value.fields.to_le_bytes());
    for (i, setting) in value.settings.iter().enumerate() {
        ansi[44 + i * 2..46 + i * 2].copy_from_slice(&setting.to_le_bytes());
    }
    ansi[DEVMODE16_SIZE..].copy_from_slice(extra.public_extension);
    let total = size_of::<DEVMODEW>()
        .checked_add(extra.driver_extra.len())
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "native DEVMODE size overflow")
        })?;
    let mut wide = zeroed(total)?;
    wide[W_SPEC..W_FORM].copy_from_slice(&ansi[A_SPEC..A_FORM]);
    wide[W_TAIL..size_of::<DEVMODEW>()].copy_from_slice(&ansi[A_TAIL..]);
    fixed_to_wide(&ansi[..32], &mut wide[..64], codec)?;
    fixed_to_wide(&ansi[A_FORM..A_TAIL], &mut wide[W_FORM..W_TAIL], codec)?;
    wide[offset_of!(DEVMODEW, dmSize)..offset_of!(DEVMODEW, dmSize) + 2]
        .copy_from_slice(&(size_of::<DEVMODEW>() as u16).to_le_bytes());
    wide[size_of::<DEVMODEW>()..].copy_from_slice(extra.driver_extra);
    NativeDevMode::from_bytes(&wide)
}

fn fixed_to_guest(
    source: &[u16],
    codec: GuestTextCodec,
) -> Result<super::guest_text::BoundedGuestTextEncoding, RuntimeError> {
    let end = source
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(source.len());
    codec.from_wide_bounded(&source[..end], 31)
}

fn fixed_to_wide(
    source: &[u8],
    target: &mut [u8],
    codec: GuestTextCodec,
) -> Result<(), RuntimeError> {
    let end = source.iter().position(|byte| *byte == 0).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "WOW DEVMODE fixed name is not terminated",
        )
    })?;
    let encoded = codec.to_wide(&source[..end])?;
    if encoded.len() >= 32 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "WOW DEVMODE fixed name exceeds its WCHAR field",
        ));
    }
    for (i, unit) in encoded.iter().enumerate() {
        target[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

fn zeroed(size: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate DEVMODE conversion bytes",
            error,
        )
    })?;
    bytes.resize(size, 0);
    Ok(bytes)
}

fn bad_native() -> RuntimeError {
    RuntimeError::new(
        Kind::CompatibilityGap,
        "native DEVMODE has an unsupported size or truncated private tail",
    )
}

#[cfg(test)]
#[path = "win16_devmode_tests.rs"]
mod tests;
