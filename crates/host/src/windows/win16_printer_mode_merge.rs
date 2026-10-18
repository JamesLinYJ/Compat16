//! Merge only dmFields-selected members over current per-user settings.
use super::*;
use std::mem::offset_of;
use windows_sys::Win32::Graphics::Gdi::*;

pub(super) fn apply(current: &mut [u8], input: &[u8]) -> Result<(), RuntimeError> {
    let old = checked_native(current)?;
    let supplied = checked_native(input)?;
    const UNION: usize = offset_of!(DEVMODEW, Anonymous1);
    // SDK field offsets, widths and masks. Overlapping printer/display union
    // members are copied only when their corresponding bit was selected.
    let members = [
        (DM_ORIENTATION, UNION, 2),
        (DM_PAPERSIZE, UNION + 2, 2),
        (DM_PAPERLENGTH, UNION + 4, 2),
        (DM_PAPERWIDTH, UNION + 6, 2),
        (DM_SCALE, UNION + 8, 2),
        (DM_COPIES, UNION + 10, 2),
        (DM_DEFAULTSOURCE, UNION + 12, 2),
        (DM_PRINTQUALITY, UNION + 14, 2),
        (DM_POSITION, UNION, 8),
        (DM_DISPLAYORIENTATION, UNION + 8, 4),
        (DM_DISPLAYFIXEDOUTPUT, UNION + 12, 4),
        (DM_COLOR, offset_of!(DEVMODEW, dmColor), 2),
        (DM_DUPLEX, offset_of!(DEVMODEW, dmDuplex), 2),
        (DM_YRESOLUTION, offset_of!(DEVMODEW, dmYResolution), 2),
        (DM_TTOPTION, offset_of!(DEVMODEW, dmTTOption), 2),
        (DM_COLLATE, offset_of!(DEVMODEW, dmCollate), 2),
        (DM_FORMNAME, offset_of!(DEVMODEW, dmFormName), 64),
        (DM_LOGPIXELS, offset_of!(DEVMODEW, dmLogPixels), 2),
        (DM_BITSPERPEL, offset_of!(DEVMODEW, dmBitsPerPel), 4),
        (DM_PELSWIDTH, offset_of!(DEVMODEW, dmPelsWidth), 4),
        (DM_PELSHEIGHT, offset_of!(DEVMODEW, dmPelsHeight), 4),
        (
            DM_DISPLAYFLAGS | DM_NUP,
            offset_of!(DEVMODEW, Anonymous2),
            4,
        ),
        (
            DM_DISPLAYFREQUENCY,
            offset_of!(DEVMODEW, dmDisplayFrequency),
            4,
        ),
        (DM_ICMMETHOD, offset_of!(DEVMODEW, dmICMMethod), 4),
        (DM_ICMINTENT, offset_of!(DEVMODEW, dmICMIntent), 4),
        (DM_MEDIATYPE, offset_of!(DEVMODEW, dmMediaType), 4),
        (DM_DITHERTYPE, offset_of!(DEVMODEW, dmDitherType), 4),
        (DM_PANNINGWIDTH, offset_of!(DEVMODEW, dmPanningWidth), 4),
        (DM_PANNINGHEIGHT, offset_of!(DEVMODEW, dmPanningHeight), 4),
    ];
    for (mask, offset, length) in members {
        if supplied.dmFields & mask != 0 {
            current[offset..offset + length].copy_from_slice(&input[offset..offset + length]);
        }
    }
    let fields = offset_of!(DEVMODEW, dmFields);
    current[fields..fields + 4].copy_from_slice(&(old.dmFields | supplied.dmFields).to_le_bytes());
    // Like NT ExtDeviceMode, preserve the current driver's private defaults
    // unless the caller supplies the same nonzero private-data length.
    if supplied.dmDriverExtra != 0 && supplied.dmDriverExtra == old.dmDriverExtra {
        let start = usize::from(old.dmSize);
        let length = usize::from(old.dmDriverExtra);
        current[start..start + length].copy_from_slice(
            &input[usize::from(supplied.dmSize)..usize::from(supplied.dmSize) + length],
        );
    }
    Ok(())
}
