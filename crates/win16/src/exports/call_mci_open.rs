//! MCI_OPEN parameter layouts selected by SDK 3.1 device family.

use super::*;

#[derive(Clone, Copy)]
enum OpenDeviceKind {
    Waveform,
    Animation,
    Overlay,
}

pub(super) fn decode_open(
    flags: u32,
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciParameters, Win16Error> {
    const OPEN_TYPE_ID: u32 = 0x1000;
    const OPEN_ELEMENT: u32 = 0x0200;
    const OPEN_ELEMENT_ID: u32 = 0x0800;
    const EXTENSION_FLAGS: u32 = 0x0007_0000;
    let bytes = read_struct(far, 20, false, selectors, memory)?;
    let record = mci_wire::read::<mci_wire::Open>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
    validate_far_write_at(far, 4, 2, selectors, memory)?;
    let type_raw = record.device_type.get();
    let element_raw = record.element.get();
    let alias_raw = record.alias.get();
    let device_type = if flags & 0x2000 == 0 && flags & OPEN_TYPE_ID == 0 {
        None
    } else if flags & OPEN_TYPE_ID != 0 {
        // Preserve the Win16 DWORD until host projection validates its ordinal.
        (type_raw != 0).then_some(Win16MciOpenValue::ResourceId(type_raw))
    } else if type_raw == 0 {
        None
    } else {
        Some(Win16MciOpenValue::Ansi(read_far_string(
            type_raw, selectors, memory,
        )?))
    };
    let element = if flags & OPEN_ELEMENT == 0 && flags & OPEN_ELEMENT_ID == 0 {
        None
    } else if flags & OPEN_ELEMENT_ID != 0 {
        (element_raw != 0).then_some(Win16MciOpenValue::ElementId(element_raw))
    } else if element_raw == 0 {
        None
    } else {
        Some(Win16MciOpenValue::Ansi(read_far_string(
            element_raw, selectors, memory,
        )?))
    };
    let alias = if flags & 0x0400 == 0 || alias_raw == 0 {
        None
    } else {
        Some(read_far_string(alias_raw, selectors, memory)?)
    };
    let type_kind = mci_open_device_kind(device_type.as_ref());
    let extension = match (flags & EXTENSION_FLAGS, type_kind) {
        (0, _) => Win16MciOpenExtension::None,
        (value, Some(OpenDeviceKind::Waveform)) if value == 0x0001_0000 => {
            let bytes = read_struct(far, 24, false, selectors, memory)?;
            let record = mci_wire::read::<mci_wire::WaveOpen>(&bytes)
                .map_err(|_| Win16Error::InvalidRange)?;
            Win16MciOpenExtension::Wave {
                buffer_seconds: record.buffer_seconds.get(),
            }
        }
        (value, Some(OpenDeviceKind::Animation | OpenDeviceKind::Overlay)) => {
            // The target family selects this fixed extension layout; the
            // overlapping flag bits do not independently select a record.
            let bytes = read_struct(far, 28, false, selectors, memory)?;
            let record = mci_wire::read::<mci_wire::WindowOpen>(&bytes)
                .map_err(|_| Win16Error::InvalidRange)?;
            Win16MciOpenExtension::Window {
                style: if value & 0x0001_0000 != 0 {
                    record.style.get()
                } else {
                    0
                },
                parent_window: if value & 0x0002_0000 != 0 {
                    record.parent_window.get()
                } else {
                    0
                },
            }
        }
        _ => {
            return Ok(Win16MciParameters::Unsupported {
                message: MCI_OPEN,
                flags,
            });
        }
    };
    Ok(Win16MciParameters::Open {
        callback: record.callback.get(),
        device_type,
        element,
        alias,
        extension,
    })
}

fn mci_open_device_kind(value: Option<&Win16MciOpenValue>) -> Option<OpenDeviceKind> {
    match value {
        Some(Win16MciOpenValue::ResourceId(522)) => Some(OpenDeviceKind::Waveform),
        Some(Win16MciOpenValue::ResourceId(519)) => Some(OpenDeviceKind::Animation),
        Some(Win16MciOpenValue::ResourceId(515)) => Some(OpenDeviceKind::Overlay),
        Some(Win16MciOpenValue::Ansi(name)) if name.eq_ignore_ascii_case(b"waveaudio") => {
            Some(OpenDeviceKind::Waveform)
        }
        Some(Win16MciOpenValue::Ansi(name)) if name.eq_ignore_ascii_case(b"animation") => {
            Some(OpenDeviceKind::Animation)
        }
        Some(Win16MciOpenValue::Ansi(name)) if name.eq_ignore_ascii_case(b"overlay") => {
            Some(OpenDeviceKind::Overlay)
        }
        _ => None,
    }
}
