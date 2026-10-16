//! Guest class resource replacement for USER.130 SetClassWord.
//!
//! `WINDOWS.H:2956-2958` declares the class icon, cursor and background as
//! WORD class fields, and every window created from the class is defaulted by
//! `DefWindowProc`, which supplies those resources natively. A replacement
//! therefore has to reach the registered native class as well as the guest
//! metadata; publishing only one of them would report a change that the
//! original program cannot observe.
//!
//! The native replacement runs before the guest field is published. A native
//! refusal keeps the old field; a host transport error stops dispatch without
//! returning a guest result. Guest handles and previous values stay WORDs,
//! never native resource handles.

use super::*;
use crate::{Diagnostic, Win16HostClassResource};

/// The class resource fields `WINDOWS.H` exposes through Get/SetClassWord.
#[derive(Clone, Copy)]
enum Slot { Icon, Cursor, Background }

impl Slot {
    fn name(self) -> &'static str {
        match self {
            Self::Icon => "GCW_HICON",
            Self::Cursor => "GCW_HCURSOR",
            Self::Background => "GCW_HBRBACKGROUND",
        }
    }
}

impl GuestWindowClasses {
    /// Replace one guest class resource field and return its previous WORD.
    /// The entry is located by the exact host class token, so a reused guest
    /// handle or a class-name collision cannot redirect the write.
    fn replace_resource(
        &mut self,
        class: Win16HostClass,
        slot: Slot,
        handle: u16,
    ) -> Option<u16> {
        let entry = self.entries.iter_mut().find(|entry| entry.host_class == class)?;
        let field = match slot {
            Slot::Icon => &mut entry.info.h_icon,
            Slot::Cursor => &mut entry.info.h_cursor,
            Slot::Background => &mut entry.info.hbr_background,
        };
        Some(std::mem::replace(field, handle))
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn set_class_icon(
        &mut self,
        window: u16,
        class: Win16HostClass,
        handle: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.replace_class_resource(window, class, Slot::Icon, handle, host)
    }

    pub(in crate::win16_runtime) fn set_class_cursor(
        &mut self,
        window: u16,
        class: Win16HostClass,
        handle: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.replace_class_resource(window, class, Slot::Cursor, handle, host)
    }

    pub(in crate::win16_runtime) fn set_class_background(
        &mut self,
        window: u16,
        class: Win16HostClass,
        handle: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.replace_class_resource(window, class, Slot::Background, handle, host)
    }

    fn replace_class_resource(
        &mut self,
        window: u16,
        class: Win16HostClass,
        slot: Slot,
        value: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // The selected HWND names the class the replacement reaches, exactly
        // as the Win16 entry point does. Predefined aliases and windows whose
        // class is not this exact registration never grant private metadata.
        let Some(&native) = self.window_handles.get(&window) else { return Ok(0); };
        if window == 0 || self.window_host_class(window) != Some(class)
            || self.window_system_classes.contains_key(&window)
        {
            return Ok(0);
        }
        // A declared WORD field holds the guest handle, and the owned resource
        // behind it is the same token kind registration passes to the host. A
        // Win16 resource handle is 16 bits; the class accessor admitted only
        // the documented WORD form before reaching this helper.
        let handle = value as u16;
        let resource = match slot {
            Slot::Icon => match self.guest_images.icon(handle) {
                Some(icon) => Win16HostClassResource::Icon(Some(icon)),
                None if handle == 0 => Win16HostClassResource::Icon(None),
                None => return Ok(refused_resource(host, window, slot)),
            },
            Slot::Cursor => match self.guest_images.cursor(handle) {
                Some(cursor) => Win16HostClassResource::Cursor(Some(cursor)),
                None if handle == 0 => Win16HostClassResource::Cursor(None),
                None => return Ok(refused_resource(host, window, slot)),
            },
            Slot::Background => {
                let background = if handle == 0 {
                    None
                } else if handle <= LAST_SYSTEM_COLOR_INDEX + 1 {
                    // Win16 passes COLOR_* + 1 as an HBRUSH value.
                    Some(Win16ClassBackground::SystemColor(handle - 1))
                } else {
                    match self.guest_gdi.object(handle) {
                        Some(brush) => Some(Win16ClassBackground::Brush(brush)),
                        None => return Ok(refused_resource(host, window, slot)),
                    }
                };
                Win16HostClassResource::Background(background)
            }
        };
        // The host confirms the native replacement before guest publication.
        // Ok(false) guarantees no native mutation; a transport error instead
        // stops dispatch because the native outcome may not be observable.
        if !host.win16_replace_class_resource(class, native, resource)? {
            return Ok(refused_resource(host, window, slot));
        }
        let previous = self.window_classes.replace_resource(class, slot, handle)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "native class resource replacement lost its guest registration"))?;
        Ok(u32::from(previous))
    }
}

fn refused_resource(host: &mut impl RuntimeHost, window: u16, slot: Slot) -> u32 {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
        "Win16 SetClassWord {} for guest HWND 0x{window:04X} could not replace \
         the class resource; the previous value stands",
        slot.name(),
    )));
    0
}
