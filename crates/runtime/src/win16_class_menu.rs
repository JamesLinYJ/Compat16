//! Class default-menu replacement without storing native or borrowed pointers.
//!
//! The Win16 SDK declares GCL_MENUNAME as a LONG FAR value. Keep that exact
//! value for Get/SetClassLong while copying the resource identity for later
//! CreateWindow and custom-dialog preparation. Existing HWND menus and already
//! prepared creation payloads keep their independent menu instances.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn set_class_menu_name(
        &mut self,
        class: Win16HostClass,
        address: u32,
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        // Resolve the exact guest registration before touching a caller FAR.
        // A predefined/native class never grants access to private metadata.
        let Some(index) = self.window_classes.entries.iter()
            .position(|entry| entry.host_class == class) else { return Ok(0); };
        let menu_name = if address == 0 {
            None
        } else if address >> 16 == 0 {
            Some(Win16ResourceName::Id(address as u16))
        } else {
            let bytes = match win16_abi::strings::read_ansi_z(
                &self.selectors, memory, address, win16_abi::MAX_WIN16_STRING_BYTES,
            ) {
                Ok(bytes) => bytes,
                Err(win16_abi::Win16Error::OutOfMemory) => return Err(RuntimeError::new(
                    Kind::ResourceExhausted, "cannot copy Win16 class menu resource name")),
                // Invalid guest storage must not publish only the raw LONG or
                // erase the old menu. No native mutation has been attempted.
                Err(_) => return Ok(0),
            };
            Some(Win16ResourceName::Name(bytes))
        };
        // All validation and allocation precede publication; no callback or
        // fallible work can leave raw metadata and the resource copy unequal.
        let entry = &mut self.window_classes.entries[index];
        let previous = entry.info.lpsz_menu_name;
        entry.menu_name = menu_name;
        entry.info.lpsz_menu_name = address;
        Ok(previous)
    }
}
