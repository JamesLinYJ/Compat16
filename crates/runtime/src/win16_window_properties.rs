//! Win16 USER Set/Get/Remove/EnumProps and guest callback continuation.
//!
//! The Win16 contract is from the bundled SDK 3.1 `WINDOWS.H` and Programmer's
//! Reference: Vol. 1 §1.17 (Property Functions) and Vol. 2, printed pp. 281
//! (`EnumProps`) and 854 (`SetProp`). These specify global-atom property keys,
//! original atom-versus-string callback form, current-item removal, early
//! termination when another property is removed, and `-1` when no property is
//! enumerated. Host calls use Microsoft's SetPropA/GetPropA/RemovePropA/
//! EnumPropsA contract. Win16 `HANDLE` data remains an opaque WORD; the host
//! stores it in a private sidecar rather than exposing the native HANDLE.

use guest_core::{memory::Memory, Registers};
use win16_abi::{Win16ReturnKind, Win16WindowPropertyName, Win16WindowPropertyRequest};
use super::{windows::WindowReturn, Win16State};
use crate::{RuntimeError, RuntimeHost, Win16HostPropertyName, Win16WindowCall,
    Win16WindowOperation, Win16WindowTarget};

const MAX_PROPERTY_NAME_BYTES: usize = 255;

#[derive(Clone, Copy)]
pub(super) enum WindowPropertyReturn {
    Set,
    Get,
    Remove,
    Enum { procedure: u32, guest_window: u16 },
}

impl Win16State {
    pub(super) fn begin_window_properties(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16WindowPropertyRequest,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16WindowPropertyRequest as Request;
        match request {
            Request::Set { window, name, data } => {
                let Some(name) = host_name(name) else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::SetWindowProperty {
                        window: self.property_window_target(window), name, data,
                    }, WindowPropertyReturn::Set, return_to)
            }
            Request::Get { window, name } => {
                let Some(name) = host_name(name) else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::GetWindowProperty {
                        window: self.property_window_target(window), name,
                    }, WindowPropertyReturn::Get, return_to)
            }
            Request::Remove { window, name } => {
                let Some(name) = host_name(name) else {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::RemoveWindowProperty {
                        window: self.property_window_target(window), name,
                    }, WindowPropertyReturn::Remove, return_to)
            }
            Request::Enum { window, callback } => {
                self.begin_property_call(registers, memory, host,
                    Win16WindowCall::EnumWindowProperties {
                        window: self.property_window_target(window),
                    }, WindowPropertyReturn::Enum {
                        procedure: callback,
                        guest_window: window,
                    }, return_to)
            }
        }
    }

    fn begin_property_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: Win16WindowCall,
        result: WindowPropertyReturn,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::WindowCall(call),
            WindowReturn::WindowProperties(result),
            return_to,
        )
    }

    fn property_window_target(&self, guest: u16) -> Win16WindowTarget {
        if guest == 0 {
            Win16WindowTarget::Null
        } else {
            self.window_handles.get(&guest).copied()
                .map(Win16WindowTarget::Mapped)
                .unwrap_or(Win16WindowTarget::Invalid)
        }
    }

}

pub(super) fn host_name(name: Win16WindowPropertyName) -> Option<Win16HostPropertyName> {
    Some(match name {
        Win16WindowPropertyName::Atom(0) => return None,
        Win16WindowPropertyName::Atom(atom) => Win16HostPropertyName::Atom(atom),
        Win16WindowPropertyName::String(bytes)
            if bytes.is_empty() || bytes.len() > MAX_PROPERTY_NAME_BYTES || bytes.contains(&0) => {
                return None;
            }
        Win16WindowPropertyName::String(bytes) => Win16HostPropertyName::String(bytes),
    })
}
