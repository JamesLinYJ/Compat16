//! Win16 USER query, state, geometry, and RECT operation marshalling.

use guest_core::{Registers, memory::Memory};
use win16_abi::{
    Access, Point16, Rect16, SegmentedPointer, Win16ApiRequest, Win16ClassName, Win16ReturnKind,
};

use super::Win16State;
use super::windows::WindowReturn;
use crate::win16_host_window_ops::{
    Win16WindowCall, Win16WindowCallContinuation, Win16WindowCallOutput,
    Win16WindowInsertAfter, Win16WindowSearchClass, Win16WindowTarget,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostPoint, Win16WindowOperation,
};

#[path = "win16_window_operations/child_lookup.rs"]
mod child_lookup;
#[path = "win16_window_operations/geometry.rs"]
mod geometry;
#[path = "win16_window_operations/defer.rs"]
mod defer;
pub(super) use defer::DeferredWindowBatches;
#[path = "win16_window_operations/caret.rs"]
mod caret;
#[path = "win16_window_operations/window.rs"]
mod window;
#[path = "win16_window_operations/mdi.rs"]
mod mdi;

const POINT16_SIZE: usize = 4;

impl Win16State {
    /// Handle the batched Win16 USER window-operation exports from their
    /// project-owned decoded request and return contract.
    /// Dispatch geometry helpers and native USER window calls to their focused request modules.
    pub(super) fn begin_window_api(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16ApiRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16ApiRequest as Request;

        match request {
            Request::User(win16_abi::Win16UserRequest::ChildLookup(request)) => {
                self.begin_user_child_lookup(request, registers, memory, host, return_to, return_kind)
            }
            Request::User(win16_abi::Win16UserRequest::Mdi(request)) => {
                self.begin_user_mdi(request, registers, memory, host, return_to, return_kind)
            }
            request @ Request::User(win16_abi::Win16UserRequest::Geometry(_)) => {
                self.begin_geometry_api(registers, memory, host, request, return_to, return_kind)
            }
            request @ Request::User(win16_abi::Win16UserRequest::Window(_)) => {
                self.begin_window_request(registers, memory, host, request, return_to, return_kind)
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-window request reached the Win16 window-operation bridge",
            )),
        }
    }

    fn submit_value_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: Win16WindowCall,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.submit_call(
            registers,
            memory,
            host,
            call,
            Win16WindowCallOutput::None,
            return_to,
            return_kind,
            None,
        )
    }

    pub(super) fn submit_call(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: Win16WindowCall,
        output: Win16WindowCallOutput,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        destroyed_guest_window: Option<u16>,
    ) -> Result<Option<u8>, RuntimeError> {
        let continuation = Win16WindowCallContinuation {
            return_kind,
            output,
            destroyed_guest_window,
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::WindowCall(call),
            WindowReturn::WindowCall(continuation),
            return_to,
        )
    }

    pub(super) fn native_window(&self, guest: u16) -> Win16WindowTarget {
        if guest == 0 {
            Win16WindowTarget::Null
        } else {
            self.window_handles
                .get(&guest)
                .copied()
                .map(Win16WindowTarget::Mapped)
                .unwrap_or(Win16WindowTarget::Invalid)
        }
    }

    fn window_insert_after(&self, guest: u16) -> Option<Win16WindowInsertAfter> {
        Some(match guest {
            0 => Win16WindowInsertAfter::Top,
            1 => Win16WindowInsertAfter::Bottom,
            u16::MAX => Win16WindowInsertAfter::Topmost,
            0xfffe => Win16WindowInsertAfter::NotTopmost,
            value => Win16WindowInsertAfter::Window(*self.window_handles.get(&value)?),
        })
    }

    fn find_window_class(
        &self,
        class: Option<Win16ClassName>,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16WindowSearchClass>, RuntimeError> {
        let Some(class) = class else {
            return Ok(None);
        };
        if let Some(host_class) = self.window_classes.host_class_for_name(&class, host)? {
            return Ok(Some(Win16WindowSearchClass::Registered(host_class)));
        }
        match class {
            Win16ClassName::Name(name) => Ok(Some(Win16WindowSearchClass::Name(name))),
            Win16ClassName::Atom(atom) => {
                let (bytes, copied) = host.win16_global_get_atom_name(atom, 256)?;
                let Some(name) = bytes.get(..usize::from(copied)) else {
                    return Ok(None);
                };
                if copied == 0 {
                    Ok(None)
                } else {
                    Ok(Some(Win16WindowSearchClass::Name(name.to_vec())))
                }
            }
        }
    }

    fn checked_guest_range(
        &self,
        far: u32,
        size: usize,
        access: Access,
        memory: &Memory,
    ) -> Result<SegmentedPointer, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, access, size, memory)
            .map_err(crate::runtime_error)?;
        Ok(pointer)
    }

    fn read_rect(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
    ) -> Result<Rect16, RuntimeError> {
        let mut bytes = [0; Rect16::SIZE];
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        Ok(Rect16::decode(&bytes))
    }

    fn write_rect(
        &self,
        memory: &mut Memory,
        pointer: SegmentedPointer,
        rect: Rect16,
    ) -> Result<(), RuntimeError> {
        self.selectors
            .write(memory, pointer, &rect.encode())
            .map_err(crate::runtime_error)
    }

    fn read_point(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
    ) -> Result<Point16, RuntimeError> {
        let mut bytes = [0; 4];
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(crate::runtime_error)?;
        Ok(Point16 {
            x: i16::from_le_bytes([bytes[0], bytes[1]]),
            y: i16::from_le_bytes([bytes[2], bytes[3]]),
        })
    }

}

fn is_rect_empty(rect: Rect16) -> bool {
    rect.left >= rect.right || rect.top >= rect.bottom
}
