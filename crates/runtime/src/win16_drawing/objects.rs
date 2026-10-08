//! Objects requests handled by the direct Win16 GDI adapter.

use super::*;

impl Win16State {
    pub(super) fn drawing_object_requests(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreateSolidBrush {
                color,
            }) => match host.win16_gdi(Operation::CreateSolidBrush { color })? {
                HostResult::Object(Some(object)) => {
                    if let Some(handle) = self.guest_gdi.allocate_object(object) {
                        Ok(u32::from(handle))
                    } else {
                        let _ = host.win16_delete_object(object)?;
                        Ok(0)
                    }
                }
                HostResult::Object(None) => Ok(0),
                _ => Err(wrong_result("CreateSolidBrush")),
            },
            request => self.drawing_extended(request, memory, host),
        }
    }
}
