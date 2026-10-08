//! Menu creation requests and resource-template projection.

use super::*;

impl Win16State {
    pub(super) fn begin_menu_creation(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16UserMenuRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16UserMenuRequest as Request;

        match request {
            request @ (Request::CreateMenu | Request::CreatePopupMenu) => {
                if !self.guest_menus.has_free_handle() {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                }
                let popup = matches!(request, Request::CreatePopupMenu);
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::Create { popup },
                    MenuCallKind::Handle,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::LoadMenu { instance, name } => {
                if !self.guest_menus.has_free_handle() {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                }
                let Some(template) = self.resource_menu_template(instance, name, host)? else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::CreateFromTemplate { template },
                    MenuCallKind::Handle,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::LoadMenuIndirect { template: far } => {
                if !self.guest_menus.has_free_handle() || far == 0 {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                }
                let pointer = self
                    .selectors
                    .pointer_from_far(far)
                    .map_err(crate::runtime_error)?;
                let Some(bytes) = self.read_menu_template(memory, pointer)? else {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "LoadMenuIndirect received an unsupported or malformed Win16 menu template",
                    ));
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let parsed = match formats::parse_win16_menu(&bytes) {
                    Ok(menu) => menu,
                    Err(formats::FormatError::AllocationFailed) => {
                        return Err(RuntimeError::new(
                            Kind::ResourceExhausted,
                            "cannot allocate parsed Win16 menu template",
                        ));
                    }
                    Err(error) => {
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::CompatibilityGap,
                            format!("LoadMenuIndirect template rejected: {error}"),
                        ));
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    }
                };
                let Some(template) = Self::host_menu_template(&parsed, host)? else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::CreateFromTemplate { template },
                    MenuCallKind::Handle,
                    return_kind,
                    None,
                    return_to,
                )
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-menu creation request reached menu creation",
            )),
        }
    }
}
