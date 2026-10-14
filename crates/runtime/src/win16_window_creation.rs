//! Win16 CreateWindow request routing and completion observation metadata.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn allocate_window_creation_identity(
        &mut self,
    ) -> Result<Win16CreationId, RuntimeError> {
        let creation = Win16CreationId(self.next_window_creation);
        self.next_window_creation = self.next_window_creation.checked_add(1).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "Win16 window creation identities exhausted")
        })?;
        Ok(creation)
    }

    pub(in crate::win16_runtime) fn begin_create_window(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: WindowCreateRequest,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(class) = self.resolve_window_class_for_create(
            request.instance, &request.class_name, host,
        )?
        else {
            return self.complete_create_window_failure(
                registers,
                host,
                return_to,
                request.instance,
                request.class_name.clone(),
                Win16WindowCreationRejection::GuestClassUnavailable,
            );
        };
        let parent = if request.parent == 0 {
            None
        } else {
            let Some(&native) = self.window_handles.get(&request.parent) else {
                return self.complete_create_window_failure(
                    registers,
                    host,
                    return_to,
                    request.instance,
                    request.class_name.clone(),
                    Win16WindowCreationRejection::GuestParentUnavailable,
                );
            };
            Some(native)
        };
        let child = request.style & WS_CHILD != 0;
        let menu = if child || request.menu == 0 {
            None
        } else if let Some(menu) = self.guest_menus.resolve(request.menu) {
            Some(menu)
        } else {
            return self.complete_create_window_failure(
                registers,
                host,
                return_to,
                request.instance,
                request.class_name.clone(),
                Win16WindowCreationRejection::GuestMenuUnavailable,
            );
        };
        let class_menu_template = if !child && menu.is_none() && class.has_menu_resource {
            let resource = self
                .window_classes
                .menu_resource_for_host_class(class.host_class)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "resolved Win16 class lost its exact menu resource identity",
                    )
                })?;
            match self.resource_menu_template(class.instance, resource, host)? {
                Some(template) => Some(template),
                None => {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "Win16 class RT_MENU could not be materialized; CreateWindow was not invoked",
                    ));
                    return self.complete_create_window_failure(
                        registers,
                        host,
                        return_to,
                        request.instance,
                        request.class_name.clone(),
                        Win16WindowCreationRejection::UnsupportedClassMenuResource,
                    );
                }
            }
        } else {
            None
        };
        // Check callback code and its stack before entering native creation.
        if class.wnd_proc != 0 {
            self.check_window_callback(registers, class.wnd_proc, memory)?;
        }
        let creation = self.allocate_window_creation_identity()?;
        let mdi_client = match self.prepare_mdi_client_creation(&class, request.parameter, memory)? {
            super::super::mdi_client_creation::MdiClientCreatePreparation::NotMdiClient => None,
            super::super::mdi_client_creation::MdiClientCreatePreparation::Prepared(data) => Some(data),
            super::super::mdi_client_creation::MdiClientCreatePreparation::Rejected => {
                return self.complete_create_window_failure(registers, host, return_to,
                    request.instance, request.class_name.clone(),
                    Win16WindowCreationRejection::InvalidGuestCreationData);
            }
        };
        let operation = Win16WindowOperation::Create {
            creation,
            data: Win16HostCreationData {
                class: class.host_class,
                guest_instance: request.instance,
                guest_class_name: match &request.class_name {
                    Win16ClassName::Name(name) => crate::Win16HostClassName::Name(name.clone()),
                    Win16ClassName::Atom(atom) => crate::Win16HostClassName::Atom(*atom),
                },
                guest_menu: request.menu,
                class_menu_template,
                create_parameter: request.parameter,
                creation_data: None,
                mdi_client,
                dialog_root: false,
                menu,
                title: request.window_name.clone(),
                style: request.style,
                ex_style: request.ex_style,
                x: request.x,
                y: request.y,
                width: request.width,
                height: request.height,
                parent,
                child_id: child.then_some(request.menu),
            },
        };
        let procedure = WindowProcedure {
            class: class.host_class,
            address: class.wnd_proc,
            // WNDPROC's instance and GWW_HINSTANCE belong to the window.
            // The registering DLL still owns a global class and its menu.
            instance: request.instance,
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            operation,
            WindowReturn::Create {
                creation,
                request,
                procedure,
                window: None,
                parent_was_updated: false,
            },
            return_to,
        )
    }

    fn complete_create_window_failure(
        &mut self,
        registers: &mut Registers,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        class_instance: u16,
        window_class: Win16ClassName,
        rejection: Win16WindowCreationRejection,
    ) -> Result<Option<u8>, RuntimeError> {
        let completed = self.complete_return(
            registers,
            return_to.0,
            return_to.1,
            return_to.2,
            0,
            Win16ReturnKind::Word,
        )?;
        if host.win16_service_trace_enabled() {
            host.observe_win16_io(&crate::Win16IoEvent::WindowCreation {
                api: Win16WindowCreationApi::CreateWindow,
                phase: Win16WindowCreationPhase::GuestApiCompleted,
                native_return: Win16NativeWindowApiReturn::NotInvoked,
                preflight_rejection: Some(rejection),
                class_instance: Some(class_instance),
                window_class: Some(&window_class),
                live_window: None,
                guest_window: 0,
                dialog_ncdestroy_observed: None,
                dialog_template: None,
            });
        }
        Ok(completed)
    }
}
