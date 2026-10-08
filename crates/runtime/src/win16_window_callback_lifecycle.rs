//! Associate native callback targets with exact guest window procedures.

use super::*;

impl Win16State {
    pub(super) fn callback_window(
        &mut self,
        native: Win16HostWindow,
        class: Win16HostClass,
        creation: Option<Win16CreationId>,
        creation_data: Option<&Win16HostCreationData>,
        mdi_child_creation: Option<&crate::Win16HostMdiChildCreation>,
    ) -> Result<(u16, WindowProcedure), RuntimeError> {
        if let Some(data) = mdi_child_creation {
            let (expected, mdi_client_guest, extra_bytes, creation_id) = {
                let plan = self.mdi_creation_plan_for_callback(creation, data)?;
                if class != plan.mdi.class {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native MDI child callback class differs from its exact WM_MDICREATE plan"));
                }
                (
                    WindowProcedure {
                        class: plan.mdi.class,
                        address: plan.child_procedure,
                        instance: plan.child_instance,
                    },
                    plan.mdi_client_guest,
                    self.window_classes.window_extra_bytes(plan.mdi.class),
                    plan.creation,
                )
            };
            let mut existing_guest = None;
            for (&guest, &mapped_native) in &self.window_handles {
                if mapped_native != native {
                    continue;
                }
                if existing_guest.replace(guest).is_some() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native MDI child callback has multiple live Win16 HWND aliases"));
                }
            }
            if let Some(window) = existing_guest {
                let Some(procedure) = self.window_procedures.get(&window).copied() else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "mapped MDI child callback has no exact guest WndProc"));
                };
                if procedure.class != expected.class
                    || procedure.address != expected.address
                    || procedure.instance != expected.instance
                    || !self.mdi_children.contains(&window)
                    || self.window_creations.get(&window) != Some(&creation_id)
                    || self.window_system_classes.contains_key(&window)
                    || self.window_parents.get(&window) != Some(&mdi_client_guest)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "mapped MDI child callback no longer matches its exact creation claim"));
                }
                return Ok((window, procedure));
            }

            let window = self.allocate_window_handle(native).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 window handle table is full while claiming MDI child callback",
            ))?;
            self.window_procedures.insert(window, expected);
            let initialized = self.initialize_window_data(
                window,
                Some(class),
                expected.instance,
                false,
                extra_bytes,
            ).and_then(|()| self.link_window_parent(window, mdi_client_guest));
            if let Err(error) = initialized {
                return match self.retire_window_handle(window) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "MDI child callback registration failed and guest HWND cleanup also failed",
                        cleanup_error,
                    )),
                };
            }
            if let Err(error) = self.associate_window_creation(window, native, creation_id) {
                let cleanup = self.retire_window_handle(window);
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "MDI child creation registration failed and guest HWND cleanup also failed",
                        cleanup_error,
                    )),
                };
            }
            self.mdi_children.insert(window);
            return Ok((window, expected));
        }

        if let Some((&window, _)) = self.window_handles.iter().find(|(_, token)| **token == native) {
            let procedure = self.window_procedures.get(&window).copied().ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "Win16 window procedure mapping is missing"))?;
            if procedure.class != class {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native callback class does not match its guest window"));
            }
            // Callback creation ids route work to their pending API operation;
            // they are not per-HWND lifetime identities. Only associate an
            // id for an actual root creation, never for a dialog template
            // control or another alias of that native window.
            let is_active_window_creation_root = creation.is_some_and(|creation| {
                self.window_operations.iter().any(|frame| {
                    matches!(
                        frame.continuation(),
                        Some(WindowReturn::Create {
                            creation: pending,
                            ..
                        }) if *pending == creation
                    )
                })
            });
            let is_active_dialog_creation_root = creation_data
                .is_some_and(|data| data.dialog_root)
                && creation.is_some_and(|creation| {
                    self.window_operations.iter().any(|frame| {
                        let Some(WindowReturn::UserFamily(continuation)) = frame.continuation()
                        else {
                            return false;
                        };
                        continuation.pending_dialog_creation() == Some(creation)
                    })
                });
            if (is_active_window_creation_root || is_active_dialog_creation_root)
                && let Some(creation) = creation
            {
                self.associate_window_creation(window, native, creation)?;
            }
            return Ok((window, procedure));
        }

        if let Some(data) = creation_data {
            let index = self.window_operations.iter().rposition(|frame| {
                let Some(WindowReturn::UserFamily(continuation)) = frame.continuation()
                    else { return false; };
                creation.is_some_and(|creation| {
                    continuation.pending_dialog_creation() == Some(creation)
                        && continuation.validate_pending_dialog_class(creation, data)
                })
            });
            if let Some(index) = index {
                let resolved = self.window_classes.resolve_registered_host_class(class)
                    .filter(|resolved| {
                        resolved.instance == data.guest_instance
                            && resolved.wnd_proc != 0
                            && (!data.dialog_root || resolved.window_extra_bytes >= 30)
                    })
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "dialog creation route does not resolve to its exact guest class"))?;
                let procedure = WindowProcedure {
                    class,
                    address: resolved.wnd_proc,
                    instance: resolved.instance,
                };
                let window_creation = if data.dialog_root {
                    Some(creation.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "dialog root callback has no exact creation generation",
                    ))?)
                } else {
                    None
                };
                if data.dialog_root {
                    let Some(WindowReturn::UserFamily(continuation)) =
                        self.window_operations[index].continuation_mut() else {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "dialog root continuation changed while binding its HWND"));
                        };
                    // Bind the native root before allocating a guest alias so
                    // a conflicting callback cannot leave a stray HWND entry.
                    if !continuation.bind_pending_dialog_window(native) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "custom dialog root HWND conflicts with its active creation"));
                    }
                }
                let window = self.allocate_window_handle(native).ok_or_else(|| RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 window handle table is full",
                ))?;
                self.window_procedures.insert(window, procedure);
                self.initialize_window_data(
                    window,
                    Some(class),
                    data.guest_instance,
                    data.dialog_root,
                    Some(resolved.window_extra_bytes),
                )?;
                if let Some(creation) = window_creation {
                    if let Err(error) = self.associate_window_creation(window, native, creation) {
                        let cleanup = self.retire_window_handle(window);
                        return match cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup_error) => Err(RuntimeError::with_source(
                                Kind::InternalInvariant,
                                "dialog root creation registration failed and guest HWND cleanup also failed",
                                cleanup_error,
                            )),
                        };
                    }
                }
                return Ok((window, procedure));
            }
        }

        let index = self.window_operations.iter().rposition(|frame| {
            matches!(
                frame.continuation(),
                Some(WindowReturn::Create {
                    creation: pending,
                    procedure,
                    window: None,
                    ..
                }) if Some(*pending) == creation && procedure.class == class
            )
        }).ok_or_else(|| {
            let dialog_routes = self.window_operations.iter().filter(|frame| {
                matches!(frame.continuation(), Some(WindowReturn::UserFamily(continuation))
                    if continuation.pending_dialog_creation() == creation && creation.is_some())
            }).count();
            RuntimeError::new(Kind::InternalInvariant, format!(
                "native callback has no guest window or active creation: window {}, class {}, creation {}, matching dialog operations {}, creation data present {}",
                native.0, class.0, creation.map_or(0, |id| id.0), dialog_routes,
                creation_data.is_some(),
            ))
        })?;
        let (procedure, creation) = match self.window_operations[index].continuation() {
            Some(WindowReturn::Create { procedure, creation, .. }) => (*procedure, *creation),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 pending creation changed while assigning its window")),
        };
        let window = self.allocate_window_handle(native).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 window handle table is full",
        ))?;
        self.window_procedures.insert(window, procedure);
        self.initialize_window_data(
            window,
            Some(class),
            procedure.instance,
            false,
            self.window_classes.window_extra_bytes(class),
        )?;
        if let Err(error) = self.associate_window_creation(window, native, creation) {
            let cleanup = self.retire_window_handle(window);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "window creation registration failed and guest HWND cleanup also failed",
                    cleanup_error,
                )),
            };
        }
        if let Some(WindowReturn::Create { window: slot, .. }) =
            self.window_operations[index].continuation_mut()
        {
            *slot = Some(window);
        }
        Ok((window, procedure))
    }
}
