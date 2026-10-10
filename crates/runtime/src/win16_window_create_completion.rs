//! Retained CreateWindow projection stages for one exact operation frame.

use super::*;

impl Win16State {
    pub(super) fn project_query_procedure_completion(
        &mut self,
        frame_id: u64,
        memory: &mut Memory,
    ) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        loop {
            let (phase, value, window, native_window, procedure) = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .and_then(|frame| {
                    let completion = frame.completion.as_ref()?;
                    let WindowReturn::QueryProcedure { window, native_window } =
                        &completion.continuation else { return None; };
                    let Win16WindowResult::Procedure(procedure) = &completion.result else {
                        return None;
                    };
                    let WindowProjectionJournal::Api(
                        WindowApiProjectionJournal::QueryProcedure(owner),
                    ) = &completion.journal.projection else { return None; };
                    Some((owner.phase, owner.value, *window, *native_window, *procedure))
                })
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "QueryWindowProcedure projection lost its exact result and phase owner"))?;

            use super::operation_frame::ProcedureProjectionPhase as Phase;
            match phase {
                Phase::Ready => {
                    let value = if self.window_handles.get(&window) == Some(&native_window) {
                        match procedure {
                            Some(procedure) => self.native_procedure_gate(procedure, memory)?,
                            None => 0,
                        }
                    } else {
                        0
                    };
                    let frame = self.window_operations.last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "QueryWindowProcedure frame changed before result caching"))?;
                    let completion = frame.completion.as_mut().ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "QueryWindowProcedure result disappeared before result caching"))?;
                    let WindowProjectionJournal::Api(
                        WindowApiProjectionJournal::QueryProcedure(owner),
                    ) = &mut completion.journal.projection else {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "QueryWindowProcedure phase owner changed before result caching"));
                    };
                    owner.value = Some(value);
                    owner.phase = Phase::ProcedureGateInstalled;
                }
                Phase::ProcedureGateInstalled => {
                    let frame = self.window_operations.last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "QueryWindowProcedure frame changed before return phase"))?;
                    let completion = frame.completion.as_mut().ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "QueryWindowProcedure result disappeared before return phase"))?;
                    let WindowProjectionJournal::Api(
                        WindowApiProjectionJournal::QueryProcedure(owner),
                    ) = &mut completion.journal.projection else {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "QueryWindowProcedure phase owner changed before return phase"));
                    };
                    owner.phase = Phase::ReturnReady;
                }
                Phase::ReturnReady => {
                    let value = value.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "QueryWindowProcedure return phase lost its cached gate address"))?;
                    return Ok((value, Win16ReturnKind::Dword));
                }
            }
        }
    }

    // Runtime-only projection entrypoint also used to verify nested creation
    // reconciliation without fabricating a native source-retirement proof.
    pub(in crate::win16_runtime) fn project_create_window_completion(
        &mut self,
        frame_id: u64,
    ) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        loop {
            let snapshot = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .and_then(|frame| {
                    let completion = frame.completion.as_ref()?;
                    let WindowReturn::Create {
                        creation, request, procedure, window, parent_was_updated,
                    } = &completion.continuation else { return None; };
                    let Win16WindowResult::Created(native) = &completion.result else {
                        return None;
                    };
                    let WindowProjectionJournal::Api(
                        WindowApiProjectionJournal::Create(owner),
                    ) = &completion.journal.projection else { return None; };
                    Some((
                        owner.phase,
                        *creation,
                        owner.guest_window,
                        owner.callback_mapped,
                        request.clone(),
                        *procedure,
                        *window,
                        *parent_was_updated,
                        *native,
                    ))
                })
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "CreateWindow projection lost its exact result and phase owner"))?;

            let (phase, creation, guest_window, callback_mapped, request, procedure,
                window, mut parent_was_updated, native_result) = snapshot;
            use super::operation_frame::CreateWindowProjectionPhase as Phase;

            match phase {
                Phase::Ready => {
                    let guest = match native_result.live_window {
                        Some(native) => {
                            if let Some(window) = window {
                                if self.window_handles.get(&window) != Some(&native) {
                                    return Err(RuntimeError::new(Kind::InternalInvariant,
                                        "native created window differs from its retained callback HWND"));
                                }
                                window
                            } else {
                                // A parent callback can obtain this system control
                                // through GetDlgItem before CreateWindow returns.
                                // Reuse that exact mapping and promote ownership;
                                // allocating again would give one HWND two aliases.
                                let window = self.map_window_handle(native, true)?;
                                let frame = self.window_operations.last_mut()
                                    .filter(|frame| frame.id == frame_id)
                                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                                        "CreateWindow frame changed after guest HWND allocation"))?;
                                let completion = frame.completion.as_mut().ok_or_else(||
                                    RuntimeError::new(Kind::InternalInvariant,
                                        "CreateWindow result disappeared after guest HWND allocation"))?;
                                let WindowReturn::Create { window: slot, .. } =
                                    &mut completion.continuation else {
                                        return Err(RuntimeError::new(Kind::InternalInvariant,
                                            "CreateWindow continuation changed after guest HWND allocation"));
                                    };
                                *slot = Some(window);
                                window
                            }
                        }
                        None => {
                            if let Some(window) = window {
                                // The exact tree edge and owner records remain
                                // retryable if common-dialog or timer cleanup
                                // fails partway through retirement.
                                self.retire_window_tree(window)?;
                            }
                            0
                        }
                    };
                    if guest != 0
                        && let Some(native) = native_result.live_window
                    {
                        self.associate_window_creation(guest, native, creation)?;
                    }
                    let frame = self.window_operations.last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow frame changed before handle phase commit"))?;
                    let completion = frame.completion.as_mut().ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow result disappeared before handle phase commit"))?;
                    let WindowProjectionJournal::Api(WindowApiProjectionJournal::Create(owner)) =
                        &mut completion.journal.projection else {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "CreateWindow phase owner changed after handle mapping"));
                        };
                    owner.guest_window = Some(guest);
                    owner.phase = if guest == 0 { Phase::WindowDataInitialized }
                        else { Phase::HandleMapped };
                }
                Phase::HandleMapped => {
                    let guest = guest_window.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "CreateWindow handle phase lost its exact guest HWND"))?;
                    let native = native_result.live_window.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "CreateWindow mapped-handle phase has no native window"))?;
                    if self.window_handles.get(&guest) != Some(&native) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow guest HWND no longer names its captured native window"));
                    }
                    if !callback_mapped && procedure.address != 0 {
                        self.window_procedures.entry(guest).or_insert(procedure);
                    }
                    let extra_bytes = self.window_classes.window_extra_bytes(procedure.class);
                    if guest != 0 {
                        self.window_system_classes.remove(&guest);
                        if let Some(kind) = self.window_classes
                            .system_kind_for_host_class(procedure.class)
                        {
                            self.window_system_classes.insert(guest, kind);
                        }
                    }
                    self.initialize_window_data(
                        guest, Some(procedure.class), procedure.instance, false, extra_bytes,
                    )?;
                    let frame = self.window_operations.last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow frame changed before window-data phase commit"))?;
                    let completion = frame.completion.as_mut().ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow result disappeared before window-data phase commit"))?;
                    let WindowProjectionJournal::Api(WindowApiProjectionJournal::Create(owner)) =
                        &mut completion.journal.projection else {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "CreateWindow phase owner changed before window-data phase commit"));
                        };
                    owner.phase = Phase::WindowDataInitialized;
                }
                Phase::WindowDataInitialized => {
                    let guest = guest_window.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "CreateWindow window-data phase lost its cached HWND"))?;
                    if guest != 0
                        && let Some(native) = native_result.live_window
                        && let Some(observed_parent) =
                            self.window_parent_observations.get(&native).copied()
                    {
                        match observed_parent {
                            Some(native_parent) => {
                                let parent = self.map_window_handle(native_parent, false)?;
                                self.set_window_parent_from_host(guest, parent)?;
                            }
                            None => self.set_window_parent_from_host(guest, 0)?,
                        }
                        self.window_parent_observations.remove(&native);
                        parent_was_updated = true;
                        if let Some(frame) = self.window_operations.last_mut()
                            .filter(|frame| frame.id == frame_id)
                            && let Some(completion) = frame.completion.as_mut()
                            && let WindowReturn::Create {
                                parent_was_updated: updated, ..
                            } = &mut completion.continuation
                        {
                            *updated = true;
                        }
                    }
                    if guest != 0 && !parent_was_updated
                        && !self.window_parents.contains_key(&guest)
                        && request.style & WS_CHILD != 0
                        && request.parent != 0
                    {
                        self.link_window_parent(guest, request.parent)?;
                        if let Some(frame) = self.window_operations.last_mut()
                            .filter(|frame| frame.id == frame_id)
                        {
                            if let Some(completion) = frame.completion.as_mut()
                                && let WindowReturn::Create { parent_was_updated, .. } =
                                    &mut completion.continuation
                            {
                                *parent_was_updated = true;
                            }
                        }
                    }
                    let frame = self.window_operations.last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow frame changed before parent phase commit"))?;
                    let completion = frame.completion.as_mut().ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow result disappeared before parent phase commit"))?;
                    let WindowProjectionJournal::Api(WindowApiProjectionJournal::Create(owner)) =
                        &mut completion.journal.projection else {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "CreateWindow phase owner changed before parent phase commit"));
                        };
                    owner.phase = Phase::ParentLinked;
                }
                Phase::ParentLinked => {
                    let guest = guest_window.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "CreateWindow parent phase lost its cached guest HWND"))?;
                    let observation = super::super::user_services_controls::Win16WindowCreationObservation {
                        api: crate::Win16WindowCreationApi::CreateWindow,
                        native_api_return: native_result.native_api_return,
                        preflight_rejection: native_result.preflight_rejection,
                        class_instance: Some(request.instance),
                        window_class: Some(request.class_name),
                        live_window: native_result.live_window,
                        guest_window: guest,
                        dialog_ncdestroy_observed: None,
                        dialog_template: None,
                    };
                    let frame = self.window_operations.last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow frame changed before return-value phase commit"))?;
                    let completion = frame.completion.as_mut().ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "CreateWindow result disappeared before return-value phase commit"))?;
                    completion.journal.creation_observation = Some(observation);
                    let WindowProjectionJournal::Api(WindowApiProjectionJournal::Create(owner)) =
                        &mut completion.journal.projection else {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "CreateWindow phase owner changed before return-value phase commit"));
                        };
                    owner.phase = Phase::ReturnReady;
                }
                Phase::ReturnReady => {
                    let guest = guest_window.ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "CreateWindow return phase lost its cached guest HWND"))?;
                    return Ok((u32::from(guest), Win16ReturnKind::Word));
                }
            }
        }
    }
}
