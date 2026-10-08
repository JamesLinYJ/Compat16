//! Loader and retirement producers for ToolHelp module notifications.

use guest_core::Selector;

use super::{
    NE_LIBRARY, NE_SEGMENT_DATA, Win16ToolhelpNotifyData, Win16ToolhelpNotifyEvent,
    NFY_DELMODULE, NFY_FREESEG, NFY_LOADSEG, NFY_STARTDLL,
    Win16ToolhelpModuleEntryScope,
};
use super::super::module_registry::ModuleState;
use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(in crate::win16_runtime) fn toolhelp_notify_module_entry_scope(
        &self,
        module_handle: u16,
    ) -> Result<Option<Win16ToolhelpModuleEntryScope>, RuntimeError> {
        let Some(record) = self.modules.records.get(&module_handle) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-entry scope lost its exact module record"));
        };
        if !record.definition.as_ref().is_some_and(|definition|
            definition.header.flags & super::NE_LIBRARY != 0)
        {
            return Ok(None);
        }
        // Only a real LibMain entry has the exact synchronous boundary that
        // the scoped consumer can drain. DLLs without an entry keep LOADSEG
        // notifications on the ordinary FIFO instead of orphaning them in a
        // scope that will never be observed.
        let Some(entry) = record.loaded.as_ref().and_then(|loaded| loaded.code_entry) else {
            return Ok(None);
        };
        let task = self.current_task_handle()?;
        let module_generation = self.selectors.reference(Selector(module_handle))
            .map_err(crate::runtime_error)?;
        let entry_selector_generation = self.selectors.reference(entry.selector)
            .map_err(crate::runtime_error)?;
        let parent_notification_callback = self.toolhelp_notify_frames.last()
            .map(|frame| frame.callback_id.0);
        Ok(Some(Win16ToolhelpModuleEntryScope {
            task,
            module_handle,
            module_generation,
            entry_selector_generation,
            parent_notification_callback,
        }))
    }

    pub(in crate::win16_runtime) fn toolhelp_notify_module_entry_has_pending(
        &self,
        code_segment: u16,
        instruction_pointer: u16,
    ) -> Result<bool, RuntimeError> {
        let Some(scope) = self.toolhelp_notify_module_entry_scope_at(
            code_segment, instruction_pointer,
        )? else {
            return Ok(false);
        };
        self.toolhelp_notify.has_module_entry_event(scope)
    }

    /// Publish fully assigned and relocated segments. The loader invokes this
    /// before the module initialization continuation starts guest code.
    pub(in crate::win16_runtime) fn queue_toolhelp_module_segments_loaded(
        &mut self,
        module_handle: u16,
    ) -> Result<(), RuntimeError> {
        let task = self.current_task_handle()?;
        if !self.toolhelp_notify.has_matching_registration(NFY_LOADSEG) {
            return Ok(());
        }
        let record = self.modules.records.get(&module_handle).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "loaded Win16 module disappeared before ToolHelp notification")
        })?;
        if record.external_application.is_some() { return Ok(()); }
        let module_generation = self.selectors.reference(Selector(module_handle))
            .map_err(crate::runtime_error)?;
        let module_entry_scope = self.toolhelp_notify_module_entry_scope(module_handle)?;
        let (Some(definition), Some(loaded)) = (&record.definition, &record.loaded) else {
            return Ok(());
        };
        let mut events = Vec::new();
        events.try_reserve_exact(loaded.segments.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 ToolHelp loaded-segment events", error)
        })?;
        for segment in &loaded.segments {
            let metadata = definition.segments.iter().find(|entry|
                entry.number == segment.number).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "loaded Win16 segment has no NE definition for ToolHelp notification",
                ))?;
            let mut module_name = Vec::new();
            module_name.try_reserve_exact(record.name.len()).map_err(|error| {
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "copy Win16 ToolHelp segment module name", error)
            })?;
            module_name.extend_from_slice(&record.name);
            let selector_generation = self.selectors.reference(segment.selector)
                .map_err(crate::runtime_error)?;
            events.push(Win16ToolhelpNotifyEvent {
                task,
                notification: NFY_LOADSEG,
                data: Win16ToolhelpNotifyData::LoadSegment {
                    module_handle,
                    module_generation,
                    selector_generation,
                    selector: segment.selector.0,
                    segment_number: segment.number,
                    segment_type: u16::from(metadata.flags & NE_SEGMENT_DATA != 0),
                    // Current discovery rejects multiple data instances.
                    instance_count: u16::from(metadata.flags & NE_SEGMENT_DATA != 0),
                    module_name,
                },
                registrations: Vec::new(),
                termination_id: None,
                module_root: None,
            });
        }
        if let Some(scope) = module_entry_scope {
            self.toolhelp_notify.enqueue_module_entry_batch(scope, events)?;
        } else {
            self.toolhelp_notify.enqueue_batch(events)?;
        }
        Ok(())
    }

    /// Snapshot FREESEG while each selector generation is still live. The
    /// queue's module roots keep those selector identities valid until the
    /// registered callback chain has returned or been explicitly discarded.
    pub(in crate::win16_runtime) fn queue_toolhelp_module_segments_freed(
        &mut self,
        module_handle: u16,
    ) -> Result<(), RuntimeError> {
        let task = self.current_task_handle()?;
        let record = self.modules.records.get(&module_handle).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "retiring Win16 module disappeared before FREESEG publication")
        })?;
        if record.external_application.is_some() { return Ok(()); }
        if record.state != ModuleState::Retired {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "FREESEG was prepared before its module entered retirement"));
        }
        let (Some(_definition), Some(loaded)) = (&record.definition, &record.loaded) else {
            return Ok(());
        };
        if !self.toolhelp_notify.has_matching_registration(NFY_FREESEG) {
            // This retirement point has no subscribed receiver. Remember it
            // once so a later UnlockSegment retry does not try to publish
            // already released selectors to a registration added afterward.
            for segment in &loaded.segments {
                self.toolhelp_notify.announce_module_segment(
                    module_handle, segment.selector.0,
                );
            }
            return Ok(());
        }

        let mut selectors = Vec::new();
        selectors.try_reserve_exact(loaded.segments.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 ToolHelp FREESEG selector snapshot", error))?;
        for segment in loaded.segments.iter().rev() {
            let selector = segment.selector.0;
            if self.toolhelp_notify.module_segment_was_announced(module_handle, selector) {
                continue;
            }
            selectors.push((selector,
                self.selectors.reference(segment.selector).map_err(crate::runtime_error)?,
            ));
        }
        if selectors.is_empty() { return Ok(()); }

        let mut events = Vec::new();
        events.try_reserve_exact(selectors.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 ToolHelp FREESEG events", error))?;
        for &(selector, selector_generation) in &selectors {
            events.push(Win16ToolhelpNotifyEvent {
                task,
                notification: NFY_FREESEG,
                data: Win16ToolhelpNotifyData::FreeSegment {
                    module_handle,
                    selector_generation,
                    selector,
                },
                registrations: Vec::new(),
                termination_id: None,
                module_root: Some(module_handle),
            });
        }
        self.retain_toolhelp_notify_module_roots(module_handle, events.len())?;
        let queued = match self.toolhelp_notify.enqueue_batch(events) {
            Ok(queued) => queued,
            Err(primary) => {
                return Err(self.release_toolhelp_notify_module_roots_with_primary(
                    module_handle, selectors.len(), primary,
                ));
            }
        };
        if queued == 0 {
            self.release_toolhelp_notify_module_roots(module_handle, selectors.len())?;
            return Ok(());
        }
        if queued != selectors.len() {
            // Every event in this batch has one task and one notification, so
            // a partial recipient snapshot would violate registry semantics.
            // Preserve the accepted exact owners and let their callbacks run.
            for &(selector, _) in selectors.iter().take(queued) {
                self.toolhelp_notify.announce_module_segment(module_handle, selector);
            }
            self.release_toolhelp_notify_module_roots(
                module_handle, selectors.len() - queued,
            )?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp FREESEG batch accepted only part of one task snapshot"));
        }
        for &(selector, _) in &selectors {
            self.toolhelp_notify.announce_module_segment(module_handle, selector);
        }
        Ok(())
    }

    /// DELMODULE is a scalar selector notification sent only after all NE
    /// segment allocations have been released, while the private header
    /// selector still names the exact module generation.
    pub(in crate::win16_runtime) fn queue_toolhelp_module_deleted(
        &mut self,
        module_handle: u16,
    ) -> Result<(), RuntimeError> {
        if self.toolhelp_notify.module_delete_was_announced(module_handle) {
            return Ok(());
        }
        let task = self.current_task_handle()?;
        let record = self.modules.records.get(&module_handle).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "retiring Win16 module disappeared before DELMODULE publication")
        })?;
        if record.external_application.is_some() || record.definition.is_none() {
            return Ok(());
        }
        if record.state != ModuleState::Retired || record.allocations.len() > 1 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DELMODULE was prepared before all module segments were retired"));
        }
        let selector_generation = self.selectors.reference(Selector(module_handle))
            .map_err(crate::runtime_error)?;
        if !self.toolhelp_notify.has_matching_registration(NFY_DELMODULE) {
            self.toolhelp_notify.announce_module_delete(module_handle);
            return Ok(());
        }

        let event = Win16ToolhelpNotifyEvent {
            task,
            notification: NFY_DELMODULE,
            data: Win16ToolhelpNotifyData::DeleteModule {
                module_handle,
                selector_generation,
            },
            registrations: Vec::new(),
            termination_id: None,
            module_root: Some(module_handle),
        };
        self.retain_toolhelp_notify_module_roots(module_handle, 1)?;
        let queued = match self.toolhelp_notify.enqueue(event) {
            Ok(queued) => queued,
            Err(primary) => {
                return Err(self.release_toolhelp_notify_module_roots_with_primary(
                    module_handle, 1, primary,
                ));
            }
        };
        if queued {
            self.toolhelp_notify.announce_module_delete(module_handle);
        } else {
            self.release_toolhelp_notify_module_roots(module_handle, 1)?;
            self.toolhelp_notify.announce_module_delete(module_handle);
        }
        Ok(())
    }

    pub(super) fn toolhelp_notify_event_owner_is_live(
        &self,
        event: &super::Win16ToolhelpNotifyEvent,
    ) -> bool {
        match &event.data {
            Win16ToolhelpNotifyData::LoadSegment {
                module_handle, module_generation, selector_generation, selector, segment_number, ..
            } => {
                let Some(record) = self.modules.records.get(module_handle) else { return false; };
                if !matches!(record.state, ModuleState::Ready | ModuleState::Initializing)
                    || record.external_application.is_some()
                    || self.selectors.reference(Selector(*module_handle)).ok()
                        != Some(*module_generation)
                {
                    return false;
                }
                let Some(loaded) = record.loaded.as_ref() else { return false; };
                self.selectors.reference(Selector(*selector)).ok() == Some(*selector_generation)
                    && loaded.segments.iter().any(|segment|
                        segment.number == *segment_number
                            && segment.selector.0 == *selector
                            && self.selectors.reference(segment.selector).ok()
                                == Some(*selector_generation))
            }
            Win16ToolhelpNotifyData::StartDll {
                module, module_generation, code_segment, instruction_pointer,
            } => self.modules.records.get(module).is_some_and(|record|
                record.state == ModuleState::Initializing
                    && record.external_application.is_none()
                    && record.definition.as_ref().is_some_and(|definition|
                        definition.header.flags & NE_LIBRARY != 0)
                    && self.selectors.reference(Selector(*module)).ok()
                        == Some(*module_generation))
                && self.toolhelp_notify_module_entry_matches(
                    *module, *code_segment, *instruction_pointer,
                ),
            Win16ToolhelpNotifyData::FreeSegment {
                module_handle, selector_generation, selector,
            } => {
                let Some(record) = self.modules.records.get(module_handle) else { return false; };
                if record.state != ModuleState::Retired
                    || record.external_application.is_some()
                {
                    return false;
                }
                let Some(loaded) = record.loaded.as_ref() else { return false; };
                self.selectors.reference(Selector(*selector)).ok() == Some(*selector_generation)
                    && loaded.segments.iter().any(|segment|
                        segment.selector.0 == *selector
                            && self.selectors.reference(segment.selector).ok()
                                == Some(*selector_generation))
            }
            Win16ToolhelpNotifyData::DeleteModule {
                module_handle, selector_generation,
            } => self.modules.records.get(module_handle).is_some_and(|record|
                record.state == ModuleState::Retired
                    && record.external_application.is_none()
                    && record.allocations.len() == 1
                    && record.definition.is_some()
                    && self.selectors.reference(Selector(*module_handle)).ok()
                        == Some(*selector_generation)),
            Win16ToolhelpNotifyData::Scalar(_) | Win16ToolhelpNotifyData::Rip { .. } => true,
        }
    }

    /// Recheck a loader notification after its ToolHelp child callback has
    /// been pushed above the exact Module callback. STARTDLL's ordinary
    /// liveness path also checks that Module is the central top, which is
    /// appropriate before publication but false in this published state.
    pub(super) fn toolhelp_notify_event_owner_is_live_under_module_entry_parent(
        &self,
        event: &super::Win16ToolhelpNotifyEvent,
        parent: super::Win16ToolhelpModuleEntryParent,
    ) -> bool {
        let scope = parent.scope;
        if event.task != scope.task
            || event.termination_id.is_some()
            || event.module_root.is_some()
        {
            return false;
        }
        match &event.data {
            Win16ToolhelpNotifyData::LoadSegment {
                module_handle, module_generation, ..
            } => {
                event.notification == NFY_LOADSEG
                    && *module_handle == scope.module_handle
                    && *module_generation == scope.module_generation
                    && self.toolhelp_notify_event_owner_is_live(event)
            }
            Win16ToolhelpNotifyData::StartDll {
                module, module_generation, code_segment, instruction_pointer,
            } => {
                if event.notification != NFY_STARTDLL
                    || *module != scope.module_handle
                    || *module_generation != scope.module_generation
                {
                    return false;
                }
                let Some(record) = self.modules.records.get(module) else {
                    return false;
                };
                if record.state != ModuleState::Initializing
                    || record.external_application.is_some()
                    || !record.definition.as_ref().is_some_and(|definition|
                        definition.header.flags & NE_LIBRARY != 0)
                    || self.selectors.reference(Selector(*module)).ok()
                        != Some(scope.module_generation)
                {
                    return false;
                }
                let Some(entry) = record.loaded.as_ref()
                    .and_then(|loaded| loaded.code_entry)
                else {
                    return false;
                };
                entry.selector.0 == *code_segment
                    && entry.offset == *instruction_pointer
                    && self.selectors.reference(entry.selector).ok()
                        == Some(scope.entry_selector_generation)
                    && self.selectors.reference(Selector(*code_segment)).ok()
                        == Some(scope.entry_selector_generation)
            }
            _ => false,
        }
    }

    pub(super) fn retain_toolhelp_notify_module_root(
        &mut self,
        module: u16,
    ) -> Result<(), RuntimeError> {
        let record = self.modules.records.get_mut(&module).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp notification module disappeared before callback entry",
        ))?;
        record.continuation_owner_refs = record.continuation_owner_refs.checked_add(1)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                "ToolHelp notification module-root count exhausted"))?;
        Ok(())
    }

    pub(super) fn release_toolhelp_notify_module_root(
        &mut self,
        module: u16,
    ) -> Result<(), RuntimeError> {
        let record = self.modules.records.get_mut(&module).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp notification module root lost its module record",
        ))?;
        record.continuation_owner_refs = record.continuation_owner_refs.checked_sub(1)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp notification module-root count underflowed"))?;
        self.module_reap_pending = true;
        Ok(())
    }

    pub(super) fn retain_toolhelp_notify_module_roots(
        &mut self,
        module: u16,
        count: usize,
    ) -> Result<(), RuntimeError> {
        let record = self.modules.records.get_mut(&module).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp notification module disappeared before event publication",
        ))?;
        let mut next = record.continuation_owner_refs;
        for _ in 0..count {
            next = next.checked_add(1).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted,
                "ToolHelp notification module-root count exhausted"))?;
        }
        record.continuation_owner_refs = next;
        Ok(())
    }

    pub(super) fn release_toolhelp_notify_module_roots(
        &mut self,
        module: u16,
        count: usize,
    ) -> Result<(), RuntimeError> {
        let record = self.modules.records.get_mut(&module).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp notification module root lost its module record",
        ))?;
        let mut next = record.continuation_owner_refs;
        for _ in 0..count {
            next = next.checked_sub(1).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp notification module-root count underflowed"))?;
        }
        record.continuation_owner_refs = next;
        self.module_reap_pending = true;
        Ok(())
    }

    /// Atomically retire one queued or active FREESEG/DELMODULE callback owner.
    /// The registry count and module root are prevalidated together so a stale
    /// event cannot release one half of the retirement transaction.
    pub(super) fn complete_toolhelp_module_retirement_callback(
        &mut self,
        module: u16,
    ) -> Result<(), RuntimeError> {
        let pending = self.toolhelp_notify.module_retirement_pending_count(module)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-retirement callback lost its event ledger"))?;
        let refs = self.modules.records.get(&module)
            .map(|record| record.continuation_owner_refs)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-retirement callback lost its module root"))?;
        if pending == 0 || refs == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-retirement callback has no exact event and root claims"));
        }
        self.toolhelp_notify.complete_module_retirement_notification(module)?;
        let record = self.modules.records.get_mut(&module).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp module root disappeared after retirement preflight",
        ))?;
        record.continuation_owner_refs -= 1;
        self.module_reap_pending = true;
        Ok(())
    }

    pub(super) fn discard_toolhelp_notify_event(
        &mut self,
        event: super::Win16ToolhelpNotifyEvent,
    ) -> Result<(), RuntimeError> {
        if let Some(module) = event.module_root {
            if matches!(&event.data,
                Win16ToolhelpNotifyData::FreeSegment { .. }
                    | Win16ToolhelpNotifyData::DeleteModule { .. })
            {
                self.complete_toolhelp_module_retirement_callback(module)?;
            } else {
                self.release_toolhelp_notify_module_root(module)?;
            }
        }
        if let Some(id) = event.termination_id {
            self.toolhelp_task_exit.notification_completed(id)?;
        }
        Ok(())
    }

    fn release_toolhelp_notify_module_roots_with_primary(
        &mut self,
        module: u16,
        count: usize,
        primary: RuntimeError,
    ) -> RuntimeError {
        match self.release_toolhelp_notify_module_roots(module, count) {
            Ok(()) => primary,
            Err(cleanup) => primary.with_cleanup(
                "ToolHelp module notification retained its primary failure and module-root cleanup failure",
                cleanup,
            ),
        }
    }
}
