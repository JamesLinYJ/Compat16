//! Guest procedure ownership for existing native controls, without a class.

use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ReturnKind};

use super::{Win16State, windows::{WindowClassRoot, WindowReturn}};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostWindow,
    Win16WindowOperation, Win16WindowResult};

#[derive(Clone, Copy)]
pub(super) struct NativeSubclassChange {
    pub(super) window: u16,
    pub(super) native: Win16HostWindow,
    pub(super) revision: u64,
    pub(super) previous: Option<u32>,
    pub(super) replacement: u32,
    pub(super) old_return: u32,
    pub(super) restoring: bool,
}

impl Win16State {
    pub(super) fn native_subclass_procedure(&self, window: u16) -> Option<(u32, u16)> {
        let state = self.window_data.get(&window)?;
        (self.window_handles.get(&window) == Some(&state.native_window))
            .then_some((state.native_subclass?, state.instance))
    }

    pub(super) fn begin_native_subclass_data(
        &mut self, registers: &mut Registers, memory: &mut Memory,
        host: &mut impl RuntimeHost, window: u16, replacement: Option<u32>,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let native = self.window_handles[&window];
        let current = self.native_subclass_procedure(window);
        let Some(replacement) = replacement else {
            if let Some((address, _)) = current {
                return self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, address, Win16ReturnKind::Dword);
            }
            return self.begin_window_operation(registers, memory, host,
                Win16WindowOperation::QueryProcedure { window: native },
                WindowReturn::QueryProcedure { window, native_window: native }, return_to);
        };
        // Validate guest code before publishing any native callback ingress.
        let pointer = self.selectors.pointer_from_far(replacement)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        if let Some((old, _)) = current {
            self.retain_procedure_root(window, old)?;
            if let Some(previous) = self.native_procedure_for_address(replacement) {
                let change = self.stage_native_subclass_change(
                    window, replacement, old, true,
                )?;
                return self.begin_window_operation(registers, memory, host,
                    Win16WindowOperation::SetProcedure {
                        window: native, previous, restore: true,
                    }, WindowReturn::NativeSubclass(change), return_to);
            }
            self.stage_native_subclass_change(window, replacement, old, false)?;
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, old, Win16ReturnKind::Dword);
        }

        // The creator is immutable provenance. Reparenting must not change
        // WndProc's Win16 instance, and a native HINSTANCE is never a guest word.
        let instance = self.window_data.get(&window).map(|data| data.instance);
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::QuerySubclassProcedure { window: native },
            WindowReturn::PrepareNativeSubclass {
                window, native_window: native, replacement, instance,
            }, return_to)
    }

    fn stage_native_subclass_change(
        &mut self, window: u16, replacement: u32, old_return: u32, restoring: bool,
    ) -> Result<NativeSubclassChange, RuntimeError> {
        let state = self.window_data.get_mut(&window).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "native subclass has no exact guest window data owner"))?;
        if self.window_handles.get(&window) != Some(&state.native_window) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native subclass window incarnation changed before publication"));
        }
        let revision = state.subclass_revision.checked_add(1).ok_or_else(||
            RuntimeError::new(Kind::ResourceExhausted,
                "native subclass mutation generation exhausted"))?;
        let change = NativeSubclassChange {
            window, native: state.native_window, revision,
            previous: state.native_subclass, replacement, old_return, restoring,
        };
        state.subclass_revision = revision;
        // The old guest procedure remains active during native restoration.
        // On installation, publish the new owner before native can reenter.
        if !restoring { state.native_subclass = Some(replacement); }
        Ok(change)
    }

    /// Prepare one follow-up only after the exact query source has retired.
    /// Gate allocation failure therefore cannot leave a native bridge installed
    /// while returning a null old procedure to the caller.
    pub(super) fn prepare_native_subclass_follow_up(
        &mut self, frame_id: u64, memory: &mut Memory,
    ) -> Result<Option<(Win16WindowOperation, WindowReturn)>, RuntimeError> {
        let pending = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .and_then(|frame| {
                let completion = frame.completion.as_ref()?;
                let WindowReturn::PrepareNativeSubclass {
                    window, native_window, replacement, instance,
                } = completion.continuation else { return None; };
                let Win16WindowResult::SubclassProcedure { procedure: Some(procedure), instance: captured }
                    = completion.result
                    else { return None; };
                Some((window, native_window, replacement, instance.or(captured), procedure))
            });
        let Some((window, native, replacement, instance, procedure)) = pending else { return Ok(None); };
        if self.window_handles.get(&window) != Some(&native) { return Ok(None); }
        let Some(instance) = instance else {
            self.cache_native_subclass_failure(frame_id)?;
            return Ok(None);
        };
        let old_return = self.native_procedure_gate(procedure, memory)?;
        if old_return == 0 {
            self.cache_native_subclass_failure(frame_id)?;
            return Ok(None);
        }
        // Writing back the already-current native procedure is a no-op.
        if self.native_procedure_for_address(replacement) == Some(procedure) {
            return Ok(None);
        }
        if self.native_procedure_for_address(replacement).is_some() {
            self.cache_native_subclass_failure(frame_id)?;
            return Ok(None);
        }
        // Only a successful native query proves this is a same-worker HWND.
        // Failed/foreign queries must not acquire synthetic window data.
        self.initialize_window_data(window, None, instance, false, None)?;
        let change = self.stage_native_subclass_change(window, replacement, old_return, false)?;
        Ok(Some((Win16WindowOperation::SetProcedure {
            window: native, previous: procedure, restore: false,
        }, WindowReturn::NativeSubclass(change))))
    }

    fn cache_native_subclass_failure(&mut self, frame_id: u64) -> Result<(), RuntimeError> {
        let completion = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_mut()).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "native subclass failure lost its exact completion"))?;
        // No native mutation occurred. Cache the API failure on the retired
        // query so a continuation retry cannot attempt installation again.
        completion.result = Win16WindowResult::SubclassProcedure { procedure: None, instance: None };
        Ok(())
    }

    pub(super) fn project_native_subclass_change(
        &mut self, change: NativeSubclassChange, succeeded: bool,
    ) -> Result<u32, RuntimeError> {
        if self.window_handles.get(&change.window) != Some(&change.native) {
            return Ok(0);
        }
        let Some(state) = self.window_data.get_mut(&change.window) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "completed native subclass lost its window data owner"));
        };
        // Nested callbacks may replace or restore the procedure themselves.
        // An outer completion must never overwrite their newer ownership.
        if state.subclass_revision == change.revision {
            if !succeeded { state.native_subclass = change.previous; }
            else if change.restoring { state.native_subclass = None; }
        }
        Ok(if succeeded { change.old_return } else { 0 })
    }

    pub(super) fn native_subclass_callback_owner(
        &self, native: Win16HostWindow,
    ) -> Result<(u16, u32, u16, WindowClassRoot), RuntimeError> {
        let window = self.window_handles.iter()
            .find_map(|(&window, &candidate)| (candidate == native).then_some(window))
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "native subclass callback has no live guest HWND"))?;
        let (address, instance) = self.native_subclass_procedure(window).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "native subclass callback has no explicit guest procedure owner"))?;
        Ok((window, address, instance, WindowClassRoot::NoRegistration))
    }
}
