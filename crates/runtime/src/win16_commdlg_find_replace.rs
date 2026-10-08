//! Modeless FINDMSGSTRING routing with retained guest selector identities.

use std::collections::BTreeMap;

use guest_core::memory::Memory;
use win16_abi::{GlobalHandle, SegmentedPointer};

use super::{ranges::GuestOutputRange, Win16State};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostFindReplaceDialog, Win16HostFindReplaceNotification,
    Win16HostFindReplaceUpdate, Win16HostWindow,
};

#[derive(Debug)]
pub(in crate::win16_runtime) struct Win16CommonDialogState {
    next_request_id: u64,
    pub(super) last_extended_error: u32,
    find_replace: BTreeMap<u64, FindReplaceSession>,
}

impl Default for Win16CommonDialogState {
    fn default() -> Self {
        Self { next_request_id: 1, last_extended_error: 0, find_replace: BTreeMap::new() }
    }
}

#[derive(Debug)]
struct FindReplaceSession {
    structure_far: u32,
    structure: GuestOutputRange,
    owner: Win16HostWindow,
    find_far: u32,
    find: GuestOutputRange,
    replace_far: Option<u32>,
    replace_text: Option<GuestOutputRange>,
    dialog: Option<Win16HostWindow>,
    find_message: Option<u16>,
    callback_stack: Vec<Win16HostFindReplaceNotification>,
    pins: Vec<GlobalHandle>,
    terminated: bool,
    retired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16GuestFindReplaceDispatch {
    pub(in crate::win16_runtime) request_id: u64,
    pub(in crate::win16_runtime) owner: Win16HostWindow,
    pub(in crate::win16_runtime) message: u16,
    pub(in crate::win16_runtime) w_param: u16,
    pub(in crate::win16_runtime) l_param: u32,
}

impl Win16State {
    pub(in crate::win16_runtime) fn reserve_find_replace(
        &mut self,
        memory: &Memory,
        structure_far: u32,
        structure: SegmentedPointer,
        owner: Win16HostWindow,
        replace_call: bool,
        find_far: u32,
        find: SegmentedPointer,
        find_capacity: usize,
        find_snapshot: Vec<u8>,
        replace_far: Option<u32>,
        replace_pointer: Option<SegmentedPointer>,
        replace_capacity: usize,
        replace_snapshot: Option<Vec<u8>>,
        flags: u32,
    ) -> Result<(u64, Win16HostFindReplaceDialog), RuntimeError> {
        let structure = GuestOutputRange::capture(self, memory, structure, 36)?;
        let find = GuestOutputRange::capture(self, memory, find, find_capacity)?;
        let replace_text = match replace_pointer {
            Some(pointer) => Some(GuestOutputRange::capture(
                self, memory, pointer, replace_capacity,
            )?),
            None => None,
        };
        if find_snapshot.len() != find_capacity
            || replace_text.as_ref().map(GuestOutputRange::length) != replace_snapshot.as_ref().map(Vec::len)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 FINDREPLACE snapshot does not match its captured ranges"));
        }

        let mut pins = Vec::new();
        pins.try_reserve(3).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve modeless Find/Replace heap pins", error))?;
        for pointer in std::iter::once(structure.start())
            .chain(std::iter::once(find.start()))
            .chain(replace_text.iter().map(GuestOutputRange::start))
        {
            let handle = match self.global_handle_for_selector(pointer.selector()) {
                Ok(handle) => handle,
                Err(error) => return Err(match self.release_find_replace_pins(pins) {
                    Ok(()) => error,
                    Err(cleanup) => combine_cleanup(error, cleanup),
                }),
            };
            if let Some(handle) = handle {
                if pins.contains(&handle) { continue; }
                match self.heap.lock(handle, &mut self.selectors, memory) {
                    Ok(_) => pins.push(handle),
                    Err(error) => {
                        let primary = crate::runtime_error(error);
                        return Err(match self.release_find_replace_pins(pins) {
                            Ok(()) => primary,
                            Err(cleanup) => combine_cleanup(primary, cleanup),
                        });
                    }
                }
            }
        }

        let request_id = self.common_dialog_state.next_request_id;
        let Some(next_request_id) = request_id.checked_add(1) else {
            let primary = RuntimeError::new(Kind::ResourceExhausted,
                "Win16 Find/Replace request identities exhausted");
            return Err(match self.release_find_replace_pins(pins) {
                Ok(()) => primary,
                Err(cleanup) => combine_cleanup(primary, cleanup),
            });
        };
        if self.common_dialog_state.find_replace.contains_key(&request_id) {
            let primary = RuntimeError::new(Kind::InternalInvariant,
                "Win16 Find/Replace request identity was reused");
            return Err(match self.release_find_replace_pins(pins) {
                Ok(()) => primary,
                Err(cleanup) => combine_cleanup(primary, cleanup),
            });
        }
        self.common_dialog_state.next_request_id = next_request_id;

        let request = Win16HostFindReplaceDialog {
            request_id,
            owner: Some(owner),
            replace: replace_call,
            flags,
            find_text: find_snapshot.clone(),
            replace_text: replace_snapshot.clone(),
        };
        let session = FindReplaceSession {
            structure_far,
            structure,
            owner,
            find_far,
            find,
            replace_far,
            replace_text,
            dialog: None,
            find_message: None,
            callback_stack: Vec::new(),
            pins,
            terminated: false,
            retired: false,
        };
        self.common_dialog_state.find_replace.insert(request_id, session);
        Ok((request_id, request))
    }

    pub(in crate::win16_runtime) fn cancel_find_replace(&mut self, request_id: u64) -> Result<(), RuntimeError> {
        let Some(session) = self.common_dialog_state.find_replace.get_mut(&request_id) else {
            return Ok(());
        };
        session.retired = true;
        while let Some(handle) = session.pins.last().copied() {
            self.heap.unlock(handle, &mut self.selectors)
                .map_err(crate::runtime_error)
                .map_err(|error| error.with_context(
                    "releasing a retained Find/Replace selector pin"))?;
            let Some(retired) = session.pins.pop() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Find/Replace pin disappeared before its exact unlock was recorded"));
            };
            if retired != handle {
                session.pins.push(retired);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Find/Replace pin order changed during terminal cleanup"));
            }
        }
        if self.common_dialog_state.find_replace.get(&request_id)
            .is_some_and(|session| session.callback_stack.is_empty())
        {
            self.common_dialog_state.find_replace.remove(&request_id);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn bind_find_replace_result(
        &mut self,
        request_id: u64,
        dialog: Option<Win16HostWindow>,
        message: u16,
    ) -> Result<bool, RuntimeError> {
        let Some(session) = self.common_dialog_state.find_replace.get_mut(&request_id) else {
            return Ok(false);
        };
        if session.retired || session.terminated || dialog.is_none() || message == 0 {
            return Ok(false);
        }
        if session.dialog.is_some_and(|seen| Some(seen) != dialog)
            || session.find_message.is_some_and(|seen| seen != message)
        {
            return Ok(false);
        }
        session.dialog = dialog;
        session.find_message = Some(message);
        Ok(true)
    }

    pub(in crate::win16_runtime) fn common_dialog_notification_is_live(
        &self,
        memory: &Memory,
        notification: &Win16HostFindReplaceNotification,
    ) -> Result<bool, RuntimeError> {
        let Some(session) = self.common_dialog_state.find_replace.get(&notification.request_id) else {
            return Ok(false);
        };
        let owner_still_mapped = self.window_handles.values().any(|window| *window == session.owner);
        let dialog_matches = match (session.dialog, notification.dialog) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let identity_live = !session.retired
            && !session.terminated
            && owner_still_mapped
            && notification.owner == session.owner
            && dialog_matches
            && notification.find_message != 0
            && session.find_message.is_none_or(|expected| expected == notification.find_message)
            && notification.find_text.len() == session.find.length()
            && notification.replace_text.as_ref().map(Vec::len)
                == session.replace_text.as_ref().map(GuestOutputRange::length)
            && notification.find_text.contains(&0)
            && notification.replace_text.as_ref().is_none_or(|bytes| bytes.contains(&0));
        if !identity_live { return Ok(false); }
        for range in std::iter::once(&session.structure)
            .chain(std::iter::once(&session.find))
            .chain(session.replace_text.iter())
        {
            match range.is_live(self, memory) {
                Ok(()) => {}
                Err(error) if super::is_guest_api_failure(&error) => return Ok(false),
                Err(error) => return Err(error.with_context(
                    "validating retained Find/Replace guest output ranges")),
            }
        }
        let structure = match session.structure.read(self, memory) {
            Ok(bytes) => bytes,
            Err(error) if super::is_guest_api_failure(&error) => return Ok(false),
            Err(error) => return Err(error.with_context(
                "reading retained FINDREPLACE callback bindings")),
        };
        let raw: [u8; win16_abi::commdlg_abi::FindReplace16::SIZE] =
            structure.try_into().map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "captured FINDREPLACE record has an unexpected size"))?;
        let record = win16_abi::commdlg_abi::FindReplace16::decode(&raw);
        if record.find_text != session.find_far
            || record.replace_text != session.replace_far.unwrap_or(0)
            || usize::from(record.find_text_capacity) != session.find.length()
            || usize::from(record.replace_text_capacity)
                != session.replace_text.as_ref().map_or(0, GuestOutputRange::length)
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub(in crate::win16_runtime) fn common_dialog_callback_message(
        &self,
        request_id: u64,
    ) -> Option<Win16HostFindReplaceNotification> {
        self.common_dialog_state.find_replace.get(&request_id)?
            .callback_stack.last().cloned()
    }

    pub(in crate::win16_runtime) fn prepare_find_replace_notification(
        &mut self,
        memory: &mut Memory,
        notification: &Win16HostFindReplaceNotification,
    ) -> Result<Option<Win16GuestFindReplaceDispatch>, RuntimeError> {
        if !self.common_dialog_notification_is_live(memory, notification)? {
            return Err(RuntimeError::new(Kind::GuestFault,
                "stale Win16 Find/Replace notification reached guest dispatch"));
        }
        let session = self.common_dialog_state.find_replace
            .get_mut(&notification.request_id).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "live Find/Replace notification lost its session"))?;
        if session.dialog.is_some_and(|dialog| notification.dialog != Some(dialog))
            || session.find_message.is_some_and(|message| message != notification.find_message)
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 Find/Replace notification no longer matches its native dialog"));
        }
        session.callback_stack.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve nested Find/Replace callback snapshot", error))?;
        let structure_range = session.structure.clone();
        let find_range = session.find.clone();
        let replace_range = session.replace_text.clone();
        let request_id = notification.request_id;
        let structure_far = session.structure_far;
        let owner = session.owner;
        let find_far = session.find_far;
        let replace_far = session.replace_far;
        let find_capacity = session.find.length();
        let replace_capacity = session.replace_text.as_ref().map_or(0, GuestOutputRange::length);
        let structure = structure_range.read(self, memory)?;
        let raw: [u8; win16_abi::commdlg_abi::FindReplace16::SIZE] = structure.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "captured FINDREPLACE record has an unexpected size"))?;
        let mut record = win16_abi::commdlg_abi::FindReplace16::decode(&raw);
        if record.find_text != find_far
            || record.replace_text != replace_far.unwrap_or(0)
            || usize::from(record.find_text_capacity) != find_capacity
            || usize::from(record.replace_text_capacity) != replace_capacity
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "guest changed the captured FINDREPLACE callback bindings"));
        }
        let mut writes = vec![(find_range, notification.find_text.clone())];
        if let (Some(range), Some(bytes)) = (replace_range, notification.replace_text.as_ref()) {
            writes.push((range, bytes.clone()));
        }
        record.flags = notification.flags;
        writes.push((structure_range, record.encode().to_vec()));
        super::ranges::commit_guest_writes(self, memory, writes)?;

        let session = self.common_dialog_state.find_replace
            .get_mut(&request_id).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Find/Replace session vanished while applying a notification"))?;
        session.dialog = notification.dialog.or(session.dialog);
        session.find_message = Some(notification.find_message);
        session.terminated = notification.dialog_terminated;
        session.callback_stack.push(notification.clone());
        // The native dialog owns independent buffers. Windows 3.1 CDDEMO frees
        // the guest FINDREPLACE chunk from FR_DIALOGTERM; drop pins after the
        // terminal snapshot has been copied in, but retain session identity
        // until its guest callback finishes.
        let retire_terminal_session = notification.dialog_terminated;
        if retire_terminal_session {
            self.cancel_find_replace(request_id)?;
        }

        Ok(Some(Win16GuestFindReplaceDispatch {
            request_id,
            owner,
            message: notification.find_message,
            w_param: 0,
            l_param: structure_far,
        }))
    }

    pub(in crate::win16_runtime) fn finish_find_replace_guest_callback(
        &mut self,
        memory: &Memory,
        request_id: u64,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16HostFindReplaceUpdate>, RuntimeError> {
        let snapshot = match self.common_dialog_state.find_replace.get_mut(&request_id) {
            Some(session) => match session.callback_stack.pop() {
                Some(snapshot) => snapshot,
                None => return Ok(None),
            },
            None => return Ok(None),
        };
        let terminal_dialog = if snapshot.dialog_terminated {
            snapshot.dialog.or_else(|| self.common_dialog_state.find_replace
                .get(&request_id).and_then(|session| session.dialog))
        } else { None };
        let can_update = self.common_dialog_state.find_replace.get(&request_id)
            .is_some_and(|session| !session.retired && !session.terminated);
        let mut update = None;
        let mut fatal = None;
        if !snapshot.dialog_terminated && can_update {
            match self.read_find_replace_guest_update(request_id, memory) {
                Ok(Some((flags, find_text, replace_text))) => {
                    update = Some(Win16HostFindReplaceUpdate {
                        request_id,
                        flags,
                        find_text,
                        replace_text,
                    });
                }
                Ok(None) => host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "guest changed a modeless FINDREPLACE pointer or returned an unterminated buffer; native dialog state was retained",
                )),
                Err(error) if super::is_guest_api_failure(&error) => host.report_diagnostic(
                    &Diagnostic::warning(error.kind(), error.with_context(
                        "reading a modeless FINDREPLACE callback result").to_string())),
                Err(error) => fatal = Some(error.with_context(
                    "reading a modeless FINDREPLACE callback result")),
            }
        }

        let finished = self.common_dialog_state.find_replace.get(&request_id)
            .is_some_and(|session| session.callback_stack.is_empty()
                && (session.terminated || session.retired));
        if finished {
            if let Err(cleanup) = self.cancel_find_replace(request_id) {
                fatal = Some(match fatal {
                    Some(primary) => combine_cleanup(primary, cleanup),
                    None => cleanup,
                });
            }
        }
        if let Some(dialog) = terminal_dialog {
            if let Err(cleanup) = self.retire_dialog_window(dialog) {
                fatal = Some(match fatal {
                    Some(primary) => combine_cleanup(primary, cleanup),
                    None => cleanup,
                });
            }
        }
        match fatal {
            Some(error) => Err(error),
            None => Ok(update),
        }
    }

    pub(in crate::win16_runtime) fn retire_common_dialog_window(
        &mut self,
        native: Win16HostWindow,
    ) -> Result<(), RuntimeError> {
        let count = self.common_dialog_state.find_replace.values().filter(|session|
            session.owner == native || session.dialog == Some(native)).count();
        let mut ids = Vec::new();
        ids.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact Find/Replace window-retirement identities",
            error,
        ))?;
        ids.extend(self.common_dialog_state.find_replace.iter().filter_map(|(&id, session)|
            (session.owner == native || session.dialog == Some(native)).then_some(id)));
        let mut first_error = None;
        for id in ids {
            if let Err(error) = self.cancel_find_replace(id) {
                first_error = Some(match first_error.take() {
                    Some(primary) => combine_cleanup(primary, error),
                    None => error,
                });
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(in crate::win16_runtime) fn retire_all_common_dialogs(&mut self) -> Result<(), RuntimeError> {
        let mut ids = Vec::new();
        ids.try_reserve_exact(self.common_dialog_state.find_replace.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve exact Find/Replace teardown session identities", error))?;
        ids.extend(self.common_dialog_state.find_replace.keys().copied());
        let mut first_error = None;
        for id in ids {
            if let Err(error) = self.cancel_find_replace(id) {
                first_error = Some(match first_error.take() {
                    Some(primary) => combine_cleanup(primary, error),
                    None => error,
                });
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn read_find_replace_guest_update(
        &self,
        request_id: u64,
        memory: &Memory,
    ) -> Result<Option<(u32, Vec<u8>, Option<Vec<u8>>)>, RuntimeError> {
        let session = self.common_dialog_state.find_replace.get(&request_id).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "Find/Replace session disappeared while reading its callback result"))?;
        let bytes = session.structure.read(self, memory)?;
        let raw: [u8; win16_abi::commdlg_abi::FindReplace16::SIZE] = bytes.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "captured FINDREPLACE callback structure has invalid size"))?;
        let structure = win16_abi::commdlg_abi::FindReplace16::decode(&raw);
        if structure.find_text != session.find_far
            || structure.replace_text != session.replace_far.unwrap_or(0)
            || usize::from(structure.find_text_capacity) != session.find.length()
            || usize::from(structure.replace_text_capacity)
                != session.replace_text.as_ref().map_or(0, GuestOutputRange::length)
        {
            return Ok(None);
        }
        let find = session.find.read(self, memory)?;
        if !find.contains(&0) { return Ok(None); }
        let replace = match &session.replace_text {
            Some(range) => {
                let bytes = range.read(self, memory)?;
                if !bytes.contains(&0) { return Ok(None); }
                Some(bytes)
            }
            None => None,
        };
        Ok(Some((structure.flags, find, replace)))
    }

    fn global_handle_for_selector(
        &self,
        selector: win16_abi::SelectorRef,
    ) -> Result<Option<GlobalHandle>, RuntimeError> {
        for (&raw, &base) in &self.global_selectors {
            // global_selectors is runtime-owned metadata, so a stale saved
            // identity is an invariant failure rather than bad guest input.
            let descriptor = self.selectors.describe(base).map_err(|error|
                RuntimeError::with_source(Kind::InternalInvariant,
                    "runtime HGLOBAL table contains a stale selector identity", error))?;
            let base_pointer = SegmentedPointer::new(base, 0);
            for index in 0..descriptor.segment_count {
                let displacement = u32::try_from(index.checked_mul(65_536).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "global selector span overflows address space"))?)
                    .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                        "global selector span exceeds DWORD", error))?;
                let segment = self.selectors.add_bytes(base_pointer, displacement)
                    .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant,
                        "runtime HGLOBAL selector span is inconsistent", error))?;
                if segment.selector() == selector {
                    return Ok(self.global_handles.get(&raw).copied());
                }
            }
        }
        Ok(None)
    }

    fn release_find_replace_pins(&mut self, pins: Vec<GlobalHandle>) -> Result<(), RuntimeError> {
        let mut first_error = None;
        for handle in pins.into_iter().rev() {
            if let Err(error) = self.heap.unlock(handle, &mut self.selectors) {
                let error = crate::runtime_error(error);
                if first_error.is_none() { first_error = Some(error); }
            }
        }
        match first_error {
            Some(error) => Err(error.with_context("releasing modeless Find/Replace buffer pins")),
            None => Ok(()),
        }
    }
}

fn combine_cleanup(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    RuntimeError::with_source(Kind::InternalInvariant,
        format!("{}; Find/Replace pin cleanup also failed", primary), cleanup)
        .with_context("preserving the original common-dialog failure")
}
