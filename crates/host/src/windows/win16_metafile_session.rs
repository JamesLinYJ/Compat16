//! Typed WMF session tables and exact GDI incarnation retirement.

use super::*;
use std::sync::{Mutex, MutexGuard};

pub(in crate::windows) struct MetafileSession {
    pub(super) operation: u64,
    pub(super) count: usize,
    pub(super) maximum_record_bytes: usize,
    state: Mutex<SessionState>,
}
pub(super) struct SessionState {
    pub(super) callback: Option<Win16HostCallback>,
    pub(super) table: Vec<usize>,
    pub(super) final_table: Option<Vec<Option<Win16HostGdiObject>>>,
    notes: Vec<MetafileObjectNote>,
    finished: bool,
}
impl MetafileSession {
    pub(super) fn lock(&self) -> Result<MutexGuard<'_, SessionState>, RuntimeError> {
        self.state
            .lock()
            .map_err(|_| invariant("WMF session state lock was poisoned"))
    }
    pub(in crate::windows) fn retired_tokens(
        &self,
    ) -> Result<Vec<Win16HostGdiObject>, RuntimeError> {
        let state = self.lock()?;
        if !state.finished {
            return Err(invariant(
                "WMF completion preceded native enumeration return",
            ));
        }
        Ok(state
            .notes
            .iter()
            .filter(|note| note.retired())
            .map(|note| note.token)
            .collect())
    }
    pub(super) fn finish(&self) -> Result<(), RuntimeError> {
        let notes = self.lock()?.notes.clone();
        for note in notes {
            note.acknowledge_deletion()?;
        }
        self.lock()?.finished = true;
        Ok(())
    }
}
pub(in crate::windows) fn prepare(
    operation: &Win16WindowOperation,
    id: u64,
) -> Result<Option<Arc<MetafileSession>>, RuntimeError> {
    let Win16WindowOperation::EnumMetafile { bits, .. } = operation else {
        return Ok(None);
    };
    let parsed = formats::parse_wmf(bits).map_err(|error| {
        RuntimeError::with_source(Kind::InvalidInput, "invalid WMF enumeration stream", error)
    })?;
    let count = usize::from(parsed.header().object_count);
    Ok(Some(Arc::new(MetafileSession {
        operation: id,
        count,
        maximum_record_bytes: parsed.maximum_record_words() as usize * 2,
        state: Mutex::new(SessionState {
            callback: None,
            table: vec![0; count],
            final_table: None,
            notes: Vec::new(),
            finished: false,
        }),
    })))
}
impl Win16Windows {
    fn metafile_session(
        &self,
        callback: Win16HostCallback,
    ) -> Result<&MetafileSession, RuntimeError> {
        let pending = self
            .pending
            .iter()
            .rev()
            .find(|pending| pending.awaiting == Some(callback))
            .ok_or_else(|| invariant("WMF table has no exact suspended owner"))?;
        let session = pending
            .metafile
            .as_deref()
            .ok_or_else(|| invariant("WMF table has another pending owner"))?;
        if pending.awaiting != Some(callback)
            || session.operation != pending.id
            || session.lock()?.callback != Some(callback)
        {
            return Err(invariant(
                "WMF table does not match the exact suspended callback",
            ));
        }
        Ok(session)
    }
    pub(in crate::windows) fn metafile_callback_table(
        &self,
        callback: Win16HostCallback,
        objects: &mut Win16Objects,
    ) -> Result<Win16HostMetafileResult, RuntimeError> {
        let session = self.metafile_session(callback)?;
        let table = session.lock()?.table.clone();
        let mut tokens = Vec::with_capacity(table.len());
        for handle in table {
            tokens.push(if handle == 0 {
                None
            } else {
                Some(
                    objects.existing_native_token(handle)?.ok_or_else(|| {
                        invariant("native WMF table introduced an unowned object")
                    })?,
                )
            });
        }
        Ok(Win16HostMetafileResult::Table(tokens))
    }
    pub(in crate::windows) fn commit_metafile_table(
        &self,
        callback: Win16HostCallback,
        table: &[Option<Win16HostGdiObject>],
        objects: &Win16Objects,
        final_commit: bool,
    ) -> Result<(), RuntimeError> {
        let session = self.metafile_session(callback)?;
        if final_commit
            && self.pending.last().and_then(|pending| pending.awaiting) != Some(callback)
        {
            return Err(invariant(
                "WMF final table acknowledgement is not the active callback top",
            ));
        }
        if table.len() != session.count {
            return Err(invariant("WMF table commit changed its extent"));
        }
        let mut native = Vec::with_capacity(table.len());
        let mut notes = Vec::new();
        for token in table {
            native.push(match token {
                None => 0,
                Some(token) => {
                    let handle = objects.metafile_object(*token)?.ok_or_else(|| {
                        RuntimeError::new(
                            Kind::GuestFault,
                            "WMF table commit contains a retired object",
                        )
                    })?;
                    notes.push(
                        objects
                            .metafile_note(*token)
                            .ok_or_else(|| invariant("WMF object note disappeared"))?,
                    );
                    handle
                }
            });
        }
        let mut state = session.lock()?;
        if let Some(previous) = &state.final_table {
            if !final_commit || previous != table {
                return Err(invariant(
                    "WMF table commit changed after its final acknowledgement",
                ));
            }
            return Ok(());
        }
        // Reserve before publishing the new native table. Notes distinguish
        // recycled native handle bits by the exact opaque object incarnation.
        state.notes.try_reserve(notes.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain WMF table object lifetimes",
                error,
            )
        })?;
        for note in notes {
            if !state.notes.iter().any(|old| old.token == note.token) {
                state.notes.push(note);
            }
        }
        state.table = native;
        if final_commit {
            state.final_table = Some(table.to_vec());
        }
        Ok(())
    }
}
