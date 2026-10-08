//! Narrow read access to the active object-method stage for OLE release queries.

use super::Win16State;

impl Win16State {
    pub(super) fn pending_ole1_object_method_slot(&self, object_proxy_id: u64) -> Option<u8> {
        let mut pending = self
            .ole1_client_documents
            .pending_object_methods
            .iter()
            .filter(|sequence| sequence.record.id == object_proxy_id);
        let slot = pending.next().map(|sequence| sequence.slot);
        if pending.next().is_some() {
            None
        } else {
            slot
        }
    }
}
