use super::*;

pub(in crate::windows::win16_windows) struct NativeQueuedClassicDdeEvent {
    pub(in crate::windows::win16_windows) event: Win16HostClassicDdeEvent,
    pub(in crate::windows::win16_windows) atom_leases: Vec<wire::NativeGlobalAtomLease>,
    pub(in crate::windows::win16_windows) globals_to_free: Vec<windows_sys::Win32::Foundation::HGLOBAL>,
    /// DDEADVISE/DDEPOKE/DDEDATA handles that this receiver may free only
    /// after it posts a positive protocol ACK for this exact event.
    pub(in crate::windows::win16_windows) globals_after_positive_ack: Vec<windows_sys::Win32::Foundation::HGLOBAL>,
}

impl Drop for NativeQueuedClassicDdeEvent {
    fn drop(&mut self) {
        for handle in self.globals_to_free.drain(..) {
            // SAFETY: These handles were received through this exact DDE
            // message and the DDE release flags transferred their ownership.
            unsafe { GlobalFree(handle) };
        }
    }
}

pub(in crate::windows::win16_windows) struct NativeClassicDdeConversation {
    pub(in crate::windows::win16_windows) peer: Win16HostClassicDdePeer,
    // Application/topic snapshots travel in the checked binding receipt.
    // This host record retains their native references for its own lifetime.
    pub(in crate::windows::win16_windows) _atom_leases: Vec<wire::NativeGlobalAtomLease>,
}

pub(in crate::windows::win16_windows) struct NativeClassicDdeTransfer {
    pub(in crate::windows::win16_windows) handle: windows_sys::Win32::Foundation::HGLOBAL,
    pub(in crate::windows::win16_windows) peer: Win16HostClassicDdePeer,
    pub(in crate::windows::win16_windows) conversation: Option<Win16ClassicDdeConversationId>,
    pub(in crate::windows::win16_windows) owns_handle: bool,
    pub(in crate::windows::win16_windows) release_after_receive: bool,
    pub(in crate::windows::win16_windows) protocol_ack_posted: bool,
    pub(in crate::windows::win16_windows) message: u16,
    pub(in crate::windows::win16_windows) atom_leases: Vec<wire::NativeGlobalAtomLease>,
}

impl Drop for NativeClassicDdeTransfer {
    fn drop(&mut self) {
        if self.owns_handle && !self.handle.is_null() {
            // SAFETY: This ledger entry is the unique owner of the movable
            // block allocated for the exact DDE transfer.
            unsafe { GlobalFree(self.handle) };
        }
    }
}

pub(in crate::windows::win16_windows) struct NativeClassicDdeTransaction {
    pub(in crate::windows::win16_windows) peer: Win16HostClassicDdePeer,
    pub(in crate::windows::win16_windows) conversation: Win16ClassicDdeConversationId,
    pub(in crate::windows::win16_windows) message: u16,
    pub(in crate::windows::win16_windows) transfer: Option<Win16ClassicDdeTransferId>,
    pub(in crate::windows::win16_windows) item: Option<Win16ClassicDdeAtom>,
    /// True while this endpoint is waiting for the peer's protocol response.
    /// Incoming response transactions are consumed by EventId retirement and
    /// must never be matched as a second peer ACK.
    pub(in crate::windows::win16_windows) awaiting_peer_ack: bool,
    pub(in crate::windows::win16_windows) source_event_id: Option<Win16ClassicDdeEventId>,
    pub(in crate::windows::win16_windows) requires_local_ack: bool,
    pub(in crate::windows::win16_windows) local_acknowledged: Option<bool>,
    pub(in crate::windows::win16_windows) _atom_leases: Vec<wire::NativeGlobalAtomLease>,
}

pub(in crate::windows::win16_windows) struct NativeSynchronousClassicDdeFrame {
    pub(in crate::windows::win16_windows) event: Win16HostClassicDdeEvent,
    pub(in crate::windows::win16_windows) callback_step: Arc<Win16HostClassicDdeCallbackStep>,
    pub(in crate::windows::win16_windows) atom_leases: Vec<wire::NativeGlobalAtomLease>,
    pub(in crate::windows::win16_windows) globals_to_free: Vec<windows_sys::Win32::Foundation::HGLOBAL>,
    pub(in crate::windows::win16_windows) globals_after_positive_ack: Vec<windows_sys::Win32::Foundation::HGLOBAL>,
    pub(in crate::windows::win16_windows) raw_w_param: WPARAM,
    pub(in crate::windows::win16_windows) raw_l_param: LPARAM,
    pub(in crate::windows::win16_windows) packed_l_param: Option<(u16, LPARAM)>,
}

impl Drop for NativeSynchronousClassicDdeFrame {
    fn drop(&mut self) {
        if let Some((message, l_param)) = self.packed_l_param.take() {
            // SAFETY: The exact received packed DDE LPARAM remains owned by
            // this frame unless it was transferred to DefWindowProc.
            unsafe { wire::free_packed_lparam(message, l_param) };
        }
        for handle in self.globals_to_free.drain(..) {
            // SAFETY: The exact synchronous DDE receiver owns these blocks
            // according to the message's release flags or EXECUTE contract.
            unsafe { GlobalFree(handle) };
        }
    }
}

pub(in crate::windows::win16_windows) struct PendingSynchronousClassicDdeIngress {
    pub(in crate::windows::win16_windows) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::windows::win16_windows) event: Win16HostClassicDdeEvent,
    pub(in crate::windows::win16_windows) atom_leases: Vec<wire::NativeGlobalAtomLease>,
    pub(in crate::windows::win16_windows) globals_to_free: Vec<windows_sys::Win32::Foundation::HGLOBAL>,
    pub(in crate::windows::win16_windows) globals_after_positive_ack: Vec<windows_sys::Win32::Foundation::HGLOBAL>,
    pub(in crate::windows::win16_windows) assigned_operation: Option<Win16ClassicDdeOperationId>,
    pub(in crate::windows::win16_windows) callback: Win16HostCallback,
    pub(in crate::windows::win16_windows) frame: Win16HostClassicDdeCallbackFrame,
    pub(in crate::windows::win16_windows) raw_w_param: WPARAM,
    pub(in crate::windows::win16_windows) raw_l_param: LPARAM,
    pub(in crate::windows::win16_windows) packed_l_param: Option<(u16, LPARAM)>,
}

impl Drop for PendingSynchronousClassicDdeIngress {
    fn drop(&mut self) {
        if let Some((message, l_param)) = self.packed_l_param.take() {
            // SAFETY: The received packed LPARAM stays owned by this ingress
            // until default handling or a retained synchronous frame takes it.
            unsafe { wire::free_packed_lparam(message, l_param) };
        }
        for handle in self.globals_to_free.drain(..) {
            // SAFETY: The exact synchronous DDE receiver owns these blocks
            // according to the message's release flags or EXECUTE contract.
            unsafe { GlobalFree(handle) };
        }
    }
}
