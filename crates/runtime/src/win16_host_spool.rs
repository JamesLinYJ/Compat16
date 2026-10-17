//! Owned Win16 PRINT.H spooler operations sent to the native host.
//!
//! Guest HPJOB values are runtime-owned identities. This boundary uses an
//! opaque token instead of exposing a Windows PRINTER_HANDLE or job ID.

use crate::Win16HostTaskOwner;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostSpoolJob(u64);

impl Win16HostSpoolJob {
    /// Create a host-owned token. The native printer handle never crosses the
    /// boundary; only this identity is retained by the Win16 guest mapping.
    pub const fn new(token: u64) -> Self {
        Self(token)
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

/// A copied Win16 print request after guest pointers have been decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostSpoolOperation {
    OpenJob {
        /// Task that owns this GDI spool document until CloseJob or teardown.
        owner: Win16HostTaskOwner,
        /// Win16's output port/device string, for example `LPT1:`.
        output_target: Vec<u8>,
        document_name: Vec<u8>,
        /// PRINT.H spells this WORD as HPJOB; DDK section 5.4.1 identifies it
        /// as the application's abort DC. The runtime validates the guest DC;
        /// this WORD is never interpreted as a native Windows handle.
        legacy_argument: u16,
    },
    /// WNetOpenJob creates a spooler document and returns an HFILE-shaped
    /// guest token through Win16NetworkPrintJobs. The host token here is
    /// deliberately independent from that guest WORD handle.
    NetworkOpenJob {
        /// Existing Win16 task owner scopes the host lease; Windows still
        /// evaluates actual printer/job access permissions.
        owner: Win16HostTaskOwner,
        queue: Vec<u8>,
        document_name: Option<Vec<u8>>,
        copies: u16,
    },
    StartPage {
        job: Win16HostSpoolJob,
    },
    EndPage {
        job: Win16HostSpoolJob,
    },
    Write {
        job: Win16HostSpoolJob,
        bytes: Vec<u8>,
    },
    CloseJob {
        job: Win16HostSpoolJob,
    },
    /// WNetCloseJob ends the document but retains its task-owned opaque
    /// identity so later Hold/Release/Cancel/SetCopies calls can address the
    /// exact native spool job.
    NetworkCloseJob {
        job: Win16HostSpoolJob,
    },
    NetworkAbortJob {
        job: Win16HostSpoolJob,
        queue: Vec<u8>,
    },
    NetworkJobControl {
        job: Win16HostSpoolJob,
        queue: Vec<u8>,
        control: Win16NetworkPrintJobControl,
    },
    NetworkSetJobCopies {
        job: Win16HostSpoolJob,
        queue: Vec<u8>,
        copies: u16,
    },
    /// Release a retained identity without cancelling a completed job. An
    /// active document is aborted before its printer handle is closed.
    ReleaseNetworkJob {
        job: Win16HostSpoolJob,
    },
    /// Retry every native job lease belonging to one Win16 task. This is also
    /// the cleanup fallback for host tokens returned after an allocation
    /// failure prevented the runtime from retaining each individual token.
    ReleaseNetworkOwner {
        owner: Win16HostTaskOwner,
    },
    DeleteJob {
        job: Win16HostSpoolJob,
        /// The XP WOW thunk ignores this SDK `int` argument. Preserve its
        /// signed 16-bit value while the runtime applies the SDK contract.
        legacy_argument: i16,
    },
    WriteDialog {
        job: Win16HostSpoolJob,
        text: Vec<u8>,
        count: i16,
    },
    DeleteSpoolPage {
        job: Win16HostSpoolJob,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NetworkPrintJobControl {
    Hold,
    Release,
    Cancel,
}

/// Normal Windows spooler outcomes stay values so the guest layer can map
/// them to the documented Win16 status/handle convention. `native_error` is
/// populated only when the corresponding Windows API failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostSpoolResult {
    OpenJob {
        job: Option<Win16HostSpoolJob>,
        native_error: Option<u32>,
    },
    NetworkOpenJob {
        job: Option<Win16HostSpoolJob>,
        queue_name: Option<Vec<u8>>,
        /// True when the WNetOpenJob request completes without a copy warning.
        /// For one requested copy this means the original RAW stream is passed
        /// through once; it does not claim a physical count encoded by that PDL
        /// or a DEVMODE write. Only WNetSetJobCopies clamps to the native maximum.
        copies_applied: bool,
        native_error: Option<u32>,
        copies_error: Option<u32>,
        /// Typed internal cause for a copy negotiation/readback failure.
        copies_diagnostic: Option<Win16HostSpoolDiagnostic>,
    },
    NetworkCloseJob {
        succeeded: bool,
        queue_name: Option<Vec<u8>>,
        native_error: Option<u32>,
    },
    Status {
        succeeded: bool,
        native_error: Option<u32>,
    },
    Write {
        bytes_written: u32,
        native_error: Option<u32>,
    },
}

/// Typed host-side cause retained when a copy failure has no faithful native
/// status code projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostSpoolDiagnostic {
    pub kind: crate::DiagnosticKind,
    pub message: String,
}

/// Opaque Windows printer-change subscription. Its native notification and
/// printer handles remain owned by the host queue registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostNetworkQueueWatch(u64);

impl Win16HostNetworkQueueWatch {
    pub const fn new(token: u64) -> Self {
        Self(token)
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkQueueOperation {
    /// `local_device` is WNetWatchQueue's redirected device name; `user` is
    /// its nullable advisory username filter from the WFW SDK contract.
    Watch {
        owner: Win16HostTaskOwner,
        local_device: Vec<u8>,
        user: Option<Vec<u8>>,
    },
    Unwatch {
        watch: Win16HostNetworkQueueWatch,
    },
    Snapshot {
        /// Existing Win16 task owner scopes borrowed native job handles.
        owner: Win16HostTaskOwner,
        queue: Vec<u8>,
        /// WNetLockQueueData's nullable advisory username. The returned queue
        /// may still contain jobs belonging to other users.
        user: Option<Vec<u8>>,
    },
    /// Polls native change notifications without waiting. Returned watches
    /// are owned identities; the runtime translates them to guest HWND events.
    PeekChanges,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostNetworkPrintQueueSnapshot {
    pub name: Vec<u8>,
    pub comment: Option<Vec<u8>>,
    pub status: u16,
    pub printer_count: u16,
    pub jobs: Vec<Win16HostNetworkPrintJobSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostNetworkPrintJobSnapshot {
    pub job: Win16HostSpoolJob,
    pub username: Option<Vec<u8>>,
    pub parameters: Option<Vec<u8>>,
    pub position: u16,
    pub status: u16,
    pub submitted: u32,
    pub size: u32,
    pub copies: u16,
    pub comment: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkQueueResult {
    Watch {
        watch: Option<Win16HostNetworkQueueWatch>,
        /// Shared identity_source value for USER's asynchronous post, distinct
        /// from the provider's opaque watch token.
        notification_source_id: Option<u64>,
        native_error: Option<u32>,
    },
    Status {
        succeeded: bool,
        native_error: Option<u32>,
    },
    Snapshot {
        snapshot: Option<Win16HostNetworkPrintQueueSnapshot>,
        native_error: Option<u32>,
        /// Host job tokens left live after a failed partial snapshot rollback.
        cleanup_jobs: Vec<Win16HostSpoolJob>,
        diagnostic: Option<Win16HostSpoolDiagnostic>,
    },
    Changes {
        changed: Vec<Win16HostNetworkQueueWatch>,
        failed_watch: Option<Win16HostNetworkQueueWatch>,
        native_error: Option<u32>,
    },
}
