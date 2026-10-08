//! Guest/native timer identity mappings for USER messages.

use super::*;

/// One task-local Win16 timer registration.
///
/// The guest HWND and timer ID form the Win16 key. `host_id` records the
/// corresponding native timer identity without exposing it through the guest
/// ABI. `callback` is the guest TIMERPROC FAR address, if SetTimer supplied
/// one; it is invoked only by the checked guest callback continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16TimerRegistration {
    pub(in crate::win16_runtime) host_id: u64,
    /// Opaque native-window identity captured when SetTimer succeeds. It is
    /// retained with retired generations so queued callbacks remain tied to
    /// the original window even after its live HWND mapping is removed.
    pub(in crate::win16_runtime) host_window: Option<Win16HostWindow>,
    pub(in crate::win16_runtime) callback: Option<u32>,
}

/// Win16-to-host metadata for timers installed on the shared USER worker.
/// This is not a message queue: Windows remains the sole owner of timer
/// scheduling and queued WM_TIMER delivery.
#[derive(Clone, Debug, Default)]
pub(in crate::win16_runtime) struct Win16TimerRegistrations {
    entries: BTreeMap<(u16, u16), Win16TimerRegistration>,
    // KillTimer does not remove WM_TIMER records which Windows already
    // queued. Keep retired generations addressable until the Win16 task is
    // torn down so an old native timer token cannot resolve to a replacement.
    retired: BTreeMap<u64, (u16, u16, Win16TimerRegistration)>,
}

impl Win16TimerRegistrations {
    pub(in crate::win16_runtime) fn get(
        &self,
        window: u16,
        timer_id: u16,
    ) -> Option<Win16TimerRegistration> {
        self.entries.get(&(window, timer_id)).copied()
    }

    /// Replace metadata only after native SetTimer succeeds. The caller may
    /// retain and restore the previous value if it needs rollback semantics.
    pub(in crate::win16_runtime) fn insert(
        &mut self,
        window: u16,
        timer_id: u16,
        registration: Win16TimerRegistration,
    ) -> Option<Win16TimerRegistration> {
        let previous = self.entries.insert((window, timer_id), registration);
        if let Some(previous) = previous {
            self.retired
                .insert(previous.host_id, (window, timer_id, previous));
        }
        previous
    }

    pub(in crate::win16_runtime) fn remove(
        &mut self,
        window: u16,
        timer_id: u16,
    ) -> Option<Win16TimerRegistration> {
        let previous = self.entries.remove(&(window, timer_id));
        if let Some(previous) = previous {
            self.retired
                .insert(previous.host_id, (window, timer_id, previous));
        }
        previous
    }

    /// Assign a representable Win16 identifier when USER's native SetTimer
    /// chooses one (the Win16 caller passed zero). Existing task-local IDs are
    /// retained so a native 32/64-bit timer identity never leaks into WPARAM16.
    pub(in crate::win16_runtime) fn allocate_guest_id(&self, window: u16) -> Option<u16> {
        (1..=u16::MAX).find(|timer_id| !self.entries.contains_key(&(window, *timer_id)))
    }

    /// Resolve a generation even after replacement or KillTimer. Native
    /// Windows may already have queued its callback before retirement.
    pub(in crate::win16_runtime) fn registration_for_host(
        &self,
        host_id: u64,
    ) -> Option<(u16, u16, Win16TimerRegistration)> {
        self.entries
            .iter()
            .find_map(|(&(window, timer_id), registration)| {
                (registration.host_id == host_id).then_some((window, timer_id, *registration))
            })
            .or_else(|| self.retired.get(&host_id).copied())
    }

    pub(in crate::win16_runtime) fn callback_addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries
            .values()
            .filter_map(|registration| registration.callback)
            .chain(
                self.retired
                    .values()
                    .filter_map(|(_, _, registration)| registration.callback),
            )
    }

    /// Retire timer registrations when USER destroys a guest window. Native
    /// Windows destroys HWND-owned timers together with the HWND.
    pub(in crate::win16_runtime) fn remove_window(&mut self, window: u16) {
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&(owner, timer_id), registration)| {
                (owner == window).then_some((timer_id, *registration))
            })
            .collect();
        for (timer_id, registration) in removed {
            self.entries.remove(&(window, timer_id));
            self.retired
                .insert(registration.host_id, (window, timer_id, registration));
        }
    }

    pub(in crate::win16_runtime) fn clear(&mut self) {
        self.entries.clear();
        self.retired.clear();
    }
}
