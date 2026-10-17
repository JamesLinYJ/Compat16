//! Guest/native timer identity mappings for USER messages.

use super::*;

/// One task-local Win16 timer registration.
///
/// The guest HWND and timer ID form the Win16 key. `host_id` records the
/// corresponding native timer identity without exposing it through the guest
/// ABI. `callback` is the guest TIMERPROC FAR address, if SetTimer or
/// SetSystemTimer supplied one; it is invoked only by the checked guest
/// callback continuation. `system` keeps the two APIs in separate kill
/// namespaces for the same window and guest id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16TimerRegistration {
    pub(in crate::win16_runtime) host_id: u64,
    /// Opaque native-window identity captured when SetTimer succeeds. It is
    /// retained with retired generations so queued callbacks remain tied to
    /// the original window even after its live HWND mapping is removed.
    pub(in crate::win16_runtime) host_window: Option<Win16HostWindow>,
    pub(in crate::win16_runtime) callback: Option<u32>,
    pub(in crate::win16_runtime) system: bool,
}

impl Win16TimerRegistration {
    /// Guest message delivered when this registration fires. A system timer
    /// uses WM_SYSTIMER; an ordinary timer uses WM_TIMER.
    pub(in crate::win16_runtime) fn guest_message(self) -> u16 {
        if self.system {
            crate::Win16ScalarMessage::SystemTimer as u16
        } else {
            crate::Win16ScalarMessage::Timer as u16
        }
    }
}

/// Win16-to-host metadata for timers installed on the shared USER worker.
/// This is not a message queue: Windows remains the sole owner of timer
/// scheduling and queued WM_TIMER delivery.
#[derive(Clone, Debug, Default)]
pub(in crate::win16_runtime) struct Win16TimerRegistrations {
    entries: BTreeMap<(u16, u16, bool), Win16TimerRegistration>,
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
        system: bool,
    ) -> Option<Win16TimerRegistration> {
        self.entries.get(&(window, timer_id, system)).copied()
    }

    /// Replace metadata only after native SetTimer succeeds. The caller may
    /// retain and restore the previous value if it needs rollback semantics.
    pub(in crate::win16_runtime) fn insert(
        &mut self,
        window: u16,
        timer_id: u16,
        registration: Win16TimerRegistration,
    ) -> Option<Win16TimerRegistration> {
        let previous = self
            .entries
            .insert((window, timer_id, registration.system), registration);
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
        system: bool,
    ) -> Option<Win16TimerRegistration> {
        let previous = self.entries.remove(&(window, timer_id, system));
        if let Some(previous) = previous {
            self.retired
                .insert(previous.host_id, (window, timer_id, previous));
        }
        previous
    }

    /// Assign a representable Win16 identifier when USER's native SetTimer
    /// chooses one (the Win16 caller passed zero). Existing task-local IDs are
    /// retained so a native 32/64-bit timer identity never leaks into WPARAM16.
    /// Allocation stays inside the requested namespace.
    pub(in crate::win16_runtime) fn allocate_guest_id(
        &self,
        window: u16,
        system: bool,
    ) -> Option<u16> {
        (1..=u16::MAX)
            .find(|timer_id| !self.entries.contains_key(&(window, *timer_id, system)))
    }

    /// Resolve a generation even after replacement or KillTimer. Native
    /// Windows may already have queued its callback before retirement.
    pub(in crate::win16_runtime) fn registration_for_host(
        &self,
        host_id: u64,
    ) -> Option<(u16, u16, Win16TimerRegistration)> {
        self.entries
            .iter()
            .find_map(|(&(window, timer_id, _), registration)| {
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
    /// Windows destroys HWND-owned timers together with the HWND. Both
    /// namespaces for that window are retired.
    pub(in crate::win16_runtime) fn remove_window(&mut self, window: u16) {
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&(owner, timer_id, _), registration)| {
                (owner == window).then_some((timer_id, *registration))
            })
            .collect();
        for (timer_id, registration) in removed {
            self.entries
                .remove(&(window, timer_id, registration.system));
            self.retired
                .insert(registration.host_id, (window, timer_id, registration));
        }
    }

    pub(in crate::win16_runtime) fn clear(&mut self) {
        self.entries.clear();
        self.retired.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(host_id: u64, system: bool) -> Win16TimerRegistration {
        Win16TimerRegistration {
            host_id,
            host_window: None,
            callback: None,
            system,
        }
    }

    #[test]
    fn system_timers_do_not_share_an_id_with_set_timer() {
        let mut timers = Win16TimerRegistrations::default();
        timers.insert(1, 7, registration(10, false));
        timers.insert(1, 7, registration(11, true));
        assert_eq!(timers.get(1, 7, false).unwrap().host_id, 10);
        assert_eq!(timers.get(1, 7, true).unwrap().host_id, 11);
        assert!(timers.remove(1, 7, false).is_some());
        assert!(timers.get(1, 7, false).is_none());
        assert_eq!(timers.get(1, 7, true).unwrap().host_id, 11);
        assert!(!timers.registration_for_host(10).unwrap().2.system);
        assert_eq!(
            timers.get(1, 7, true).unwrap().guest_message(),
            crate::Win16ScalarMessage::SystemTimer as u16
        );
        assert_eq!(
            timers.registration_for_host(10).unwrap().2.guest_message(),
            crate::Win16ScalarMessage::Timer as u16
        );
    }

    #[test]
    fn auto_ids_and_window_retirement_stay_inside_each_namespace() {
        let mut timers = Win16TimerRegistrations::default();
        timers.insert(4, 1, registration(1, false));
        assert_eq!(timers.allocate_guest_id(4, false), Some(2));
        assert_eq!(timers.allocate_guest_id(4, true), Some(1));
        timers.insert(4, 1, registration(2, true));
        timers.remove_window(4);
        assert!(timers.get(4, 1, false).is_none());
        assert!(timers.get(4, 1, true).is_none());
        assert!(timers.registration_for_host(1).is_some());
        assert!(timers.registration_for_host(2).is_some());
    }
}
