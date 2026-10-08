//! Guest HMENU identities for the native Win16 menu bridge.

use std::collections::BTreeMap;

use crate::Win16HostMenu;

/// Maps Win16 HMENU words to opaque host menu identities. Native ownership
/// remains with USER; this table is only the checked guest handle view.
pub(crate) struct GuestMenus {
    by_guest: BTreeMap<u16, Win16HostMenu>,
    by_host: BTreeMap<Win16HostMenu, u16>,
    next_handle: u16,
}

impl GuestMenus {
    pub(super) fn new() -> Self {
        Self {
            by_guest: BTreeMap::new(),
            by_host: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// Intern a native menu token, returning a stable guest HMENU word. `None`
    /// means the finite Win16 handle namespace is full.
    pub(super) fn intern(&mut self, host: Win16HostMenu) -> Option<u16> {
        if let Some(&guest) = self.by_host.get(&host) {
            return Some(guest);
        }
        for _ in 0..u16::MAX {
            let guest = self.next_handle;
            self.next_handle = self.next_handle.wrapping_add(1);
            if self.next_handle == 0 {
                self.next_handle = 1;
            }
            if guest == 0 || self.by_guest.contains_key(&guest) {
                continue;
            }
            self.by_guest.insert(guest, host);
            self.by_host.insert(host, guest);
            return Some(guest);
        }
        None
    }

    pub(super) fn resolve(&self, guest: u16) -> Option<Win16HostMenu> {
        self.by_guest.get(&guest).copied()
    }

    pub(super) fn has_free_handle(&self) -> bool {
        self.by_guest.len() < usize::from(u16::MAX)
    }

    /// Drop runtime identities for native menu objects already invalidated by
    /// Windows, such as an attached tree destroyed with its owner window.
    pub(super) fn invalidate(&mut self, tokens: &[Win16HostMenu]) {
        for token in tokens {
            if let Some(guest) = self.by_host.remove(token) {
                self.by_guest.remove(&guest);
            }
        }
    }

    pub(super) fn clear(&mut self) {
        self.by_guest.clear();
        self.by_host.clear();
    }
}
