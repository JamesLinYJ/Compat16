//! Guest local/global class namespaces, independent of native class names.
//!
//! Windows 3.1 defines CS_GLOBALCLASS as 0x4000. Class lookup searches the
//! caller's local registrations, then global registrations, then predefined
//! USER classes. A global class keeps its registering module as its owner.

use super::*;

const CS_GLOBALCLASS: u16 = 0x4000;

impl GuestWindowClass {
    fn is_global(&self) -> bool {
        self.info.style & CS_GLOBALCLASS != 0
    }

    fn matches_name(&self, name: &Win16ClassName, lower: Option<&[u8]>) -> bool {
        match name {
            Win16ClassName::Atom(atom) => self.atom == *atom
                || self.source_name_atom == Some(*atom),
            Win16ClassName::Name(_) => self.lower_name.as_deref() == lower,
        }
    }
}

impl GuestWindowClasses {
    pub(super) fn registered_class_index(
        &self,
        owner: Option<u16>,
        name: &Win16ClassName,
        lower: Option<&[u8]>,
    ) -> Option<usize> {
        if let Win16ClassName::Atom(atom) = name
            && let Some(index) = self.entries.iter().position(|entry| entry.atom == *atom)
        {
            // A returned registration atom names this exact class. An
            // inaccessible local registration must not fall through to an
            // unrelated global class whose source-name alias has this value.
            let entry = &self.entries[index];
            return (entry.is_global() || Some(entry.instance) == owner).then_some(index);
        }
        // Separate passes are required: a module may register a local class
        // after a same-named global class, including one it registered itself.
        self.entries.iter().position(|entry| !entry.is_global()
            && Some(entry.instance) == owner && entry.matches_name(name, lower))
            .or_else(|| self.entries.iter().position(|entry| entry.is_global()
                && entry.matches_name(name, lower)))
    }

    pub(super) fn registration_conflicts(
        &self,
        owner: u16,
        style: u16,
        lower: Option<&[u8]>,
        source_atom: Option<u16>,
    ) -> bool {
        self.entries.iter().any(|entry| {
            let same_name = entry.lower_name.as_deref() == lower
                || source_atom.is_some() && entry.source_name_atom == source_atom;
            same_name && if entry.is_global() {
                // Only one global registration owns a name. A new local
                // class may shadow it without replacing or borrowing it.
                style & CS_GLOBALCLASS != 0
            } else {
                entry.instance == owner
            }
        })
    }
}
