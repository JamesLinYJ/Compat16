//! USER.403 removes one exact guest registration after native acknowledgment.
//!
//! Windows 3.0 Programmer's Reference, UnregisterClass (4-452), requires the
//! registering module instance and no remaining windows; predefined classes
//! cannot be removed. The FAR name also supports a registration atom, as in
//! the other USER class selectors. Neither guest selector reaches native USER.

use super::*;
use crate::Diagnostic;
use crate::win16_runtime::{
    messages::MessageOutput,
    messages_mdi::MdiOutputPlan,
    windows::{WindowClassRoot, WindowReturn},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowClassRetention {
    Unretained,
    Retained,
    Unresolved,
}

impl Win16State {
    pub(in crate::win16_runtime) fn unregister_class(
        &mut self,
        instance: u16,
        name: Win16ClassName,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        // A null/system-wide owner is not a license to search other modules.
        // Unlike CreateWindow, this API requires the registering instance.
        if instance == 0 { return Ok(0); }
        let Some(owner) = self.class_instance(instance) else { return Ok(0); };
        let Some(index) = self.class_to_unregister(owner, &name, host)? else { return Ok(0); };
        let class = self.window_classes.entries[index].host_class;
        match self.window_class_retention(class) {
            WindowClassRetention::Retained => return Ok(0),
            WindowClassRetention::Unresolved => return Ok(unresolved_callback_class(host)),
            WindowClassRetention::Unretained => {}
        }
        // This synchronous host contract does not run guest callbacks. Its
        // opaque token targets the worker's own registration, including native
        // windows not yet projected as guest HWNDs. Keep all bytes/roots until
        // success; a refusal or an error leaves the entire entry untouched.
        if !host.win16_unregister_window_class(class)? { return Ok(0); }
        self.window_classes.entries.remove(index);
        Ok(1)
    }

    /// Shared with automatic module cleanup: native unregister success alone
    /// cannot release a registration still owned by suspended guest work.
    pub(super) fn window_class_retention(&self, class: Win16HostClass) -> WindowClassRetention {
        if self.window_handles.keys().any(|&window| {
            self.window_host_class(window) == Some(class)
                || self.window_procedures.get(&window).is_some_and(|proc| proc.class == class)
        }) || self.window_operations.iter().any(|frame| match frame.continuation() {
            Some(WindowReturn::Create { procedure, .. }) => procedure.class == class,
            Some(WindowReturn::UserFamily(continuation)) => continuation.retains_window_class(class),
            Some(WindowReturn::Message {
                output: MessageOutput::Mdi(Some(MdiOutputPlan::Create(plan))),
            }) | Some(WindowReturn::DispatchMessage {
                mdi_output: Some(MdiOutputPlan::Create(plan)),
            }) => plan.mdi.class == class,
            _ => false,
        }) || self.window_callbacks.iter().any(|frame|
            frame.class_root == WindowClassRoot::Class(class))
        {
            return WindowClassRetention::Retained;
        }
        if self.window_callbacks.iter().any(|frame| frame.class_root == WindowClassRoot::Unresolved) {
            return WindowClassRetention::Unresolved;
        }
        WindowClassRetention::Unretained
    }

    fn class_to_unregister(
        &self,
        owner: u16,
        name: &Win16ClassName,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<usize>, RuntimeError> {
        let lower = match name {
            Win16ClassName::Name(bytes) => {
                if bytes.is_empty() || bytes.len() > MAX_CLASS_NAME_BYTES { return Ok(None); }
                host.win16_ansi_lower_string(bytes)?
            }
            Win16ClassName::Atom(0) => return Ok(None),
            Win16ClassName::Atom(atom) => {
                // Returned registration atoms outrank source-name aliases,
                // even when the returned atom belongs to another module.
                if let Some(index) = self.window_classes.entries.iter()
                    .position(|entry| entry.atom == *atom)
                {
                    return Ok((self.window_classes.entries[index].instance == owner).then_some(index));
                }
                let Some(index) = self.window_classes.entries.iter().position(|entry|
                    entry.instance == owner && entry.source_name_atom == Some(*atom))
                else { return Ok(None); };
                // RegisterClass copies a source atom's name but does not own
                // that global atom. Revalidate it before accepting the alias:
                // a deleted and reused number cannot remove the old class.
                let (bytes, copied) = host.win16_global_get_atom_name(*atom, 256)?;
                if copied == 0 || usize::from(copied) > MAX_CLASS_NAME_BYTES { return Ok(None); }
                let bytes = bytes.get(..usize::from(copied)).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "host atom name count exceeds its copied bytes"))?;
                let lower = host.win16_ansi_lower_string(bytes)?;
                return Ok((self.window_classes.entries[index].lower_name.as_deref()
                    == Some(lower.as_slice())).then_some(index));
            }
        };
        // Cached predefined aliases and unrelated native classes are not in
        // this table. Guest name resemblance never grants native ownership.
        Ok(self.window_classes.entries.iter().position(|entry|
            entry.instance == owner && entry.lower_name.as_deref() == Some(lower.as_slice())))
    }
}

fn unresolved_callback_class(host: &mut impl RuntimeHost) -> u16 {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        "Win16 UnregisterClass cannot establish a retained callback's exact class identity; returned FALSE"));
    0
}
