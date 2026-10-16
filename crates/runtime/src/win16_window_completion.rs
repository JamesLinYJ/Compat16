//! Completion and resource rollback for suspended native USER operations.

use super::*;

const WM_NCPAINT: u16 = 0x0085;

impl Win16State {
    pub(in crate::win16_runtime) fn retire_dialog_window(
        &mut self,
        native: Win16HostWindow,
    ) -> Result<(), RuntimeError> {
        if let Some(guest) = self.window_handles.iter().find_map(|(guest, existing)| {
            (*existing == native).then_some(*guest)
        }) {
            self.retire_window_tree(guest)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn window_code_references(&self) -> Vec<u32> {
        let mut references = Vec::new();
        references.extend(self.dde_code_references());
        for saved in self.dde_guest_contexts.iter().chain(&self.dde_context_restores) {
            if let Some((selector, offset)) = self.legacy_cpu_frame_saved_code(saved.cpu_owner) {
                references.push(guest_code_reference(selector, offset));
            }
        }
        references.extend(self.native_function_code_references());
        references.extend(self.window_procedures.values().map(|procedure| procedure.address));
        references.extend(self.dialog_procedures.values().filter_map(|(procedure, _)|
            (*procedure != 0).then_some(*procedure)));
        references.extend(self.window_procedure_roots());
        references.extend(self.timers.callback_addresses());
        for frame in &self.window_callbacks {
            references.push(guest_code_reference(frame.saved.cs, frame.saved.ip()));
            references.push(frame.callback_address);
        }
        for frame in &self.window_operations {
            references.push(guest_code_reference(frame.saved.cs, frame.saved.ip()));
            references.push(guest_code_reference(frame.return_to.0, frame.return_to.1));
            match frame.continuation() {
                Some(WindowReturn::Create { procedure, .. }) if procedure.address != 0 =>
                    references.push(procedure.address),
                Some(WindowReturn::PrepareNativeSubclass { replacement, .. }) =>
                    references.push(*replacement),
                Some(WindowReturn::NativeSubclass(change)) => {
                    references.push(change.replacement);
                    references.extend(change.previous);
                }
                Some(WindowReturn::WindowProperties(
                    super::super::window_properties::WindowPropertyReturn::Enum { procedure, .. },
                )) => references.push(*procedure),
                Some(WindowReturn::EnumMetafile { procedure, .. }) => references.push(*procedure),
                Some(WindowReturn::GrayString { procedure, .. }) if *procedure != 0 =>
                    references.push(*procedure),
                Some(WindowReturn::UserFamily(continuation)) => {
                    if let Some((procedure, _)) = continuation.pending_dialog_procedure() {
                        references.push(procedure);
                    }
                }
                _ => {}
            }
        }
        references
    }

    pub(in crate::win16_runtime) fn active_window_callback(
        &self,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    ) -> Option<Win16HostCallback> {
        self.active_window_message(window, message, w_param, l_param)
            .map(|source| source.callback)
    }

    pub(in crate::win16_runtime) fn active_guest_notification(
        &self,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    ) -> Option<crate::Win16GuestNotification> {
        let source = self.active_window_message(window, message, w_param, l_param)?;
        let notification = source.guest_notification?;
        match notification.target {
            crate::Win16GuestNotificationTarget::Window { window: target, guest_hwnd }
                if source.window == window
                    && self.window_handles.get(&guest_hwnd) == Some(&target)
                    && self.window_handles.get(&window) == Some(&target) => Some(notification),
            _ => None,
        }
    }

    pub(in crate::win16_runtime) fn active_window_message(
        &self,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    ) -> Option<ForwardedWindowMessage> {
        // Inspect only the innermost callback frame. Guest CallWindowProc can
        // explicitly carry a matching source into its own frame; unrelated
        // nested sends never search or inherit an older callback.
        let frame = self.window_callbacks.last()?;
        let source = match frame.continuation {
            WindowCallbackContinuation::Host { callback, native_window, window, .. }
            | WindowCallbackContinuation::HostDialog { callback, native_window, window, .. } => {
                ForwardedWindowMessage {
                    callback,
                    native_window,
                    window,
                    message: frame.payload.message,
                    w_param: frame.payload.w_param,
                    l_param: frame.payload.l_param,
                    guest_notification: frame.guest_notification,
                    class_root: frame.class_root,
                }
            }
            WindowCallbackContinuation::GuestProcedureCall {
                forwarded: Some(source),
            } => source,
            _ => return None,
        };
        let parameters_match = message == WM_NCPAINT
            || (source.w_param == w_param && source.l_param == l_param);
        (source.window == window
            && source.message == message
            && self.window_handles.get(&window) == Some(&source.native_window)
            && parameters_match)
            .then_some(source)
    }

}
