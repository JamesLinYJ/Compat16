//! Win16 USER MDI frame and message translation calls.

use super::*;

impl Win16State {
    /// Handle USER.445, USER.447, and USER.451 with opaque native window identities.
    pub(super) fn begin_user_mdi(
        &mut self,
        request: win16_abi::Win16UserMdiRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use win16_abi::Win16UserMdiRequest as Request;

        match request {
            Request::DefFrameProc {
                frame,
                mdi_client,
                message,
                w_param,
                l_param,
            } => {
                let frame_native = match self.native_window(frame) {
                    Win16WindowTarget::Mapped(window) => window,
                    Win16WindowTarget::Null | Win16WindowTarget::Invalid => {
                        return self.complete_return(
                            registers,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            0,
                            return_kind,
                        );
                    }
                };
                let mdi_client_native = match self.native_window(mdi_client) {
                    Win16WindowTarget::Mapped(window) => Some(window),
                    Win16WindowTarget::Null => None,
                    Win16WindowTarget::Invalid => {
                        return self.complete_return(
                            registers,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            0,
                            return_kind,
                        );
                    }
                };

                // MDI messages use the explicitly supplied MDI client only
                // when it is a live MdiClient system-class alias. Other
                // messages share the complete DefWindowProc translator.
                let translated = if super::super::messages_mdi::is_mdi_message(message) {
                    if let Some(native) = mdi_client_native {
                        // `translate_mdi_message` rechecks this native token
                        // against the runtime's exact guest HWND alias.
                        self.translate_mdi_message(
                            crate::Win16MdiEndpoint::Client,
                            Some((mdi_client, native)),
                            message,
                            w_param,
                            l_param,
                            memory,
                            host,
                        )?
                    } else {
                        None
                    }
                } else {
                    self.translate_window_message(
                        frame, message, w_param, l_param, memory, host, false,
                    )?
                };
                let Some((translated, output)) = translated else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                };
                let callback = self.active_window_callback(frame, message, w_param, l_param);
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::DefFrameProc {
                        frame: frame_native,
                        mdi_client: mdi_client_native,
                        callback,
                        message: translated,
                    },
                    WindowReturn::Message { output },
                    return_to,
                )
            }
            Request::DefMDIChildProc {
                window,
                message,
                w_param,
                l_param,
            } => {
                let Win16WindowTarget::Mapped(child_native) = self.native_window(window) else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                };
                // Child MDI semantics are available only through this
                // explicit API context; the general translator never guesses
                // a child endpoint from WM_MDIACTIVATE or another message ID.
                let translated = if super::super::messages_mdi::is_mdi_message(message) {
                    self.translate_mdi_message(
                        crate::Win16MdiEndpoint::Child(child_native),
                        None,
                        message,
                        w_param,
                        l_param,
                        memory,
                        host,
                    )?
                } else {
                    self.translate_window_message(
                        window, message, w_param, l_param, memory, host, false,
                    )?
                };
                let Some((translated, output)) = translated else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                };
                let callback = self.active_window_callback(window, message, w_param, l_param);
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::DefaultMdiChild {
                        window: child_native,
                        callback,
                        message: translated,
                    },
                    WindowReturn::Message { output },
                    return_to,
                )
            }
            Request::TranslateMDISysAccel {
                mdi_client,
                message,
            } => {
                let Win16WindowTarget::Mapped(mdi_client_native) = self.native_window(mdi_client)
                else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                };
                let message_window = if message.hwnd == 0 {
                    None
                } else if let Some(window) = self.window_handles.get(&message.hwnd).copied() {
                    Some(window)
                } else {
                    host.report_diagnostic(&crate::Diagnostic::warning(
                        Kind::CompatibilityGap,
                        format!(
                            "Win16 MDI MSG HWND 0x{:04X} is not mapped; message was not translated",
                            message.hwnd,
                        ),
                    ));
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                };
                let queued = crate::Win16HostQueuedMessage {
                    source: crate::Win16MessageSource::GuestMessage,
                    window: message_window,
                    message: message.message,
                    w_param: message.w_param,
                    // TranslateMDISysAccel interprets keyboard message fields;
                    // LPARAM remains numeric Win16 bits and is never a pointer.
                    l_param: crate::Win16MessageParam::GuestBits(message.l_param),
                    time: message.time,
                    point: Win16HostPoint {
                        x: i32::from(message.pt.x),
                        y: i32::from(message.pt.y),
                    },
                };
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::TranslateMDISysAccel {
                        mdi_client: mdi_client_native,
                        message: queued,
                    },
                    // This operation has the same BOOL/WORD result contract
                    // as TranslateMessage and shares its checked completion.
                    WindowReturn::TranslateMessage,
                    return_to,
                )
            }
        }
    }
}
