//! USER window request marshalling.

use super::*;

// WinUser.h's documented adjacent-window selectors accepted by GetNextWindow.
const GW_HWNDNEXT: u16 = 2;
const GW_HWNDPREV: u16 = 3;

impl Win16State {
    pub(super) fn begin_window_request(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16ApiRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16ApiRequest as Request;

        match request {
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetClassName {
                    window,
                    output,
                    capacity,
                },
            )) => {
                if capacity <= 0 {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                }
                let capacity = capacity as u16;
                let pointer =
                    self.checked_guest_range(output, usize::from(capacity), Access::Write, memory)?;
                let output_range = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, usize::from(capacity),
                )?;
                self.submit_call(
                    registers,
                    memory,
                    host,
                    Win16WindowCall::GetClassName {
                        window: self.native_window(window),
                        capacity,
                    },
                    Win16WindowCallOutput::ClassName { range: output_range, capacity },
                    return_to,
                    return_kind,
                    None,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::FindWindow {
                    class_name,
                    window_name,
                },
            )) => {
                let class_was_supplied = class_name.is_some();
                let class = self.find_window_class(class_name, host)?;
                if class_was_supplied && class.is_none() {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                }
                self.submit_value_call(
                    registers,
                    memory,
                    host,
                    Win16WindowCall::FindWindow {
                        class,
                        title: window_name,
                    },
                    return_to,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsIconic { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::IsIconic {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::EnableWindow { window, enable },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::EnableWindow {
                    window: self.native_window(window),
                    enable: enable != 0,
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsWindowEnabled { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::IsWindowEnabled {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::BringWindowToTop { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::BringWindowToTop {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetParent { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetParent {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsWindow { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::IsWindow {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsWindowVisible { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::IsWindowVisible {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::DestroyWindow { window },
            )) => self.submit_call(
                registers,
                memory,
                host,
                Win16WindowCall::DestroyWindow {
                    window: self.native_window(window),
                },
                Win16WindowCallOutput::None,
                return_to,
                return_kind,
                (window != 0).then_some(window),
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetActiveWindow { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::SetActiveWindow {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetActiveWindow,
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetActiveWindow,
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetWindow { window, command },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetWindow {
                    window: self.native_window(window),
                    command,
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetTopWindow { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetTopWindow {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetNextWindow { window, direction },
            )) => {
                let command = match direction {
                    GW_HWNDNEXT | GW_HWNDPREV => direction,
                    _ => {
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
                self.submit_value_call(
                    registers,
                    memory,
                    host,
                    Win16WindowCall::GetWindow {
                        window: self.native_window(window),
                        command,
                    },
                    return_to,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::ShowOwnedPopups { window, show },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::ShowOwnedPopups {
                    window: self.native_window(window),
                    show: show != 0,
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsZoomed { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::IsZoomed {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetDlgCtrlID { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetDlgCtrlId {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetDesktopWindow,
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetDesktopWindow,
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetLastActivePopup { window },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::GetLastActivePopup {
                    window: self.native_window(window),
                },
                return_to,
                return_kind,
            ),
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-window request reached the Win16 window-operation bridge",
            )),
        }
    }
}
