//! Runtime request arms owned by the User service group.

use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::{Win16ApiRequest, Win16ExportDescriptor};

use super::Win16State;
use super::windows;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn dispatch_user(
        &mut self,
        request: Win16ApiRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        descriptor: &Win16ExportDescriptor,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (return_selector, return_offset, return_sp) = return_to;
        let value = match request {
            Win16ApiRequest::NetworkRedirector(request) => {
                u32::from(self.dispatch_network_redirector(request, memory, host)?)
            }
            request @ (Win16ApiRequest::User(win16_abi::Win16UserRequest::Mdi(_))
                | Win16ApiRequest::User(win16_abi::Win16UserRequest::ChildLookup(_))) => {
                return self.begin_window_api(registers, memory, host, request, return_to, descriptor.return_kind);
            }
            Win16ApiRequest::WindowData(request) => {
                return self.begin_window_data(
                    registers,
                    memory,
                    host,
                    request,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::ClassData(request) => self.access_class_data(request, memory, host)?,
            Win16ApiRequest::WindowProperties(request) => {
                return self.begin_window_properties(
                    registers,
                    memory,
                    host,
                    request,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::StringFormat(request)) => {
                self.write_output(memory, request.output, &request.bytes)?;
                u32::from(request.return_length)
            }
            Win16ApiRequest::DestroyImage(request) => self.destroy_guest_image(request, host)?,
            request @ (Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::PostMessage { .. }
                | win16_abi::Win16UserMessagesRequest::SendMessage { .. }
                | win16_abi::Win16UserMessagesRequest::SendDlgItemMessage { .. }
                | win16_abi::Win16UserMessagesRequest::WaitMessage
                | win16_abi::Win16UserMessagesRequest::PostAppMessage { .. }
                | win16_abi::Win16UserMessagesRequest::GetMessagePos
                | win16_abi::Win16UserMessagesRequest::GetMessageTime
                | win16_abi::Win16UserMessagesRequest::CallWindowProc { .. }
                | win16_abi::Win16UserMessagesRequest::GetKeyboardState { .. }
                | win16_abi::Win16UserMessagesRequest::SetKeyboardState { .. }
                | win16_abi::Win16UserMessagesRequest::GetQueueStatus { .. }
                | win16_abi::Win16UserMessagesRequest::GetInputState,
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetTimer { .. }
                | win16_abi::Win16UserWindowRequest::KillTimer { .. }
                | win16_abi::Win16UserWindowRequest::SetCapture { .. }
                | win16_abi::Win16UserWindowRequest::ReleaseCapture
                | win16_abi::Win16UserWindowRequest::SetFocus { .. }
                | win16_abi::Win16UserWindowRequest::GetFocus
                | win16_abi::Win16UserWindowRequest::GetCapture,
            ))) => {
                return self.begin_user_message_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                );
            }
            // Geometry requests share checked guest-memory marshalling and
            // return handling. Route the family together so new rectangle
            // helpers cannot be decoded but omitted from runtime dispatch.
            request @ (Win16ApiRequest::User(win16_abi::Win16UserRequest::Geometry(_))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::CreateCaret { .. }
                | win16_abi::Win16UserWindowRequest::DestroyCaret
                | win16_abi::Win16UserWindowRequest::SetCaretPos { .. }
                | win16_abi::Win16UserWindowRequest::HideCaret { .. }
                | win16_abi::Win16UserWindowRequest::ShowCaret { .. }
                | win16_abi::Win16UserWindowRequest::GetCaretPos { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetClassName { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::FindWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::CloseWindow { .. }
                | win16_abi::Win16UserWindowRequest::ArrangeIconicWindows { .. }
                | win16_abi::Win16UserWindowRequest::OpenIcon { .. }
                | win16_abi::Win16UserWindowRequest::IsIconic { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::EnableWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsWindowEnabled { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::BringWindowToTop { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetParent { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsWindowVisible { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::DestroyWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetActiveWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetActiveWindow,
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetTopWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetNextWindow { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::ShowOwnedPopups { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::IsZoomed { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetDlgCtrlID { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetDesktopWindow,
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetLastActivePopup { .. },
            ))) => {
                return self.begin_window_api(
                    registers,
                    memory,
                    host,
                    request,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::InitApp { instance },
            )) => self.init_app(instance, host)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::SetWindowText { window, text },
            )) => {
                return self.begin_set_window_text(
                    registers,
                    memory,
                    host,
                    window,
                    descriptor.return_kind,
                    text,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetWindowText {
                    window,
                    output,
                    count,
                },
            )) => {
                return self.begin_get_window_text(
                    registers,
                    memory,
                    host,
                    window,
                    output,
                    count,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetWindowTextLength { window },
            )) => {
                return self.begin_get_window_text_length(
                    registers,
                    memory,
                    host,
                    window,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::RegisterWindowMessage { name },
            )) => u32::from(host.win16_register_window_message(name.as_deref())?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Text(
                win16_abi::Win16UserTextRequest::RegisterClipboardFormat { name },
            )) => u32::from(host.win16_register_clipboard_format(name.as_deref())?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Text(
                win16_abi::Win16UserTextRequest::GetClipboardFormatName {
                    format,
                    output,
                    count,
                },
            )) => u32::from(self.clipboard_format_name(format, output, count, memory, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Resources(
                win16_abi::Win16UserResourcesRequest::LoadString {
                    instance,
                    string_id,
                    output_buffer,
                },
            )) => self.load_string(instance, string_id, output_buffer, memory)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Resources(
                win16_abi::Win16UserResourcesRequest::LoadBitmap { instance, name },
            )) => u32::from(self.load_bitmap(instance, name, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Resources(
                win16_abi::Win16UserResourcesRequest::LoadIcon { instance, name },
            )) => u32::from(self.load_icon(instance, name, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Resources(
                win16_abi::Win16UserResourcesRequest::LoadCursor { instance, name },
            )) => u32::from(self.load_cursor(instance, name, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Resources(
                request @ (win16_abi::Win16UserResourcesRequest::CreateIcon { .. }
                    | win16_abi::Win16UserResourcesRequest::CreateCursor { .. }),
            )) => u32::from(self.create_image_masks(request, memory, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::SetMessageQueue { message_count },
            )) => u32::from(self.set_message_queue(message_count, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::GetMessage {
                    output,
                    window,
                    min_message,
                    max_message,
                },
            )) => {
                return self.begin_get_message(
                    registers,
                    memory,
                    host,
                    output,
                    window,
                    min_message,
                    max_message,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::PeekMessage {
                    output,
                    window,
                    min_message,
                    max_message,
                    flags,
                },
            )) => {
                return self.begin_peek_message(
                    registers,
                    memory,
                    host,
                    output,
                    window,
                    min_message,
                    max_message,
                    flags,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::TranslateMessage { message },
            )) => {
                return self.begin_translate_message(
                    registers,
                    memory,
                    host,
                    message,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::DispatchMessage { message },
            )) => {
                return self.begin_dispatch_message(
                    registers,
                    memory,
                    host,
                    message,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::PostQuitMessage { exit_code },
            )) => {
                return self.begin_post_quit_message(
                    registers,
                    memory,
                    host,
                    exit_code,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Menu(
                request @ (win16_abi::Win16UserMenuRequest::CreateMenu
                | win16_abi::Win16UserMenuRequest::CreatePopupMenu
                | win16_abi::Win16UserMenuRequest::LoadMenu { .. }
                | win16_abi::Win16UserMenuRequest::LoadMenuIndirect { .. }
                | win16_abi::Win16UserMenuRequest::ChangeMenu { .. }
                | win16_abi::Win16UserMenuRequest::HiliteMenuItem { .. }
                | win16_abi::Win16UserMenuRequest::EndMenu
                | win16_abi::Win16UserMenuRequest::GetMenuItemID { .. }
                | win16_abi::Win16UserMenuRequest::SetSystemMenu { .. }
                | win16_abi::Win16UserMenuRequest::IsMenu { .. }
                | win16_abi::Win16UserMenuRequest::SetMenuContextHelpId { .. }
                | win16_abi::Win16UserMenuRequest::GetMenuContextHelpId { .. }
                | win16_abi::Win16UserMenuRequest::ModifyMenu { .. }
                | win16_abi::Win16UserMenuRequest::GetMenuCheckMarkDimensions
                | win16_abi::Win16UserMenuRequest::SetMenuItemBitmaps { .. }
                | win16_abi::Win16UserMenuRequest::MakeMenuRToL { .. }
                | win16_abi::Win16UserMenuRequest::GetMenuItemRect { .. }
                | win16_abi::Win16UserMenuRequest::CheckMenuRadioItem { .. }
                | win16_abi::Win16UserMenuRequest::DestroyMenu { .. }
                | win16_abi::Win16UserMenuRequest::CheckMenuItem { .. }
                | win16_abi::Win16UserMenuRequest::EnableMenuItem { .. }
                | win16_abi::Win16UserMenuRequest::GetSystemMenu { .. }
                | win16_abi::Win16UserMenuRequest::GetMenu { .. }
                | win16_abi::Win16UserMenuRequest::GetSubMenu { .. }
                | win16_abi::Win16UserMenuRequest::SetMenu { .. }
                | win16_abi::Win16UserMenuRequest::DrawMenuBar { .. }
                | win16_abi::Win16UserMenuRequest::GetMenuString { .. }
                | win16_abi::Win16UserMenuRequest::GetMenuState { .. }
                | win16_abi::Win16UserMenuRequest::GetMenuItemCount { .. }
                | win16_abi::Win16UserMenuRequest::InsertMenu { .. }
                | win16_abi::Win16UserMenuRequest::AppendMenu { .. }
                | win16_abi::Win16UserMenuRequest::RemoveMenu { .. }
                | win16_abi::Win16UserMenuRequest::DeleteMenu { .. }
                | win16_abi::Win16UserMenuRequest::TrackPopupMenu { .. }),
            )) => {
                return self.begin_menu_api(
                    registers,
                    memory,
                    host,
                    request,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Atoms(
                win16_abi::Win16UserAtomsRequest::GlobalAddAtom { name },
            )) => u32::from(self.global_add_atom(name, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Atoms(
                win16_abi::Win16UserAtomsRequest::GlobalDeleteAtom { atom },
            )) => u32::from(if self.is_registered_class_atom(atom) {
                atom
            } else {
                // GlobalDeleteAtom has no guest failure sentinel: keep its
                // zero return, but retain a diagnostic for a native failure.
                match host.win16_global_delete_atom(atom) {
                    Ok(()) => {}
                    Err(error) if error.kind() == Kind::HostFailure => {
                        host.report_diagnostic(&crate::Diagnostic::warning(
                            Kind::HostFailure, error.to_string(),
                        ));
                    }
                    Err(error) => return Err(error),
                }
                0
            }),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Atoms(
                win16_abi::Win16UserAtomsRequest::GlobalFindAtom { name },
            )) => u32::from(self.global_find_atom(name, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Atoms(
                win16_abi::Win16UserAtomsRequest::GlobalGetAtomName {
                    atom,
                    output_buffer,
                },
            )) => u32::from(self.global_get_atom_name(atom, output_buffer, memory, host)?),
            request @ (Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::FillRect { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::InvertRect { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::FrameRect { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::DrawIcon { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::DrawFocusRect { .. },
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::DrawText { .. },
            ))) => self.user_service_drawing(request, memory, host)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetDc { window },
            )) => {
                return self.begin_user_get_dc(
                    registers,
                    memory,
                    host,
                    window,
                    false,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetWindowDc { window },
            )) => {
                return self.begin_user_get_dc(
                    registers,
                    memory,
                    host,
                    window,
                    true,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::ReleaseDc { window, dc },
            )) => {
                return self.begin_user_release_dc(
                    registers,
                    memory,
                    host,
                    window,
                    dc,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::BeginPaint { window, paint },
            )) => {
                return self.begin_paint(
                    registers,
                    memory,
                    host,
                    window,
                    paint,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::EndPaint { window, paint },
            )) => {
                return self.begin_end_paint(
                    registers,
                    memory,
                    host,
                    window,
                    paint,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Ansi(
                win16_abi::Win16UserAnsiRequest::ClassifyCharacter { value, classification },
            )) => u32::from(host.win16_classify_character(value, classification)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Ansi(
                win16_abi::Win16UserAnsiRequest::AnsiLower { target },
            )) => self.ansi_case(target, false, memory, host)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Ansi(
                win16_abi::Win16UserAnsiRequest::AnsiUpper { target },
            )) => self.ansi_case(target, true, memory, host)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Ansi(
                win16_abi::Win16UserAnsiRequest::AnsiCaseBuffer {
                    pointer,
                    length,
                    upper,
                },
            )) => u32::from(self.ansi_case_buffer(pointer, length, upper, memory, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Ansi(
                win16_abi::Win16UserAnsiRequest::AnsiNext { pointer },
            )) => self.ansi_next(pointer, memory, host)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Ansi(
                win16_abi::Win16UserAnsiRequest::AnsiPrev { start, current },
            )) => self.ansi_prev(start, current, memory, host)?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::GetClassInfo {
                    instance,
                    class_name,
                    class_info,
                },
            )) => u32::from(self.get_class_info(instance, class_name, class_info, memory, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::RegisterClass {
                    window_class,
                    class_name,
                    menu_name,
                },
            )) => {
                u32::from(self.register_class(window_class, class_name, menu_name, memory, host)?)
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::UnregisterClass { class_name, instance },
            )) => u32::from(self.unregister_class(instance, class_name, host)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::CreateWindow {
                    class_name,
                    window_name,
                    ex_style,
                    style,
                    x,
                    y,
                    width,
                    height,
                    parent,
                    menu,
                    instance,
                    parameter,
                },
            )) => {
                return self.begin_create_window(
                    registers,
                    memory,
                    host,
                    windows::WindowCreateRequest {
                        class_name,
                        window_name,
                        ex_style,
                        style,
                        x,
                        y,
                        width,
                        height,
                        parent,
                        menu,
                        instance,
                        parameter,
                    },
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Window(
                win16_abi::Win16UserWindowRequest::ShowWindow { window, command },
            )) => {
                return self.begin_show_window(
                    registers,
                    memory,
                    host,
                    window,
                    command,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Messages(
                win16_abi::Win16UserMessagesRequest::DefWindowProc {
                    window,
                    message,
                    w_param,
                    l_param,
                },
            )) => {
                return self.begin_def_window_proc(
                    registers,
                    window,
                    message,
                    w_param,
                    l_param,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Text(
                win16_abi::Win16UserTextRequest::MessageBox {
                    owner,
                    text,
                    caption,
                    style,
                },
            )) => {
                return self.begin_user_message_box(
                    registers,
                    memory,
                    host,
                    owner,
                    text,
                    caption,
                    style,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::WNetGetCaps { index },
            )) => u32::from(host.win16_wnet_get_caps(index)?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::GetTickCount,
            ))
            | Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::GetCurrentTime,
            )) => host.win16_get_tick_count()?,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::MessageBeep { beep_type },
            )) => u32::from(host.win16_message_beep(u32::from(beep_type))?),
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::GetKeyState { virtual_key },
            )) => host.win16_get_key_state(i32::from(virtual_key), false)? as u16 as u32,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::GetAsyncKeyState { virtual_key },
            )) => host.win16_get_key_state(i32::from(virtual_key), true)? as u16 as u32,
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Runtime(
                win16_abi::Win16UserRuntimeRequest::GetSystemMetrics { index },
            )) => host.win16_get_system_metrics(i32::from(index))? as u16 as u32,
            Win16ApiRequest::UserSystem(request) => {
                super::user_services_system::dispatch(request, host)?
            }
            Win16ApiRequest::UserFamily(request) => {
                return self.begin_user_family_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::UserUpdate(request) => {
                return self.begin_user_update_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::UserScrollBar(request) => {
                return self.begin_scroll_bar_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::UserCursorAccelerator(request) => {
                return self.begin_user_cursor_accelerator(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                );
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 request reached a dispatch group that does not own it",
                ));
            }
        };
        self.complete_return(
            registers,
            return_selector,
            return_offset,
            return_sp,
            value,
            descriptor.return_kind,
        )
    }
}

#[cfg(test)]
#[path = "win16_dispatch_geometry_tests.rs"]
mod geometry_tests;

#[cfg(test)]
#[path = "win16_dispatch_map_window_points_tests.rs"]
mod map_window_points_tests;

#[cfg(test)]
#[path = "win16_dispatch_caret_tests.rs"]
mod caret_tests;

#[cfg(test)]
#[path = "win16_dispatch_child_lookup_tests.rs"]
mod child_lookup_tests;

#[cfg(test)]
#[path = "win16_dispatch_set_window_pos_tests.rs"]
mod set_window_pos_tests;

#[cfg(test)]
#[path = "win16_dispatch_get_clip_cursor_tests.rs"]
mod get_clip_cursor_tests;

#[cfg(test)]
#[path = "win16_dispatch_get_cursor_tests.rs"]
mod get_cursor_tests;

#[cfg(test)]
#[path = "win16_dispatch_character_classification_tests.rs"]
mod character_classification_tests;
