//! Runtime-side translation for the known Win16 common-control exports.

use guest_core::{memory::Memory, Registers};
use win16_abi::{Rect16, SegmentedPointer, Win16CommctrlRequest, Win16ReturnKind};

use super::{windows::WindowReturn, Win16State};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError,
    Win16HostCommonControlsOperation as Operation,
    RuntimeHost,
    Win16WindowOperation};

pub(super) struct Win16CommonControlsCall {
    pub operation: Operation,
    pub continuation: Win16CommonControlsContinuation,
}

pub(super) enum Win16CommonControlsPreparation {
    Immediate { value: u32, return_kind: Win16ReturnKind },
    WindowService(Win16CommonControlsCall),
}

pub(super) struct Win16CommonControlsContinuation {
    pub(super) return_kind: Win16ReturnKind,
    pub(super) output: Win16CommonControlsOutput,
}

pub(super) enum Win16CommonControlsOutput {
    Neutral,
    Boolean,
    Window,
    Rect(super::guest_ranges::GuestOutputRange),
    Profile { output: Option<(super::guest_ranges::GuestOutputRange, usize)> },
    /// The borrowed projection currently returns a typed gap for Close/String;
    /// no completion payload is retained until an owned follow-up stage exists.
    MenuHelpResolve {},
    MenuHelpApplied,
}

impl Win16State {
    pub(super) fn begin_common_controls_request(
        &mut self,
        request: Win16CommctrlRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match self.prepare_common_controls(memory, request, return_kind, host)? {
            Win16CommonControlsPreparation::Immediate { value, return_kind } => {
                self.complete_return(registers, return_to.0, return_to.1, return_to.2,
                    value, return_kind)
            }
            Win16CommonControlsPreparation::WindowService(call) => {
                self.begin_window_operation(registers, memory, host,
                    Win16WindowOperation::CommonControls(call.operation),
                    WindowReturn::CommonControls(call.continuation), return_to)
            }
        }
    }

    pub(super) fn prepare_common_controls(
        &mut self,
        memory: &Memory,
        request: Win16CommctrlRequest,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonControlsPreparation, RuntimeError> {
        let (operation, output) = match request {
            Win16CommctrlRequest::InitCommonControls => (Operation::Init, Win16CommonControlsOutput::Neutral),
            Win16CommctrlRequest::CreateStatusWindow { style, text, parent, control_id } => {
                let parent = if parent == 0 {
                    None
                } else {
                    let Some(parent) = self.window_handles.get(&parent).copied() else {
                        return Ok(Win16CommonControlsPreparation::Immediate {
                            value: 0, return_kind,
                        });
                    };
                    Some(parent)
                };
                (Operation::CreateStatusWindow {
                    style, text, parent, id: control_id,
                }, Win16CommonControlsOutput::Window)
            }
            Win16CommctrlRequest::CreateHeaderWindow { style, text, parent, control_id } => {
                let Some(parent) = self.window_handles.get(&parent).copied() else {
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                };
                (Operation::CreateHeaderWindow { style, text, parent, id: control_id },
                    Win16CommonControlsOutput::Window)
            }
            Win16CommctrlRequest::GetEffectiveClientRect { window, rect, control_ids } => {
                let Some(window) = self.window_handles.get(&window).copied() else {
                    return Ok(Win16CommonControlsPreparation::Immediate {
                        value: 0, return_kind,
                    });
                };
                if rect == 0 {
                    return Err(RuntimeError::new(Kind::GuestFault,
                        "Win16 GetEffectiveClientRect requires a writable RECT"));
                }
                let pointer = self.selectors.pointer_from_far(rect).map_err(crate::runtime_error)?;
                self.preflight_text_write(memory, pointer, Rect16::SIZE)?;
                let output = super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, Rect16::SIZE,
                )?;
                let layout_info = read_control_layout(self, memory, control_ids)?;
                (Operation::GetEffectiveClientRect { window, layout_info },
                    Win16CommonControlsOutput::Rect(output))
            }
            Win16CommctrlRequest::MakeDragList { list_box } => {
                let Some(native_list_box) = self.window_handles.get(&list_box).copied() else {
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                };
                (Operation::MakeDragList { list_box: native_list_box, guest_list_box: list_box },
                    Win16CommonControlsOutput::Boolean)
            }
            Win16CommctrlRequest::WritePrivateProfileStruct {
                section, key, data, data_size, file_name,
            } => {
                let data = if key.is_none() || data == 0 { None } else {
                    let pointer = self.selectors.pointer_from_far(data).map_err(crate::runtime_error)?;
                    Some(self.read_text_bytes(memory, pointer, usize::from(data_size))?)
                };
                (Operation::WritePrivateProfileStruct {
                    section, key, data, data_size, file_name,
                }, Win16CommonControlsOutput::Boolean)
            }
            Win16CommctrlRequest::GetPrivateProfileStruct {
                section, key, output, capacity, file_name,
            } => {
                if output == 0 {
                    return Ok(Win16CommonControlsPreparation::Immediate {
                        value: 0, return_kind,
                    });
                }
                let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
                self.preflight_text_write(memory, pointer, usize::from(capacity))?;
                let output = Some((super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, usize::from(capacity),
                )?, usize::from(capacity)));
                (Operation::GetPrivateProfileStruct {
                    section, key, capacity, file_name,
                }, Win16CommonControlsOutput::Profile { output })
            }
            Win16CommctrlRequest::MenuHelp {
                message, w_param, l_param, menu, instance, status_bar, help_id_table,
            } => {
                let Some(status_bar) = self.window_handles.get(&status_bar).copied() else {
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                };
                const WM_MENUSELECT: u16 = 0x011f;
                const WM_COMMAND: u16 = 0x0111;
                if message == WM_COMMAND {
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                }
                if message != WM_MENUSELECT {
                    report_common_controls_gap(host, "MenuHelp ignored an undocumented message value");
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                }
                let flags = l_param as u16;
                let selected_guest_menu = (l_param >> 16) as u16;
                if flags == u16::MAX && selected_guest_menu == 0 {
                    (Operation::MenuHelpApply { status_bar, simple: false, text: None },
                        Win16CommonControlsOutput::MenuHelpApplied)
                } else if flags & 0x0010 == 0 {
                    let (command_offset, _) = self.read_menu_help_offsets(memory, help_id_table)?;
                    let string_id = super::commctrl_menu_help::selected_help_id(
                        message, w_param, flags, command_offset,
                    );
                    let Some(string_id) = string_id.filter(|value| *value != 0) else {
                        return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                    };
                    let text = self.menu_help_string(instance, string_id)?;
                    (Operation::MenuHelpApply { status_bar, simple: true, text: Some(text) },
                        Win16CommonControlsOutput::MenuHelpApplied)
                } else {
                    let table = self.read_menu_help_table(memory, help_id_table)?;
                    let popup_ids = table.popup_ids;
                    (Operation::MenuHelpResolve {
                        message, w_param, flags,
                        main_menu: self.guest_menus.resolve(menu),
                        // Win16 WINDOWSX.H's FORWARD_WM_MENUSELECT places the selected
                        // popup HMENU in wParam when MF_POPUP is set; lParam's high
                        // word is the containing menu used by the close sentinel.
                        selected_menu: self.guest_menus.resolve(w_param),
                        status_bar,
                        command_id_offset: table.command_offset,
                        menu_id_offset: table.menu_offset,
                        popup_ids,
                    }, Win16CommonControlsOutput::MenuHelpResolve {})
                }
            }
            Win16CommctrlRequest::CreateToolbar {
                parent, style, control_id, bitmap_count, bitmap_instance, bitmap_resource,
                buttons, button_count, ..
            } => {
                let dimensions = (0, 0, 0, 0, 8);
                let Some(operation) = self.prepare_toolbar(memory, parent, style, control_id,
                    bitmap_count, bitmap_instance, bitmap_resource, buttons, button_count,
                    dimensions, host)? else {
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                };
                // The historical Win16 adapter adds the SDK's CCS_NODIVIDER bit
                // when implementing the non-Ex convenience wrapper.
                const CCS_NODIVIDER: u32 = 0x0040;
                let operation = match operation {
                    Operation::CreateToolbar { style, parent, id, bitmap_count, bitmap,
                        buttons, button_width, button_height, bitmap_width, bitmap_height,
                        guest_button_size } => Operation::CreateToolbar {
                            style: style | CCS_NODIVIDER, parent, id, bitmap_count, bitmap,
                            buttons, button_width, button_height, bitmap_width, bitmap_height,
                            guest_button_size,
                        },
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "CreateToolbar preparation returned a different operation")),
                };
                (operation, Win16CommonControlsOutput::Window)
            }
            Win16CommctrlRequest::CreateToolbarEx {
                parent, style, control_id, bitmap_count, bitmap_instance, bitmap_resource,
                buttons, button_count, button_width, button_height, bitmap_width, bitmap_height,
                button_struct_size,
            } => {
                let dimensions = (
                    i16::from_le_bytes(button_width.to_le_bytes()),
                    i16::from_le_bytes(button_height.to_le_bytes()),
                    i16::from_le_bytes(bitmap_width.to_le_bytes()),
                    i16::from_le_bytes(bitmap_height.to_le_bytes()),
                    button_struct_size,
                );
                let Some(operation) = self.prepare_toolbar(memory, parent, style, control_id,
                    bitmap_count, bitmap_instance, bitmap_resource, buttons, button_count,
                    dimensions, host)? else {
                    return Ok(Win16CommonControlsPreparation::Immediate { value: 0, return_kind });
                };
                (operation, Win16CommonControlsOutput::Window)
            }
            Win16CommctrlRequest::CreateMappedBitmap {
                instance, bitmap_resource, flags, color_map, color_map_count,
            } => {
                let bitmap = self.create_mapped_bitmap(memory, instance, bitmap_resource,
                    flags, color_map, color_map_count, host)?;
                return Ok(Win16CommonControlsPreparation::Immediate {
                    value: u32::from(bitmap), return_kind,
                });
            }
        };
        Ok(Win16CommonControlsPreparation::WindowService(Win16CommonControlsCall {
            operation,
            continuation: Win16CommonControlsContinuation { return_kind, output },
        }))
    }

}

fn report_common_controls_gap(host: &mut impl RuntimeHost, message: &'static str) {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, message));
}

fn read_control_layout(
    state: &Win16State,
    memory: &Memory,
    far: u32,
) -> Result<Vec<i32>, RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(Kind::GuestFault,
            "Win16 GetEffectiveClientRect requires a zero-terminated control table"));
    }
    let pointer = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
    let descriptor = state.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
    // The first menu pair is always ignored by GetEffectiveClientRect. Later
    // entries are flags/ID pairs, but a zero flags WORD is a standalone
    // terminator, so its following ID is neither read nor included. This
    // variable-length API has no count field; the selector limit bounds scans.
    let mut values = Vec::new();
    values.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 common-control layout table", error))?;
    values.push(i32::from(read_control_word(state, memory, pointer, descriptor.limit, 0)? as i16));
    values.push(i32::from(read_control_word(state, memory, pointer, descriptor.limit, 2)? as i16));

    let mut offset = 4_u32;
    loop {
        let flags = read_control_word(state, memory, pointer, descriptor.limit, offset)?;
        values.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "grow Win16 common-control layout table", error))?;
        values.push(i32::from(flags as i16));
        if flags == 0 { return Ok(values); }

        let id_offset = offset.checked_add(2).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 GetEffectiveClientRect table offset overflow"))?;
        let id = read_control_word(state, memory, pointer, descriptor.limit, id_offset)?;
        values.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "grow Win16 common-control layout table", error))?;
        values.push(i32::from(id));
        offset = offset.checked_add(4).ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 GetEffectiveClientRect table offset overflow"))?;
    }
}

fn read_control_word(
    state: &Win16State,
    memory: &Memory,
    base: SegmentedPointer,
    selector_limit: u32,
    byte_offset: u32,
) -> Result<u16, RuntimeError> {
    let first = u32::from(base.offset()).checked_add(byte_offset).ok_or_else(||
        RuntimeError::new(Kind::GuestFault, "Win16 GetEffectiveClientRect address overflow"))?;
    let last = first.checked_add(1).ok_or_else(|| RuntimeError::new(
        Kind::GuestFault, "Win16 GetEffectiveClientRect address overflow"))?;
    if last > selector_limit {
        return Err(RuntimeError::new(Kind::GuestFault,
            "Win16 GetEffectiveClientRect table has no complete WORD before its selector limit"));
    }
    let pointer = state.selectors.add_bytes(base, byte_offset).map_err(crate::runtime_error)?;
    let mut bytes = [0_u8; 2];
    state.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
    Ok(u16::from_le_bytes(bytes))
}
