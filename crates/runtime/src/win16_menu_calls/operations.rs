//! USER menu state, item, tracking, and output-buffer operations.

use win16_abi::Access;

use super::*;

impl Win16State {
    pub(super) fn begin_menu_operations(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16UserMenuRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16UserMenuRequest as Request;

        match request {
            Request::DestroyMenu { menu } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::Destroy { menu },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::CheckMenuItem { menu, item, flags } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(
                        registers,
                        return_to,
                        u32::from(u16::MAX),
                        return_kind,
                    );
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::CheckItem { menu, item, flags },
                    MenuCallKind::ItemFlags,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::EnableMenuItem { menu, item, flags } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(
                        registers,
                        return_to,
                        u32::from(u16::MAX),
                        return_kind,
                    );
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::EnableItem { menu, item, flags },
                    MenuCallKind::ItemFlags,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetSystemMenu { window, revert } => {
                let Some(&window) = self.window_handles.get(&window) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetSystemMenu {
                        window,
                        revert: revert != 0,
                    },
                    MenuCallKind::Handle,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenu { window } => {
                let Some(&window) = self.window_handles.get(&window) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenu { window },
                    MenuCallKind::Handle,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::HiliteMenuItem {
                window,
                menu,
                item,
                flags,
            } => {
                let Some(&window) = self.window_handles.get(&window) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::HiliteItem {
                        window,
                        menu,
                        item,
                        flags,
                    },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::EndMenu => self.submit_menu_call(
                registers,
                memory,
                host,
                Win16MenuOperation::EndMenu,
                MenuCallKind::Boolean,
                return_kind,
                None,
                return_to,
            ),
            Request::IsMenu { menu } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::IsMenu { menu },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenuItemID { menu, position } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(
                        registers,
                        return_to,
                        u32::from(u16::MAX),
                        return_kind,
                    );
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenuItemId { menu, position },
                    MenuCallKind::ItemId,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::SetSystemMenu { window, menu } => {
                let Some(&window) = self.window_handles.get(&window) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let menu = if menu == 0 {
                    None
                } else {
                    let Some(menu) = self.guest_menus.resolve(menu) else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    Some(menu)
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::SetSystemMenu { window, menu },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::SetMenuContextHelpId { menu, help_id } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::SetMenuContextHelpId { menu, help_id },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenuContextHelpId { menu } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenuContextHelpId { menu },
                    MenuCallKind::ContextHelpId,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenuCheckMarkDimensions => self.submit_menu_call(
                registers,
                memory,
                host,
                Win16MenuOperation::GetMenuCheckMarkDimensions,
                MenuCallKind::CheckMarkDimensions,
                return_kind,
                None,
                return_to,
            ),
            Request::MakeMenuRToL { menu, flags } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::MakeMenuRToL {
                        menu,
                        right_to_left: flags != 0,
                    },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenuItemRect {
                window,
                menu,
                item,
                rect,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                if rect == 0 {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                }
                let output_pointer = self
                    .selectors
                    .pointer_from_far(rect)
                    .map_err(crate::runtime_error)?;
                // RECT16 is a scalar structure: require the entire 8-byte
                // output to lie in one descriptor before capturing its
                // generation lease. GetMenuString uses a separate huge-range
                // contract and must not share this preflight.
                self.selectors
                    .translate(output_pointer, Access::Write, 8, memory)
                    .map_err(crate::runtime_error)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, output_pointer, 8,
                )?;
                let window = if window == 0 {
                    None
                } else {
                    let Some(&window) = self.window_handles.get(&window) else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    Some(window)
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenuItemRect { window, menu, item },
                    MenuCallKind::MenuRect,
                    return_kind,
                    Some(output),
                    return_to,
                )
            }
            Request::CheckMenuRadioItem {
                menu,
                first,
                last,
                check,
                by_position,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::CheckRadioItem {
                        menu,
                        first,
                        last,
                        check,
                        by_position: by_position != 0,
                    },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::ChangeMenu {
                menu,
                position,
                new_item,
                item_id,
                flags: action_flags,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                if action_flags & flags::MF_APPEND != 0 {
                    let Some(item) = self.prepare_menu_item(
                        item_id,
                        new_item,
                        action_flags & !flags::MF_APPEND,
                        memory,
                        host,
                    )?
                    else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    self.submit_menu_call(
                        registers,
                        memory,
                        host,
                        Win16MenuOperation::AppendMenu {
                            menu,
                            flags: action_flags & !flags::MF_APPEND,
                            item,
                        },
                        MenuCallKind::Boolean,
                        return_kind,
                        None,
                        return_to,
                    )
                } else if action_flags & flags::MF_DELETE != 0 {
                    self.submit_menu_call(
                        registers,
                        memory,
                        host,
                        Win16MenuOperation::DeleteMenu {
                            menu,
                            item: position,
                            flags: action_flags & !flags::MF_DELETE,
                        },
                        MenuCallKind::Boolean,
                        return_kind,
                        None,
                        return_to,
                    )
                } else if action_flags & flags::MF_CHANGE != 0 {
                    let item_flags = action_flags & !flags::MF_CHANGE;
                    let Some(item) =
                        self.prepare_menu_item(item_id, new_item, item_flags, memory, host)?
                    else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    self.submit_menu_call(
                        registers,
                        memory,
                        host,
                        Win16MenuOperation::ModifyMenu {
                            menu,
                            position,
                            flags: item_flags,
                            item,
                        },
                        MenuCallKind::Boolean,
                        return_kind,
                        None,
                        return_to,
                    )
                } else if action_flags & flags::MF_REMOVE != 0 {
                    let item = if action_flags & flags::MF_BYPOSITION != 0 {
                        position
                    } else {
                        item_id
                    };
                    self.submit_menu_call(
                        registers,
                        memory,
                        host,
                        Win16MenuOperation::RemoveMenu {
                            menu,
                            item,
                            flags: action_flags & !flags::MF_REMOVE,
                        },
                        MenuCallKind::Boolean,
                        return_kind,
                        None,
                        return_to,
                    )
                } else {
                    let Some(item) =
                        self.prepare_menu_item(item_id, new_item, action_flags, memory, host)?
                    else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    self.submit_menu_call(
                        registers,
                        memory,
                        host,
                        Win16MenuOperation::InsertMenu {
                            menu,
                            position: flags::insert_menu_native_position(position, action_flags),
                            flags: action_flags,
                            item,
                        },
                        MenuCallKind::Boolean,
                        return_kind,
                        None,
                        return_to,
                    )
                }
            }
            Request::GetSubMenu { menu, position } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetSubMenu { menu, position },
                    MenuCallKind::Handle,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::SetMenu { window, menu } => {
                let Some(&window) = self.window_handles.get(&window) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let menu = if menu == 0 {
                    None
                } else {
                    let Some(menu) = self.guest_menus.resolve(menu) else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    Some(menu)
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::SetMenu { window, menu },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::DrawMenuBar { window } => {
                let Some(&window) = self.window_handles.get(&window) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::DrawMenuBar { window },
                    MenuCallKind::Void,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenuString {
                menu,
                item,
                output,
                capacity,
                flags,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let capacity_usize = if capacity > 0 {
                    if output == 0 {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    }
                    let destination = self
                        .selectors
                        .pointer_from_far(output)
                        .map_err(crate::runtime_error)?;
                    let capacity = capacity as usize;
                    Some(super::super::guest_ranges::GuestOutputRange::capture(
                        self, memory, destination, capacity,
                    )?)
                } else {
                    None
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenuString {
                        menu,
                        item,
                        flags,
                        capacity,
                    },
                    MenuCallKind::MenuString,
                    return_kind,
                    capacity_usize,
                    return_to,
                )
            }
            Request::GetMenuState { menu, item, flags } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(
                        registers,
                        return_to,
                        u32::from(u16::MAX),
                        return_kind,
                    );
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenuState { menu, item, flags },
                    MenuCallKind::ItemFlags,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::GetMenuItemCount { menu } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(
                        registers,
                        return_to,
                        u32::from(u16::MAX),
                        return_kind,
                    );
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::GetMenuItemCount { menu },
                    MenuCallKind::ItemCount,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::InsertMenu {
                menu,
                position,
                flags,
                item_id,
                new_item,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let Some(item) = self.prepare_menu_item(item_id, new_item, flags, memory, host)?
                else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::InsertMenu {
                        menu,
                        position: flags::insert_menu_native_position(position, flags),
                        flags,
                        item,
                    },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::AppendMenu {
                menu,
                flags,
                item_id,
                new_item,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let Some(item) = self.prepare_menu_item(item_id, new_item, flags, memory, host)?
                else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::AppendMenu { menu, flags, item },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::ModifyMenu {
                menu,
                position,
                flags,
                item_id,
                new_item,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let Some(item) = self.prepare_menu_item(item_id, new_item, flags, memory, host)?
                else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::ModifyMenu {
                        menu,
                        position,
                        flags,
                        item,
                    },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::SetMenuItemBitmaps {
                menu,
                position,
                flags,
                unchecked,
                checked,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let unchecked = match self.menu_bitmap(unchecked, host) {
                    Some(bitmap) => bitmap,
                    None => return self.menu_immediate(registers, return_to, 0, return_kind),
                };
                let checked = match self.menu_bitmap(checked, host) {
                    Some(bitmap) => bitmap,
                    None => return self.menu_immediate(registers, return_to, 0, return_kind),
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::SetMenuItemBitmaps {
                        menu,
                        position,
                        flags,
                        unchecked,
                        checked,
                    },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::RemoveMenu { menu, item, flags } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::RemoveMenu { menu, item, flags },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::DeleteMenu { menu, item, flags } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::DeleteMenu { menu, item, flags },
                    MenuCallKind::Boolean,
                    return_kind,
                    None,
                    return_to,
                )
            }
            Request::TrackPopupMenu {
                menu,
                flags,
                x,
                y,
                reserved,
                window,
                rect,
            } => {
                let Some(menu) = self.guest_menus.resolve(menu) else {
                    return self.menu_immediate(registers, return_to, 0, return_kind);
                };
                let owner = if window == 0 {
                    None
                } else {
                    let Some(&owner) = self.window_handles.get(&window) else {
                        return self.menu_immediate(registers, return_to, 0, return_kind);
                    };
                    Some(owner)
                };
                let rect = self.read_menu_rect(rect, memory)?;
                self.submit_menu_call(
                    registers,
                    memory,
                    host,
                    Win16MenuOperation::TrackPopupMenu {
                        menu,
                        flags,
                        x,
                        y,
                        reserved,
                        owner,
                        rect,
                    },
                    MenuCallKind::Popup,
                    return_kind,
                    None,
                    return_to,
                )
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-menu Win16 request reached menu marshalling",
            )),
        }
    }
}
