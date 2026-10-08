//! Project owned USER items through the existing Windows 3.1 wire codecs.

use guest_core::memory::Memory;
use win16_abi::owner_draw::{
    CompareItemStruct16, DeleteItemStruct16, DrawItemStruct16, MeasureItemStruct16,
};
use super::{Win16State, window_payloads::GuestWindowPayload};
use crate::{DiagnosticKind as Kind, RuntimeError,
    Win16OwnerDrawMessage as Item, Win16OwnerDrawTarget as Target};

impl Win16State {
    pub(super) fn prepare_owner_draw_payload(
        &mut self, item: Item, memory: &mut Memory,
    ) -> Result<GuestWindowPayload, RuntimeError> {
        let message = item.message_id();
        let w_param = item.control_id();
        let host_dc = item.callback_dc();
        let mut bytes = match item {
            Item::Draw { ctl_type, ctl_id, item_id, item_action, item_state,
                target, rect, item_data, .. } => {
                let hwnd_item = match target {
                    Target::Window(Some(window)) => self.map_window_handle(window, false)?,
                    Target::Menu(Some(menu)) => self.guest_menus.intern(menu).ok_or_else(||
                        RuntimeError::new(Kind::ResourceExhausted, "Win16 owner-draw HMENU table is full"))?,
                    Target::Window(None) | Target::Menu(None) => 0,
                };
                // RECT16 has signed WORD coordinates, as do the existing
                // USER geometry projections. No coordinate is an address.
                DrawItemStruct16 { ctl_type, ctl_id, item_id, item_action, item_state,
                    hwnd_item, hdc: 0, rc_item: win16_abi::Rect16 {
                        left: rect.left as i16, top: rect.top as i16,
                        right: rect.right as i16, bottom: rect.bottom as i16,
                    }, item_data }.encode().to_vec()
            }
            Item::Measure { ctl_type, ctl_id, item_id, width, height, item_data, .. } =>
                MeasureItemStruct16 { ctl_type, ctl_id, item_id,
                    item_width: width, item_height: height, item_data }.encode().to_vec(),
            Item::Delete { ctl_type, ctl_id, item_id, window, item_data, .. } => {
                let hwnd_item = match window {
                    Some(window) => self.map_window_handle(window, false)?, None => 0,
                };
                DeleteItemStruct16 { ctl_type, ctl_id, item_id, hwnd_item, item_data }.encode().to_vec()
            }
            Item::Compare { ctl_type, ctl_id, window, item_id1, item_data1, item_id2, item_data2, .. } => {
                let hwnd_item = match window {
                    Some(window) => self.map_window_handle(window, false)?, None => 0,
                };
                CompareItemStruct16 { ctl_type, ctl_id, hwnd_item,
                    item_id1, item_data1, item_id2, item_data2 }.encode().to_vec()
            }
        };
        // allocate_window_payload publishes its owner to a preparing callback
        // before locking/writing. Add the HDC lease to that same owner before
        // any selector operation can fail.
        let draw = if host_dc.is_some() {
            Some(DrawItemStruct16::decode(&bytes).map_err(crate::runtime_error)?)
        } else { None };
        let (allocation, pointer) = self.allocate_window_payload(memory, bytes.len())?;
        let callback_dc = if let Some(dc) = host_dc {
            let Some(guest_dc) = self.guest_gdi.allocate_dc(dc) else {
                return Err(self.cleanup_after_error(allocation, RuntimeError::new(
                    Kind::ResourceExhausted, "Win16 owner-draw HDC table is full")));
            };
            if self.preparing_window_callback_id().is_some() {
                self.window_callbacks.last_mut().expect("retained preparing callback")
                    .payload.callback_dc = Some((guest_dc, dc));
            }
            let mut draw = draw.expect("DRAWITEM payload encoded before HDC acquisition");
            draw.hdc = guest_dc;
            bytes.copy_from_slice(&draw.encode());
            Some((guest_dc, dc))
        } else { None };
        if let Err(error) = self.selectors.write(memory, pointer, &bytes).map_err(crate::runtime_error) {
            if self.preparing_window_callback_id().is_none()
                && let Some((guest, host)) = callback_dc
            { self.guest_gdi.forget_dc(guest, host); }
            return Err(self.cleanup_after_error(allocation, error));
        }
        Ok(GuestWindowPayload {
            message, w_param, l_param: pointer.far_value(), allocation: Some(allocation),
            output: (message == crate::win16_host_owner_draw::WM_MEASUREITEM)
                .then_some((pointer, MeasureItemStruct16::SIZE as u16)),
            callback_dc, command_control: None, command_parent: None, common_dialog_request: None,
        })
    }
}

/// Only the two documented MEASUREITEM outputs are transferred to the caller.
pub(super) fn measure_output_bytes(width: u16, height: u16) -> [u8; 4] {
    let bytes = MeasureItemStruct16 {
        item_width: width, item_height: height, ..MeasureItemStruct16::default()
    }.encode();
    let start = win16_abi::owner_draw::measure_item_struct16_offsets::ITEM_WIDTH;
    bytes[start..start + MeasureItemStruct16::OUTPUT_SIZE].try_into()
        .expect("fixed MEASUREITEM output width")
}

impl Win16State {
    pub(super) fn owner_draw_from_guest(
        &self, message: u16, control_id: u16, l_param: u32, memory: &Memory,
    ) -> Result<Option<Item>, RuntimeError> {
        use crate::win16_host_owner_draw as ids;
        let window = |guest: u16| if guest == 0 { Some(None) } else {
            self.window_handles.get(&guest).copied().map(Some)
        };
        let read = |size: usize| -> Result<Vec<u8>, RuntimeError> {
            let pointer = self.selectors.pointer_from_far(l_param).map_err(crate::runtime_error)?;
            let mut bytes = vec![0; size];
            self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
            Ok(bytes)
        };
        let item = match message {
            ids::WM_DRAWITEM => {
                let data = DrawItemStruct16::decode(&read(DrawItemStruct16::SIZE)?)
                    .map_err(crate::runtime_error)?;
                // SDK ODT_MENU = 1: the identically sized field carries HMENU,
                // while all control types use the HWND namespace.
                let target = if data.ctl_type == 1 {
                    Target::Menu(if data.hwnd_item == 0 { None } else {
                        let Some(menu) = self.guest_menus.resolve(data.hwnd_item) else { return Ok(None); };
                        Some(menu)
                    })
                } else {
                    let Some(window) = window(data.hwnd_item) else { return Ok(None); };
                    Target::Window(window)
                };
                let dc = if data.hdc == 0 { None } else {
                    let Some(dc) = self.guest_gdi.dc(data.hdc) else { return Ok(None); };
                    Some(dc)
                };
                Item::Draw { control_id, ctl_type: data.ctl_type, ctl_id: data.ctl_id,
                    item_id: data.item_id, item_action: data.item_action, item_state: data.item_state,
                    target, dc, rect: crate::Win16HostRect {
                        left: i32::from(data.rc_item.left), top: i32::from(data.rc_item.top),
                        right: i32::from(data.rc_item.right), bottom: i32::from(data.rc_item.bottom),
                    }, item_data: data.item_data }
            }
            ids::WM_MEASUREITEM => {
                let data = MeasureItemStruct16::decode(&read(MeasureItemStruct16::SIZE)?)
                    .map_err(crate::runtime_error)?;
                Item::Measure { control_id, ctl_type: data.ctl_type, ctl_id: data.ctl_id,
                    item_id: data.item_id, width: data.item_width, height: data.item_height,
                    item_data: data.item_data }
            }
            ids::WM_DELETEITEM => {
                let data = DeleteItemStruct16::decode(&read(DeleteItemStruct16::SIZE)?)
                    .map_err(crate::runtime_error)?;
                let Some(window) = window(data.hwnd_item) else { return Ok(None); };
                Item::Delete { control_id, ctl_type: data.ctl_type, ctl_id: data.ctl_id,
                    item_id: data.item_id, window, item_data: data.item_data }
            }
            ids::WM_COMPAREITEM => {
                let data = CompareItemStruct16::decode(&read(CompareItemStruct16::SIZE)?)
                    .map_err(crate::runtime_error)?;
                let Some(window) = window(data.hwnd_item) else { return Ok(None); };
                Item::Compare { control_id, ctl_type: data.ctl_type, ctl_id: data.ctl_id,
                    window, item_id1: data.item_id1, item_data1: data.item_data1,
                    item_id2: data.item_id2, item_data2: data.item_data2 }
            }
            _ => return Ok(None),
        };
        Ok(Some(item))
    }
}
