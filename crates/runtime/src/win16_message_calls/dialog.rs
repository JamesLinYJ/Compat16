//! Dialog-item message entrypoints backed by the shared message codec.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn begin_dialog_item_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        dialog: u16,
        id: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        dialog_item_messages::begin(
            self, registers, memory, host, dialog, id, message, w_param, l_param, return_to,
        )
    }

}
