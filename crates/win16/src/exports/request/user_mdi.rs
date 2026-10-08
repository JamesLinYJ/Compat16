//! Owned request values for the Win16 USER MDI family.

use super::super::*;

/// Win16 USER APIs that operate on MDI windows or a guest MSG16.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserMdiRequest {
    /// Invoke USER.445 with the original Win16 window/message fields.
    /// `l_param` remains guest bits; message-specific structures are copied
    /// only by the shared USER message translator in the runtime.
    DefFrameProc {
        frame: u16,
        mdi_client: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    /// Invoke USER.447 for an MDI child with the original Win16 message fields.
    /// `l_param` remains guest bits until shared USER message translation.
    DefMDIChildProc {
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
    },

    /// Test a checked copy of the guest MSG16 for an MDI system accelerator.
    TranslateMDISysAccel {
        mdi_client: u16,
        message: Msg16,
    },
}
