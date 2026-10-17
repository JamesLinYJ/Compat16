//! Register-context entrypoints retain the complete architectural snapshot.

use super::*;
use crate::{Win16ExportAbiKind, Win16ExportStackCleanup, Win16RegisterContext};

/// Decode an export using the guest architectural context when its ABI
/// declares register-context arguments. Stack-based exports delegate to
/// `decode_export_call`; register-context exports never inspect Pascal stack
/// arguments, and the complete register snapshot remains in the request.
pub fn decode_export_call_with_register_context(
    descriptor: &Win16ExportDescriptor,
    frame: Win16CallFrame,
    register_context: Win16RegisterContext,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<DecodedWin16Call, Win16Error> {
    match descriptor.abi_kind {
        Win16ExportAbiKind::Stack => decode_export_call(descriptor, frame, selectors, memory),
        Win16ExportAbiKind::VariableStack if descriptor.id == Win16ExportId::UserWsprintf => {
            decode_export_call(descriptor, frame, selectors, memory)
        }
        Win16ExportAbiKind::VariableStack => Err(Win16Error::VariableStackRequiresSpecialDecoder),
        Win16ExportAbiKind::RegisterContext => {
            let request = match descriptor.id {
                Win16ExportId::Win87emFpMath => Win16ApiRequest::FpMath {
                    context: register_context,
                },
                Win16ExportId::KernelInitTask => Win16ApiRequest::InitTask { context: register_context },
                Win16ExportId::KernelSwitchStackBack => Win16ApiRequest::Kernel(
                    Win16KernelRequest::SwitchStackBack { context: register_context },
                ),
                Win16ExportId::UserKeybdEvent | Win16ExportId::UserMouseEvent => {
                    Win16ApiRequest::User(Win16UserRequest::Input(super::input_event::decode(
                        descriptor.id,
                        &register_context,
                    )))
                }
                _ => return Err(Win16Error::UnsupportedRegisterContextExport),
            };
            let stack_cleanup = match descriptor.stack_cleanup {
                Win16ExportStackCleanup::Fixed(cleanup) => cleanup,
                Win16ExportStackCleanup::Variable => {
                    return Err(Win16Error::VariableStackRequiresSpecialDecoder);
                }
            };
            Ok(DecodedWin16Call {
                export: descriptor.id,
                request,
                stack_cleanup,
            })
        }
    }
}
