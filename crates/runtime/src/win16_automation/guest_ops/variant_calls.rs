use super::*;

pub(super) fn execute_variant_call(
    state: &mut Win16AutomationState,
    ordinal: u16,
    arguments: &[Arg],
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(AutomationInterfaceAction, u32) -> Result<(), RuntimeError>,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    match ordinal {
        8 => {
            let destination = guest_address(arguments, 0)?;
            variant::variant_init(destination, selectors, memory)?;
            Ok(Win16AutomationGuestResult::Void)
        }
        9 => {
            let source = guest_address(arguments, 0)?;
            let result = variant::variant_clear(
                state,
                source,
                heap,
                selectors,
                memory,
                owner,
                reject_interface,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        10 | 11 => {
            let destination = guest_address(arguments, 0)?;
            let source = guest_address(arguments, 1)?;
            let result = variant::variant_copy(
                state,
                destination,
                source,
                ordinal == 11,
                heap,
                selectors,
                memory,
                owner,
                reject_interface,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        _ => Err(unsupported_ordinal()),
    }
}
