//! Guest-registered SetClassLong(GCL_WNDPROC), without native class mutation.
//!
//! Windows 3.1 SDK Programmer's Reference Volume 1, section 1.2.10, applies
//! this replacement to the selected HWND and subsequently created windows;
//! existing siblings keep their own procedures. The returned LONG is the old
//! class FAR, which can differ from the selected HWND's displaced subclass.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn set_class_window_procedure(
        &mut self,
        window: u16,
        class: Win16HostClass,
        address: u32,
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        // This preflight is a runtime safety policy, not a claim about the
        // historical error code for every malformed Win16 callback pointer.
        if !self.valid_class_window_procedure(address, memory) { return Ok(0); }
        let Some(&native) = self.window_handles.get(&window) else { return Ok(0); };
        if window == 0 || self.window_host_class(window) != Some(class)
            || self.window_system_classes.contains_key(&window)
        {
            return Ok(0);
        }
        let Some(entry) = self.window_classes.entries.iter_mut()
            .find(|entry| entry.host_class == class) else { return Ok(0); };
        let Some(procedure) = self.window_procedures.get_mut(&window) else { return Ok(0); };
        if procedure.class != class { return Ok(0); }
        let Some(history) = self.window_data.get_mut(&window).and_then(|state|
            state.procedure_roots_for_owner_mut(native, class, procedure.instance))
        else { return Ok(0); };

        // The selected HWND history and class history have different owners.
        // Reserve both before publishing either root or changing either FAR.
        // No host operation or fallible work remains after preparation.
        replace_procedures(
            &mut entry.info.lpfn_wnd_proc,
            &mut entry.procedure_roots,
            &mut procedure.address,
            history,
            address,
            |roots| roots.try_reserve(1).map_err(|_| RuntimeError::new(
                Kind::ResourceExhausted, "Win16 class procedure history cannot grow")),
        )
    }

    fn valid_class_window_procedure(&self, address: u32, memory: &Memory) -> bool {
        if address == 0 { return false; }
        let selector = (address >> 16) as u16;
        // SelectorTable identifies descriptors by raw >> 3. RPL/TI aliases
        // must not turn service or callback-return gates into guest WNDPROCs.
        if selector & !7 == self.gate_selector.0 & !7
            || selector & !7 == self.callback_gate_selector.0 & !7
        {
            return false;
        }
        if self.owns_native_procedure_selector(selector)
            && self.native_procedure_for_address(address).is_none()
        {
            // Reject unpublished/stale slots, private pin selectors and OLE
            // gates. Only a published WNDPROC gate has the required ABI.
            return false;
        }
        self.selectors.pointer_from_far(address).ok().is_some_and(|pointer|
            self.selectors.translate(pointer, Access::Execute, 1, memory).is_ok())
    }
}

/// Allocation-failure injection covers the same transaction used by USER.132.
/// Capacity changes are harmless; neither logical history nor either current
/// address is modified unless all required reservations succeed.
fn replace_procedures(
    class_address: &mut u32,
    class_history: &mut Vec<u32>,
    window_address: &mut u32,
    window_history: &mut Vec<u32>,
    replacement: u32,
    mut reserve: impl FnMut(&mut Vec<u32>) -> Result<(), RuntimeError>,
) -> Result<u32, RuntimeError> {
    let old_class = *class_address;
    let old_window = *window_address;
    let retain_class = old_class != 0 && old_class != replacement
        && !class_history.contains(&old_class);
    let retain_window = old_window != 0 && old_window != replacement
        && !window_history.contains(&old_window);
    if retain_class { reserve(class_history)?; }
    if retain_window { reserve(window_history)?; }
    if retain_class { class_history.push(old_class); }
    if retain_window { window_history.push(old_window); }
    *class_address = replacement;
    *window_address = replacement;
    // These are raw FAR roots, like saved SetWindowLong chains. They retain
    // existing selector/FreeProcInstance limitations, not code-generation
    // leases. Active callbacks and pending creation snapshots are unchanged.
    Ok(old_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_data_procedure_reservation_failure_is_atomic_at_either_history() {
        for failure in [1, 2] {
            let mut class_address = 0x1234_0010;
            let mut window_address = 0x2345_0020;
            let mut class_history = vec![0x3456_0030];
            let mut window_history = vec![0x4567_0040];
            let mut calls = 0;
            let error = replace_procedures(&mut class_address, &mut class_history,
                &mut window_address, &mut window_history, 0x5678_0050, |roots| {
                    calls += 1;
                    if calls == failure {
                        return Err(RuntimeError::new(Kind::ResourceExhausted,
                            "injected procedure history reservation failure"));
                    }
                    roots.try_reserve(1).unwrap();
                    Ok(())
                }).unwrap_err();
            assert_eq!(error.kind(), Kind::ResourceExhausted);
            assert_eq!(calls, failure);
            assert_eq!(class_address, 0x1234_0010);
            assert_eq!(window_address, 0x2345_0020);
            assert_eq!(class_history, [0x3456_0030]);
            assert_eq!(window_history, [0x4567_0040]);
        }
    }

    #[test]
    fn class_data_procedure_deduplicated_histories_need_no_reservations() {
        let mut class_address = 0x1234_0010;
        let mut window_address = 0x2345_0020;
        let mut class_history = vec![class_address];
        let mut window_history = vec![window_address];
        assert_eq!(replace_procedures(&mut class_address, &mut class_history,
            &mut window_address, &mut window_history, 0x5678_0050,
            |_| panic!("already-rooted procedures cannot require allocation")).unwrap(),
            0x1234_0010);
        assert_eq!((class_address, window_address), (0x5678_0050, 0x5678_0050));
        assert_eq!(class_history, [0x1234_0010]);
        assert_eq!(window_history, [0x2345_0020]);
    }
}
