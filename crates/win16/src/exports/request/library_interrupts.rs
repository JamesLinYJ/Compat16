//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16LibraryInterruptsRequest {
    /// TOOLHELP interrupt callback registration. `callback` retains the
    /// guest selector:offset pair for runtime validation and task ownership;
    /// it is never interpreted as a host function pointer.
    InterruptRegister { task_handle: u16, callback: u32 },

    /// Remove the callback registration associated with a Win16 task.
    InterruptUnregister { task_handle: u16 },
}
