//! Intel task-transfer routing and the task-switch commit sequence.

mod faults;
mod memory;
mod segments;
mod transfer;
mod wire;

pub(crate) use transfer::{
    execute_direct_tss, execute_task_gate, return_from_nested_task, switch_from_event_task_gate,
};
