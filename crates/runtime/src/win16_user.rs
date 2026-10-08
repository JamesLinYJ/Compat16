//! USER task state initialization. Guest queues never contain native HWNDs.

use graphics::MessageQueue;
use guest_core::memory::Memory;
use formats::NeStringTable;
use win16_abi::Win16OutputBuffer;

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const DEFAULT_WIN16_MESSAGE_QUEUE_SIZE: usize = 8;

impl Win16State {
    pub(super) fn init_app(
        &mut self,
        instance: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(module_handle) = self.module_handle_for_instance(instance) else {
            return Ok(0);
        };
        let is_loaded_ne_module = self.modules.records.get(&module_handle)
            .is_some_and(|record| record.definition.is_some() && record.loaded.is_some());
        if !is_loaded_ne_module { return Ok(0); }
        let _ = self.ensure_user_queue(host)?;
        Ok(1)
    }

    pub(super) fn ensure_user_queue(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<crate::Win16HostTaskQueue>, RuntimeError> {
        if self.user_queue.is_none() {
            let mut queue = MessageQueue::new();
            queue.configure_limit(DEFAULT_WIN16_MESSAGE_QUEUE_SIZE).map_err(|error| {
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "initialize Win16 message queue", error)
            })?;
            self.user_queue = Some(queue);
        }

        // Bind lazily: during module load the guest HTASK selector may not
        // exist yet. The worker binds exactly the current OwnerId + HTASK
        // selector generation to its actual queue incarnation.
        host.win16_initialize_user_queue()?;
        let Some(owner) = self.tasks.current() else { return Ok(None); };
        let Some(task) = self.task_handles.get(&owner).copied() else { return Ok(None); };
        let Ok(reference) = self.selectors.reference(guest_core::Selector(task)) else {
            return Ok(None);
        };
        let generation = reference.generation();
        if let Some((bound_owner, bound_task, bound_generation, queue)) = self.user_task_queue
            && (bound_owner, bound_task, bound_generation) == (owner, task, generation)
        {
            return Ok(Some(queue));
        }
        let Some(queue) = host.win16_bind_task_queue(owner, task, generation)? else {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("Win16 USER task 0x{task:04X} has no separate bound native queue")));
            return Ok(None);
        };
        self.user_task_queue = Some((owner, task, generation, queue));
        Ok(Some(queue))
    }

    pub(super) fn set_message_queue(
        &mut self,
        message_count: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if message_count <= 0 { return Ok(0); }
        let _ = self.ensure_user_queue(host)?;
        // Win16 replaces its fixed-size queue. Pending guest messages in the
        // previous queue are discarded, including when allocation fails.
        self.user_queue.take();
        let mut queue = MessageQueue::new();
        match queue.configure_limit(message_count as usize) {
            Ok(true) => {
                self.user_queue = Some(queue);
                Ok(1)
            }
            Ok(false) => Ok(0),
            Err(error) => {
                host.report_diagnostic(&Diagnostic::warning(Kind::ResourceExhausted,
                    "Win16 SetMessageQueue could not allocate a replacement queue and returned failure")
                    .with_cause(error));
                Ok(0)
            }
        }
    }

    pub(super) fn load_string(
        &self,
        instance: u16,
        string_id: u16,
        output_buffer: Option<Win16OutputBuffer>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(module_handle) = self.module_handle_for_instance(instance) else {
            return Ok(0);
        };
        let Some(record) = self.modules.records.get(&module_handle) else { return Ok(0); };
        let Some(definition) = record.definition.as_ref() else { return Ok(0); };
        let resources = NeStringTable::from_module(&record.image, definition)
            .map_err(crate::runtime_error)?;
        let Some(bytes) = resources.get(string_id).map_err(crate::runtime_error)? else {
            return Ok(0);
        };
        let Some(output) = output_buffer else {
            // Win16's null-buffer form queries the stored string length.
            return Ok(bytes.len() as u32);
        };
        let capacity = usize::from(output.capacity);
        if capacity == 0 {
            return Ok(0);
        }
        let copied = bytes.len().min(capacity - 1);
        let mut result = Vec::new();
        result.try_reserve_exact(copied + 1).map_err(|_| RuntimeError::new(
            crate::DiagnosticKind::ResourceExhausted,
            "Win16 LoadString output allocation failed",
        ))?;
        result.extend_from_slice(&bytes[..copied]);
        result.push(0);
        self.write_output(memory, output, &result)?;
        Ok(copied as u32)
    }
}
