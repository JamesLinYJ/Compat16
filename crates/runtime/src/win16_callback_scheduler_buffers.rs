//! Guest callback buffer allocation and independent retained-owner retry.

use std::sync::Arc;

use guest_core::{memory::Memory, OwnerId};
use win16_abi::{AllocationFlags, Win16Error};

use super::{CallbackBuffer, Win16State, MAX_GUEST_CALLBACK_BUFFER};
use super::super::global_memory::GlobalTeardownResult;
use crate::{DiagnosticKind as Kind, RuntimeError};

const CALLBACK_BUFFER_OWNER: OwnerId = OwnerId(1);

impl Win16State {
    pub(in crate::win16_runtime) fn reserve_retained_callback_buffer_capacity(
        &mut self,
        new_buffers: usize,
    ) -> Result<(), RuntimeError> {
        let active = self.callback_scheduler.active.iter()
            .flat_map(|frame| frame.buffers.iter())
            .filter(|buffer| buffer.allocation.is_some()).count();
        let pending = self.callback_scheduler.pending_cleanup.iter()
            .flat_map(|frame| frame.buffers.iter())
            .filter(|buffer| buffer.allocation.is_some()).count();
        let active_toolhelp = self.toolhelp_notify_frames.iter().try_fold(
            0usize,
            |count, frame| count.checked_add(frame.retained_payload_buffer_count()),
        ).ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
            "ToolHelp callback buffer owner count overflowed"))?;
        let retained = self.callback_scheduler.retained_buffers.len();
        let required = retained.checked_add(active).and_then(|count| count.checked_add(pending))
            .and_then(|count| count.checked_add(active_toolhelp))
            .and_then(|count| count.checked_add(new_buffers)).ok_or_else(||
                RuntimeError::new(Kind::ResourceExhausted,
                    "asynchronous callback buffer owner count overflowed"))?;
        self.callback_scheduler.retained_buffers.try_reserve(
            required.saturating_sub(retained),
        ).map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
            "reserve retained asynchronous callback buffer owners before allocation", error))
    }

    pub(in crate::win16_runtime) fn allocate_callback_buffer(
        &mut self,
        memory: &mut Memory,
        bytes: &[u8],
    ) -> Result<(CallbackBuffer, u32, u32), (RuntimeError, Option<CallbackBuffer>)> {
        if bytes.len() > MAX_GUEST_CALLBACK_BUFFER {
            return Err((RuntimeError::new(Kind::ResourceExhausted,
                "asynchronous callback buffer exceeds one Win16 selector extent"), None));
        }
        let length = bytes.len().max(1);
        let size = u32::try_from(length).map_err(|error| (RuntimeError::with_source(
            Kind::ResourceExhausted, "callback buffer length exceeds the Win16 heap limit", error), None))?;
        let allocation = self.heap.alloc(memory, CALLBACK_BUFFER_OWNER, size,
            AllocationFlags::fixed().with_zero_init()).map_err(|error| {
                let error = match error {
                    Win16Error::OutOfMemory | Win16Error::HandleTableFull => RuntimeError::new(
                        Kind::ResourceExhausted,
                        "Win16 heap cannot allocate an asynchronous callback buffer"),
                    other => crate::runtime_error(other),
                };
                (error, None)
            })?;
        let pointer = match self.heap.lock(allocation, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Err((crate::runtime_error(error), Some(CallbackBuffer {
                allocation: Some(allocation), ..CallbackBuffer::default()
            }))),
        };
        if let Err(error) = self.selectors.write(memory, pointer, bytes) {
            return Err((crate::runtime_error(error), Some(CallbackBuffer {
                allocation: Some(allocation), locked: true, ..CallbackBuffer::default()
            })));
        }
        Ok((CallbackBuffer { allocation: Some(allocation), locked: true,
            ..CallbackBuffer::default() }, pointer.far_value(), length as u32))
    }

    pub(in crate::win16_runtime) fn release_callback_buffers(
        &mut self,
        buffers: &mut Vec<CallbackBuffer>,
    ) -> Result<(), RuntimeError> {
        let mut failure = None;
        for index in (0..buffers.len()).rev() {
            if buffers[index].allocation.is_none() { continue; }
            let mut buffer = std::mem::take(&mut buffers[index]);
            let Some(allocation) = buffer.allocation else { continue; };
            if buffer.locked {
                let unlock = {
                    let mut access = self.global_memory_teardown_access();
                    let (heap, selectors) = access.heap_and_selectors_mut();
                    heap.unlock(allocation, selectors)
                };
                if let Err(error) = unlock {
                    let report = buffer.remember_error(crate::runtime_error(error));
                    self.retain_callback_buffer(index, buffers, buffer, &mut failure, Some(report));
                    continue;
                }
                buffer.locked = false;
            }
            match self.free_runtime_global_on_teardown(allocation) {
                Ok(GlobalTeardownResult::Freed) => buffer.allocation = None,
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    if let Some(error) = buffer.remember_retained(retained) {
                        self.retain_callback_buffer(index, buffers, buffer,
                            &mut failure, Some(error));
                    } else {
                        self.retain_callback_buffer(index, buffers, buffer, &mut failure, None);
                    }
                }
                Err(error) => {
                    let report = buffer.remember_error(error);
                    self.retain_callback_buffer(index, buffers, buffer, &mut failure, Some(report));
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn retain_callback_buffer(
        &mut self,
        index: usize,
        buffers: &mut [CallbackBuffer],
        buffer: CallbackBuffer,
        failure: &mut Option<RuntimeError>,
        error: Option<RuntimeError>,
    ) {
        if self.callback_scheduler.retained_buffers.len()
            < self.callback_scheduler.retained_buffers.capacity()
        {
            self.callback_scheduler.retained_buffers.push(buffer);
            if let Some(error) = error {
                remember_failure(failure, error);
            }
        } else {
            buffers[index] = buffer;
            remember_failure(failure, RuntimeError::new(Kind::InternalInvariant,
                "callback buffer owner reservation was exhausted before retirement"));
        }
    }

    pub(in crate::win16_runtime) fn retry_retained_callback_buffers(&mut self) -> Result<(), RuntimeError> {
        let mut failure = None;
        let count = self.callback_scheduler.retained_buffers.len();
        for _ in 0..count {
            let mut buffer = self.callback_scheduler.retained_buffers.remove(0);
            let Some(allocation) = buffer.allocation else { continue; };
            if buffer.locked {
                let unlock = {
                    let mut access = self.global_memory_teardown_access();
                    let (heap, selectors) = access.heap_and_selectors_mut();
                    heap.unlock(allocation, selectors)
                };
                if let Err(error) = unlock {
                    let report = buffer.remember_error(crate::runtime_error(error));
                    remember_failure(&mut failure, report);
                    self.callback_scheduler.retained_buffers.push(buffer);
                    continue;
                }
                buffer.locked = false;
            }
            match self.free_runtime_global_on_teardown(allocation) {
                Ok(GlobalTeardownResult::Freed) => {}
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    let report = buffer.remember_retained(retained).unwrap_or_else(||
                        retained.retained_error("asynchronous callback buffer")
                            .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                                "retained callback buffer lost its diagnostic")));
                    remember_failure(&mut failure, report);
                    self.callback_scheduler.retained_buffers.push(buffer);
                }
                Err(error) => {
                    let report = buffer.remember_error(error);
                    remember_failure(&mut failure, report);
                    self.callback_scheduler.retained_buffers.push(buffer);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl CallbackBuffer {
    fn remember_retained(&mut self, result: GlobalTeardownResult) -> Option<RuntimeError> {
        self.retained = Some(result);
        let cause = self.first_failure.clone()?;
        let retry = result.retained_error("asynchronous callback buffer")?;
        Some(RuntimeError::with_source(cause.kind(),
            "asynchronous callback buffer retains its first typed cleanup cause", cause)
            .with_cleanup("retrying retained callback buffer", retry))
    }

    fn remember_error(&mut self, error: RuntimeError) -> RuntimeError {
        if let Some(cause) = &self.first_failure {
            return RuntimeError::with_source(cause.kind().with_cleanup(error.kind()),
                "asynchronous callback buffer retains its first typed cleanup cause",
                Arc::clone(cause)).with_cleanup("retrying callback buffer cleanup", error);
        }
        let cause = Arc::new(error);
        let report = RuntimeError::with_source(cause.kind(),
            "asynchronous callback buffer retained its initial typed cleanup cause",
            Arc::clone(&cause));
        self.first_failure = Some(cause);
        report
    }
}

fn remember_failure(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        Some(primary) => primary.with_cleanup("completing asynchronous callback buffer cleanup", error),
        None => error,
    });
}
