//! Windows 3.1 SHELL drag/drop ABI over checked guest GlobalHeap blocks.

use guest_core::memory::Memory;
use win16_abi::global::{GMEM_MOVEABLE, GMEM_ZEROINIT};
use win16_abi::{GlobalHandle, SegmentedPointer, Win16ReturnKind, Win16ShellDropRequest};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDropFiles,
    Win16HostQueuedDropFiles,
    Win16HostKeyboardCall, Win16HostKeyboardResult, Win16HostShellExecutionOperation,
    Win16WindowOperation,
};

use super::{Win16State, QueuedDropFileGlobal, windows::WindowReturn};

const WM_DROPFILES: u16 = 0x0233;
const DROP_FILE_STRUCT16_SIZE: usize = 8;
const DROP_FILE_LIST_OFFSET: u16 = DROP_FILE_STRUCT16_SIZE as u16;
const MAX_DROP_BLOCK_BYTES: usize = u16::MAX as usize + 1;
const SHFMT_ERROR: u32 = u32::MAX;

impl Win16State {
    /// Retire only the exact runtime HGLOBAL lease named by the host receipt.
    /// A receipt may arrive before runtime has projected its first peek, so a
    /// missing lease is an idempotent no-op; an existing lease with another
    /// window generation is an invariant failure.
    pub(super) fn retire_queued_drop_file_lease(
        &mut self,
        receipt: crate::Win16HostDropRetirementReceipt,
    ) -> Result<(), RuntimeError> {
        if receipt.lease.0 == 0 || receipt.window.0 == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native WM_DROPFILES retirement receipt has a reserved identity"));
        }
        let Some(index) = self.queued_drop_files.iter()
            .position(|entry| entry.lease == receipt.lease)
        else {
            return Ok(());
        };
        let (guest_handle, allocation, finish_requested) = {
            let entry = &mut self.queued_drop_files[index];
            if entry.window != receipt.window
                || self.global_handles.get(&entry.guest_handle).copied() != Some(entry.allocation)
                || self.global_selectors.get(&entry.guest_handle).is_none()
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native WM_DROPFILES retirement changed its exact lease/window/HGLOBAL generation"));
            }
            entry.native_pending = false;
            (entry.guest_handle, entry.allocation, entry.finish_requested)
        };
        if finish_requested {
            if self.global_handles.get(&guest_handle).copied() != Some(allocation) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "deferred DragFinish lost its exact queued-drop HGLOBAL generation"));
            }
            self.remember_finished_queued_drop_lease(receipt.lease, receipt.window)?;
            self.retry_finished_queued_drop_file(guest_handle)?;
        }
        Ok(())
    }

    fn remember_finished_queued_drop_lease(
        &mut self,
        lease: crate::Win16HostDropFilesLease,
        window: crate::Win16HostWindow,
    ) -> Result<(), RuntimeError> {
        let identity = (lease, window);
        if let Some(index) = self.finished_queued_drop_leases
            .iter().position(|(existing_lease, _)| *existing_lease == lease)
        {
            if self.finished_queued_drop_leases[index].1 != window {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "finished queued WM_DROPFILES lease changed its exact window generation"));
            }
            return Ok(());
        }
        self.finished_queued_drop_leases.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve finished queued WM_DROPFILES suppression identity", error))?;
        self.finished_queued_drop_leases.push(identity);
        Ok(())
    }

    fn take_finished_queued_drop_lease(
        &mut self,
        lease: crate::Win16HostDropFilesLease,
        window: crate::Win16HostWindow,
    ) -> Result<bool, RuntimeError> {
        let mut matched = None;
        for (index, identity) in self.finished_queued_drop_leases.iter().enumerate() {
            if identity.0 == lease {
                if identity.1 != window {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "finished queued WM_DROPFILES lease was presented for another window generation"));
                }
                if matched.replace(index).is_some() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "finished queued WM_DROPFILES lease has duplicate suppression records"));
                }
            }
        }
        if let Some(index) = matched {
            self.finished_queued_drop_leases.remove(index);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(super) fn poll_native_drop_retirement(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(receipt) = host.win16_take_native_drop_retirement()? else {
            return Ok(false);
        };
        self.retire_queued_drop_file_lease(receipt)?;
        // Keep the host FIFO owner until exact runtime retirement succeeds;
        // a failed transport ACK causes the same receipt to be retried.
        host.win16_ack_native_drop_retirement(receipt)?;
        Ok(true)
    }

    pub(super) fn drain_native_drop_retirements(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        while self.poll_native_drop_retirement(host)? {}
        Ok(())
    }

    /// Release the native-queue pin when USER retires this exact mapped
    /// window. Guest HGLOBAL ownership remains live until its own GlobalFree.
    pub(super) fn retire_queued_drop_files_for_window(
        &mut self,
        window: crate::Win16HostWindow,
    ) -> Result<(), RuntimeError> {
        for entry in &mut self.queued_drop_files {
            if entry.window == window {
                entry.native_pending = false;
            }
        }
        self.retry_finished_queued_drop_files()?;
        self.finished_queued_drop_leases.retain(|(_, owner)| *owner != window);
        Ok(())
    }

    /// Task shutdown retires native queue leases and frees only the runtime
    /// HGLOBAL generations created for those leases. No guest code can retain
    /// or query a synthetic queued handle after terminal teardown.
    pub(super) fn retire_all_queued_drop_file_leases(
        &mut self,
    ) -> Result<(), RuntimeError> {
        for entry in &mut self.queued_drop_files {
            entry.native_pending = false;
        }
        let mut owners = Vec::new();
        owners.try_reserve(self.queued_drop_files.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve task-owned queued WM_DROPFILES teardown identities", error))?;
        owners.extend(self.queued_drop_files.iter()
            .map(|entry| (entry.guest_handle, entry.allocation)));
        for (guest_handle, allocation) in owners {
            if self.global_handles.get(&guest_handle).copied() != Some(allocation) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "queued WM_DROPFILES teardown lost its exact HGLOBAL generation"));
            }
            let cleanup = self.free_runtime_global_on_teardown(allocation)?;
            if let Some(error) = cleanup.retained_error("queued WM_DROPFILES task") {
                return Err(error);
            }
            self.queued_drop_files.retain(|entry|
                entry.guest_handle != guest_handle || entry.allocation != allocation);
        }
        self.finished_queued_drop_leases.clear();
        Ok(())
    }

    pub(super) fn retry_finished_queued_drop_file(
        &mut self,
        guest_handle: u16,
    ) -> Result<(), RuntimeError> {
        let finished_identity = self.queued_drop_files.iter().find(|entry|
            entry.guest_handle == guest_handle
                && entry.finish_requested
                && !entry.native_pending)
            .map(|entry| (entry.lease, entry.window));
        if let Some((lease, window)) = finished_identity {
            // Install the suppression identity before GlobalFree can remove
            // the HGLOBAL and its queued-drop owner record. It also remains
            // if GlobalFree reports a busy handle, so a later removed MSG
            // never exposes an HGLOBAL the guest already finished.
            self.remember_finished_queued_drop_lease(lease, window)?;
            let _ = self.global_free(guest_handle)?;
        }
        Ok(())
    }

    fn retry_finished_queued_drop_files(&mut self) -> Result<(), RuntimeError> {
        let mut handles = Vec::new();
        handles.try_reserve(self.queued_drop_files.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve deferred Win16 DragFinish retry identities", error))?;
        handles.extend(self.queued_drop_files.iter()
            .filter(|entry| entry.finish_requested && !entry.native_pending)
            .map(|entry| entry.guest_handle));
        for handle in handles {
            self.retry_finished_queued_drop_file(handle)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn begin_shell_drop_request(
        &mut self,
        request: Win16ShellDropRequest,
        registers: &mut guest_core::Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match request {
            Win16ShellDropRequest::DragAcceptFiles { window, accept } => {
                let owner = super::compat_shell_execution::window_target(self, window);
                let operation = Win16HostShellExecutionOperation::DragAcceptFiles {
                    owner,
                    accept: accept != 0,
                };
                self.begin_window_operation(
                    registers,
                    memory,
                    host,
                    Win16WindowOperation::ShellExecution(operation),
                    WindowReturn::ShellExecution(
                        super::compat_shell_execution::Win16ShellExecutionContinuation {
                            kind: super::compat_shell_execution::Win16ShellExecutionContinuationKind::DragAcceptFiles,
                            return_kind,
                        },
                    ),
                    return_to,
                )
            }
            request => {
                let value = self.shell_drop_api(request, memory, host)?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    value,
                    return_kind,
                )
            }
        }
    }

    pub(crate) fn shell_drop_api(
        &mut self,
        request: Win16ShellDropRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ShellDropRequest::DragAcceptFiles { .. } => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DragAcceptFiles bypassed its USER-owner operation",
            )),
            Win16ShellDropRequest::DragQueryFile {
                drop,
                index,
                file_name_far,
                capacity,
            } => self.drag_query_file(drop, index, file_name_far, capacity, memory, host),
            Win16ShellDropRequest::DragFinish { drop } => {
                // DragFinish is a void SDK routine. A PeekMessage(PM_NOREMOVE)
                // lease is still backed by the queued MSG, so GlobalFree
                // reports that exact owner as busy until PM_REMOVE retires it.
                let _ = self.global_free(drop)?;
                Ok(0)
            }
            Win16ShellDropRequest::DragQueryPoint { drop, point_far } => {
                self.drag_query_point(drop, point_far, memory)
            }
            Win16ShellDropRequest::FormatDrive {
                owner,
                drive,
                format_id,
                options,
            } => {
                // SHFormatDrive can write a physical volume. It is outside the
                // runtime's safe host boundary, so report the SDK's documented
                // SHFMT_ERROR result rather than forwarding a destructive call.
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!(
                        "SHELL.400 SHFormatDrive refused physical formatting (owner=0x{owner:04X}, drive={drive}, format_id=0x{format_id:04X}, options=0x{options:04X})"
                    ),
                ));
                Ok(SHFMT_ERROR)
            }
        }
    }

    pub(super) fn prepare_drop_files_hglobal(
        &mut self,
        drop: Win16HostDropFiles,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if !self.window_callbacks.last().is_some_and(|frame|
            frame.entry_phase == super::windows::WindowCallbackEntryPhase::Preparing
                && frame.guest_drop_global.is_none())
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native WM_DROPFILES payload has no free preparing callback owner"));
        }
        let bytes = encode_drop_files_block(&drop)?;
        let handle = self.global_alloc(
            GMEM_MOVEABLE | GMEM_ZEROINIT,
            u32::try_from(bytes.len()).map_err(|_| {
                RuntimeError::new(Kind::ResourceExhausted, "Win16 HDROP size is not representable")
            })?,
            memory,
            host,
        )?;
        if handle == 0 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 GlobalAlloc could not create the WM_DROPFILES HGLOBAL",
            ));
        }
        let Some(allocation) = self.global_handles.get(&handle).copied() else {
            let error = RuntimeError::new(Kind::InternalInvariant,
                "new WM_DROPFILES HGLOBAL has no exact GlobalHeap owner");
            return Err(self.cleanup_rejected_drop_hglobal(handle, None, error,
                "free ownerless WM_DROPFILES HGLOBAL"));
        };
        let owner_is_live = self.window_callbacks.last().is_some_and(|frame|
            frame.entry_phase == super::windows::WindowCallbackEntryPhase::Preparing
                && frame.guest_drop_global.is_none());
        if !owner_is_live {
            let primary = RuntimeError::new(Kind::InternalInvariant,
                "WM_DROPFILES HGLOBAL lost its preparing callback owner");
            return Err(match self.global_free(handle) {
                Ok(0) => primary,
                Ok(_) => primary.with_cleanup(
                    "free ownerless WM_DROPFILES HGLOBAL",
                    RuntimeError::new(Kind::ResourceExhausted,
                        "GlobalFree retained the ownerless WM_DROPFILES HGLOBAL"),
                ),
                Err(cleanup) => primary.with_cleanup(
                    "free ownerless WM_DROPFILES HGLOBAL", cleanup,
                ),
            });
        }
        // Retain the exact allocator generation before guest writes. If a
        // backing transfer fails, setup teardown can retry this owner.
        let Some(frame) = self.window_callbacks.last_mut() else {
            let error = RuntimeError::new(Kind::InternalInvariant,
                "pre-entry callback owner disappeared before WM_DROPFILES write");
            return Err(self.cleanup_rejected_drop_hglobal(handle, Some(allocation), error,
                "free callback-less WM_DROPFILES HGLOBAL"));
        };
        frame.guest_drop_global = Some(allocation);
        frame.guest_drop_generation = Some(allocation);
        let Some(selector) = self.global_selectors.get(&handle).copied() else {
            let error = RuntimeError::new(Kind::InternalInvariant,
                "new WM_DROPFILES HGLOBAL has no primary selector");
            return Err(self.cleanup_rejected_drop_hglobal(handle, Some(allocation), error,
                "free selector-less WM_DROPFILES HGLOBAL"));
        };
        let pointer = SegmentedPointer::new(selector, 0);
        if let Err(primary) = self.write_text_bytes(memory, pointer, &bytes) {
            return Err(self.cleanup_rejected_drop_hglobal(handle, Some(allocation), primary,
                "failed to free a rejected WM_DROPFILES HGLOBAL"));
        }
        Ok(handle)
    }

    pub(super) fn project_queued_drop_files_hglobal(
        &mut self,
        queued: &Win16HostQueuedDropFiles,
        window: crate::Win16HostWindow,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u16>, RuntimeError> {
        if queued.lease.0 == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native WM_DROPFILES delivery has a zero queue lease"));
        }
        if let Some(index) = self.queued_drop_files.iter()
            .position(|entry| entry.lease == queued.lease)
        {
            let (guest_handle, finish_requested, allocation) = {
                let entry = &mut self.queued_drop_files[index];
                if entry.window != window
                    || entry.files != queued.files
                    || self.global_handles.get(&entry.guest_handle).copied() != Some(entry.allocation)
                    || self.global_selectors.get(&entry.guest_handle).is_none()
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "queued WM_DROPFILES lease changed its exact guest HGLOBAL generation"));
                }
                // A native queue lease only advances from peeked to removed.
                // A stale earlier peek cannot resurrect the native owner.
                if queued.native_removed {
                    entry.native_pending = false;
                }
                (entry.guest_handle, entry.finish_requested, entry.allocation)
            };
            let already_finished = self.finished_queued_drop_leases
                .contains(&(queued.lease, window));
            if already_finished || (queued.native_removed && finish_requested) {
                if !finish_requested {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "finished queued WM_DROPFILES suppression has no retained DragFinish request"));
                }
                if self.global_handles.get(&guest_handle).copied() != Some(allocation) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "finished queued WM_DROPFILES lost its exact HGLOBAL generation"));
                }
                // PM_REMOVE has retired the native queue owner, but the guest
                // already requested DragFinish on its peeked MSG. Retire or
                // retain the exact HGLOBAL owner and suppress the payload; a
                // freed WORD handle must never be projected back to the guest.
                self.remember_finished_queued_drop_lease(queued.lease, window)?;
                self.retry_finished_queued_drop_file(guest_handle)?;
                let _ = self.take_finished_queued_drop_lease(queued.lease, window)?;
                return Ok(None);
            }
            return Ok(Some(guest_handle));
        }
        if self.take_finished_queued_drop_lease(queued.lease, window)? {
            // A retirement receipt may arrive and free a finish-requested
            // HGLOBAL before its normal removed delivery is projected.
            return Ok(None);
        }
        self.queued_drop_files.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve guest WM_DROPFILES queue owner", error))?;
        let bytes = encode_drop_files_block(&queued.files)?;
        let handle = self.global_alloc(
            GMEM_MOVEABLE | GMEM_ZEROINIT,
            u32::try_from(bytes.len()).map_err(|_| RuntimeError::new(
                Kind::ResourceExhausted, "queued Win16 HDROP size is not representable"))?,
            memory,
            host,
        )?;
        if handle == 0 {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 GlobalAlloc could not create the queued WM_DROPFILES HGLOBAL"));
        }
        let Some(allocation) = self.global_handles.get(&handle).copied() else {
            return Err(self.cleanup_rejected_drop_hglobal(
                handle,
                None,
                RuntimeError::new(Kind::InternalInvariant,
                    "queued WM_DROPFILES HGLOBAL has no exact GlobalHeap owner"),
                "free ownerless queued WM_DROPFILES HGLOBAL",
            ));
        };
        let Some(selector) = self.global_selectors.get(&handle).copied() else {
            return Err(self.cleanup_rejected_drop_hglobal(
                handle,
                Some(allocation),
                RuntimeError::new(Kind::InternalInvariant,
                    "queued WM_DROPFILES HGLOBAL has no primary selector"),
                "free selector-less queued WM_DROPFILES HGLOBAL",
            ));
        };
        if let Err(primary) = self.write_text_bytes(
            memory,
            SegmentedPointer::new(selector, 0),
            &bytes,
        ) {
            return Err(self.cleanup_rejected_drop_hglobal(
                handle,
                Some(allocation),
                primary,
                "failed to free a rejected queued WM_DROPFILES HGLOBAL",
            ));
        }
        self.queued_drop_files.push(QueuedDropFileGlobal {
            lease: queued.lease,
            window,
            guest_handle: handle,
            allocation,
            files: queued.files.clone(),
            native_pending: !queued.native_removed,
            finish_requested: false,
        });
        Ok(Some(handle))
    }

    pub(super) fn active_drop_files_message(
        &mut self,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        memory: &Memory,
    ) -> Result<Option<Win16HostDropFiles>, RuntimeError> {
        if message != WM_DROPFILES || w_param == 0 || l_param != 0
        {
            return Ok(None);
        }
        if self.active_window_callback(window, message, w_param, l_param).is_none() {
            return Ok(None);
        }
        let handle = w_param;
        let Some(allocation) = self.global_handles.get(&handle).copied() else {
            return Ok(None);
        };
        let Some(frame) = self.window_callbacks.last().filter(|frame|
            frame.entry_phase == super::windows::WindowCallbackEntryPhase::GuestCallback
                && frame.payload.message == message
                && frame.payload.w_param == w_param
                && frame.payload.l_param == l_param)
        else {
            return Ok(None);
        };
        let queued_owner = self.window_handles.get(&window).is_some_and(|mapped| {
            self.queued_drop_files.iter().any(|entry|
                entry.guest_handle == handle
                    && entry.allocation == allocation
                    && entry.window == *mapped)
        });
        let direct_owner = frame.guest_drop_generation == Some(allocation);
        if !direct_owner && !queued_owner {
            return Ok(None);
        }
        let Some(block) = self.read_drop_hglobal(handle, memory)? else {
            return Err(RuntimeError::new(Kind::GuestFault,
                "active WM_DROPFILES callback has no readable HGLOBAL block"));
        };
        let paths = parse_drop_files(&block)?
            .into_iter()
            .map(|path| path.to_vec())
            .collect::<Vec<_>>();
        let x = i16::from_le_bytes([block[2], block[3]]);
        let y = i16::from_le_bytes([block[4], block[5]]);
        let non_client = u16::from_le_bytes([block[6], block[7]]) != 0;
        Ok(Some(Win16HostDropFiles {
            paths,
            point: crate::Win16HostPoint { x: i32::from(x), y: i32::from(y) },
            in_client_area: !non_client,
        }))
    }

    pub(super) fn queued_drop_global_for_dispatch(
        &self,
        message: win16_abi::Msg16,
    ) -> Result<Option<GlobalHandle>, RuntimeError> {
        if message.message != WM_DROPFILES
            || message.w_param == 0
            || message.l_param != 0
        {
            return Ok(None);
        }
        let guest_handle = message.w_param;
        let Some(&window) = self.window_handles.get(&message.hwnd) else {
            return Ok(None);
        };
        let Some(allocation) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(None);
        };
        Ok(self.queued_drop_files.iter().any(|entry|
            entry.window == window
                && entry.guest_handle == guest_handle
                && entry.allocation == allocation
        ).then_some(allocation))
    }

    fn drag_query_file(
        &mut self,
        drop: u16,
        index: u16,
        file_name_far: u32,
        capacity: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(block) = self.read_drop_hglobal(drop, memory)? else {
            return Ok(0);
        };
        let files = parse_drop_files(&block)?;
        if index == u16::MAX {
            return u32::try_from(files.len()).map_err(|_| RuntimeError::new(
                Kind::GuestFault, "HDROP contains more files than DragQueryFile can report"));
        }
        let Some(path) = files.get(usize::from(index)) else { return Ok(0); };
        if file_name_far == 0 {
            return u32::try_from(path.len()).map_err(|_| RuntimeError::new(
                Kind::GuestFault, "HDROP path is longer than DragQueryFile can report"));
        }
        if capacity == 0 { return Ok(0); }

        let max_path_bytes = usize::from(capacity - 1);
        let pointer = self.selectors.pointer_from_far(file_name_far)
            .map_err(crate::runtime_error)?;
        // A full byte-for-byte fit never needs character-boundary discovery,
        // so it remains usable even for guest code pages whose variable-width
        // clipping rules are not implemented.
        let prefix = if path.len() <= max_path_bytes {
            path.len()
        } else {
            match dbcs_safe_prefix(path, max_path_bytes, host) {
                Ok(prefix) => prefix,
                Err(error) if error.kind() == Kind::CompatibilityGap => {
                    // DragQueryFile reports failure through its return value.
                    // Validate the guest output pointer by writing its required
                    // empty string, then report the unsupported clipping rule
                    // as recoverable diagnostics instead of aborting the task.
                    self.write_text_bytes(memory, pointer, &[0])?;
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        error.to_string(),
                    ));
                    return Ok(0);
                }
                Err(error) => return Err(error),
            }
        };
        let mut output = Vec::new();
        output.try_reserve_exact(prefix + 1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve DragQueryFile guest output", error))?;
        output.extend_from_slice(&path[..prefix]);
        output.push(0);
        self.write_text_bytes(memory, pointer, &output)?;
        // The Win16 ANSI buffer capacity and returned length are byte counts;
        // only complete guest DBCS characters are copied.
        Ok(prefix as u32)
    }

    fn drag_query_point(
        &mut self,
        drop: u16,
        point_far: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if point_far == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "DragQueryPoint received a null POINT output pointer"));
        }
        let pointer = self.selectors.pointer_from_far(point_far)
            .map_err(crate::runtime_error)?;
        self.preflight_text_write(memory, pointer, 4)?;
        let Some(block) = self.read_drop_hglobal(drop, memory)? else {
            return Ok(0);
        };
        if block.len() < DROP_FILE_STRUCT16_SIZE {
            return Err(RuntimeError::new(Kind::GuestFault,
                "HDROP is shorter than DROPFILESTRUCT16"));
        }
        let mut point = [0_u8; 4];
        point[0..2].copy_from_slice(&block[2..4]);
        point[2..4].copy_from_slice(&block[4..6]);
        self.write_text_bytes(memory, pointer, &point)?;
        let non_client = u16::from_le_bytes([block[6], block[7]]) != 0;
        Ok(if non_client { 0 } else { 1 })
    }

    fn read_drop_hglobal(
        &mut self,
        handle: u16,
        memory: &Memory,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let size = self.global_size(handle)?;
        if size < DROP_FILE_STRUCT16_SIZE as u32 || size as usize > MAX_DROP_BLOCK_BYTES {
            return Ok(None);
        }
        let far = self.global_lock(handle, memory)?;
        if far == 0 { return Ok(None); }
        let read = (|| {
            let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
            self.read_text_bytes(memory, pointer, size as usize)
        })();
        let unlock = self.global_unlock(handle);
        match (read, unlock) {
            (Ok(bytes), Ok(_)) => Ok(Some(bytes)),
            (Err(primary), Ok(_)) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(
                "failed to unlock the DragQuery HGLOBAL", cleanup,
            )),
        }
    }

    fn cleanup_rejected_drop_hglobal(
        &mut self,
        guest_handle: u16,
        allocation: Option<GlobalHandle>,
        primary: RuntimeError,
        context: &'static str,
    ) -> RuntimeError {
        match self.global_free(guest_handle) {
            Ok(0) => {
                if let Some(allocation) = allocation {
                    if let Some(frame) = self.window_callbacks.last_mut()
                        .filter(|frame| frame.guest_drop_global == Some(allocation))
                    {
                        frame.guest_drop_global = None;
                    }
                }
                primary
            }
            Ok(_) => primary.with_cleanup(context, RuntimeError::new(
                Kind::ResourceExhausted,
                "GlobalFree retained a rejected WM_DROPFILES HGLOBAL",
            )),
            Err(cleanup) => primary.with_cleanup(context, cleanup),
        }
    }
}

fn encode_drop_files_block(drop: &Win16HostDropFiles) -> Result<Vec<u8>, RuntimeError> {
    let mut size = DROP_FILE_STRUCT16_SIZE;
    for path in &drop.paths {
        if path.is_empty() || path.contains(&0) {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "native WM_DROPFILES contains an empty or embedded-NUL path"));
        }
        let terminated = path.len().checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "WM_DROPFILES guest path size overflow"))?;
        size = size.checked_add(terminated).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "WM_DROPFILES guest block size overflow"))?;
    }
    size = size.checked_add(if drop.paths.is_empty() { 2 } else { 1 })
        .ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "WM_DROPFILES guest terminator size overflow"))?;
    if size > MAX_DROP_BLOCK_BYTES {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "WM_DROPFILES guest path list exceeds one Win16 far-addressable block"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 WM_DROPFILES block", error))?;
    bytes.extend_from_slice(&DROP_FILE_LIST_OFFSET.to_le_bytes());
    let x = drop.point.x.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
    let y = drop.point.y.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
    bytes.extend_from_slice(&x.to_le_bytes());
    bytes.extend_from_slice(&y.to_le_bytes());
    let non_client = if drop.in_client_area { 0_u16 } else { 1_u16 };
    bytes.extend_from_slice(&non_client.to_le_bytes());
    for path in &drop.paths {
        bytes.extend_from_slice(path);
        bytes.push(0);
    }
    bytes.push(0);
    if drop.paths.is_empty() { bytes.push(0); }
    debug_assert_eq!(bytes.len(), size);
    Ok(bytes)
}

fn parse_drop_files(block: &[u8]) -> Result<Vec<&[u8]>, RuntimeError> {
    if block.len() < DROP_FILE_STRUCT16_SIZE {
        return Err(RuntimeError::new(Kind::GuestFault,
            "HDROP is shorter than DROPFILESTRUCT16"));
    }
    let start = usize::from(u16::from_le_bytes([block[0], block[1]]));
    if start < DROP_FILE_STRUCT16_SIZE || start >= block.len() {
        return Err(RuntimeError::new(Kind::GuestFault,
            "HDROP file-list offset is outside its guest block"));
    }
    let mut files = Vec::new();
    let mut cursor = start;
    loop {
        let tail = &block[cursor..];
        let Some(relative_end) = tail.iter().position(|byte| *byte == 0) else {
            return Err(RuntimeError::new(Kind::GuestFault,
                "HDROP file list is missing its final NUL"));
        };
        if relative_end == 0 {
            // An empty first string means the entire list is empty and must
            // still carry both terminators. After a nonempty name, the byte
            // after its consumed NUL is the final empty-string terminator.
            if files.is_empty() && tail.get(1) != Some(&0) {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "HDROP file list is not double-NUL terminated"));
            }
            return Ok(files);
        }
        let end = cursor + relative_end;
        files.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve DragQueryFile path index", error))?;
        files.push(&block[cursor..end]);
        cursor = end + 1;
        if cursor >= block.len() {
            return Err(RuntimeError::new(Kind::GuestFault,
                "HDROP file list is missing its empty-name terminator"));
        }
    }
}

fn dbcs_safe_prefix(
    path: &[u8],
    capacity: usize,
    host: &mut impl RuntimeHost,
) -> Result<usize, RuntimeError> {
    let code_page = host.win16_ansi_code_page();
    if code_page == 65_001 {
        let text = std::str::from_utf8(path).map_err(|_| RuntimeError::new(
            Kind::GuestFault, "HDROP path is not valid UTF-8"))?;
        let mut end = 0;
        for (offset, character) in text.char_indices() {
            let next = offset + character.len_utf8();
            if next > capacity { break; }
            end = next;
        }
        return Ok(end);
    }
    if matches!(code_page, 52_936 | 50_220..=50_229 | 50_930 | 50_939
        | 57_002..=57_011 | 54_936 | 65_000)
    {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            format!("DragQueryFile cannot safely clip variable-width guest code page {code_page}")));
    }
    let mut cursor = 0;
    while cursor < path.len() && cursor < capacity {
        let lead = match host.win16_keyboard(Win16HostKeyboardCall::IsDbcsLeadByte {
            code_page,
            value: path[cursor],
        })? {
            Win16HostKeyboardResult::IsDbcsLeadByte(value) => value,
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 ANSI DBCS query returned another operation's result")),
        };
        if lead && cursor + 1 >= path.len() {
            return Err(RuntimeError::new(Kind::GuestFault,
                "HDROP path ends with an unpaired DBCS lead byte"));
        }
        let width = if lead { 2 } else { 1 };
        if cursor + width > capacity { break; }
        cursor += width;
    }
    Ok(cursor)
}
