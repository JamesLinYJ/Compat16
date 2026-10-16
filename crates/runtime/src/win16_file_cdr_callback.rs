//! Task-owned KERNEL FileCDR registration and synchronous callback lifetime.

use dos_kernel::{DosCallAddressSpace, DosSpanPolicy};
use guest_core::{OwnerId, Registers, memory::Memory};
use win16_abi::{Access, GlobalHandle, global::GMEM_ZEROINIT};
use x86_cpu::Cpu;

use super::super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::super::{CallbackFrameId, CallbackKind, Win16State};
use super::Win16CanonicalPath;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const MAX_FILE_CDR_PAYLOAD_BYTES: usize = 256;
const DOS_CDR_PATH_LIMIT: usize = 260;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Registration {
    owner: OwnerId,
    procedure: u32,
}

/// The opcode and one or two normalized NUL-terminated paths, captured before
/// DOS mutates caller registers and queued only after DOS reports success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct FileCdrNotice {
    owner: OwnerId,
    procedure: u32,
    opcode: u16,
    payload: Vec<u8>,
}

/// Pre-DOS snapshot shared by FileCDR delivery and cwd maintenance. Rename
/// tracking remains active even when no FileCDR callback is registered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct FileCdrDosNotice {
    owner: OwnerId,
    rename_paths: Option<(Win16CanonicalPath, Win16CanonicalPath)>,
    notification: Option<FileCdrNotice>,
}

#[derive(Clone, Debug)]
struct FileCdrInvocation {
    callback_id: CallbackFrameId,
    owner: OwnerId,
    guest_buffer: u16,
    allocation: GlobalHandle,
    call: Win16FarCallbackFrame,
}

/// FileCDR registration, successful DOS-hook notifications, and active guest
/// calls share the same task owner and callback LIFO identity.
#[derive(Clone, Debug, Default)]
pub(crate) struct FileCdrCallbackState {
    registration: Option<Registration>,
    pending: Option<FileCdrNotice>,
    invocations: Vec<FileCdrInvocation>,
}

impl FileCdrCallbackState {
    /// FileCDR's selector FFFFh query returns the retained FAR value in DX:AX.
    pub(crate) fn query(&self) -> u32 {
        self.registration
            .map_or(0, |registration| registration.procedure)
    }

    /// Install, replace, or clear a procedure after the caller has validated
    /// its executable selector. Only the registering task incarnation may
    /// change the callback.
    pub(crate) fn register(&mut self, owner: OwnerId, procedure: u32) -> bool {
        if self
            .registration
            .is_some_and(|current| current.owner != owner)
        {
            return false;
        }
        self.registration = if procedure == 0 {
            None
        } else {
            Some(Registration { owner, procedure })
        };
        true
    }

    pub(crate) fn callback_for(&self, owner: OwnerId) -> Option<u32> {
        self.registration
            .filter(|registration| registration.owner == owner)
            .map(|registration| registration.procedure)
    }

    pub(crate) fn callback_matches(&self, owner: OwnerId, procedure: u32) -> bool {
        self.registration == Some(Registration { owner, procedure })
    }

    pub(in crate::win16_runtime) fn publish(
        &mut self,
        notice: FileCdrNotice,
    ) -> Result<(), RuntimeError> {
        if self.pending.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FileCDR notification was not consumed before the next DOS call",
            ));
        }
        self.pending = Some(notice);
        Ok(())
    }

    fn take_pending(&mut self) -> Option<FileCdrNotice> {
        self.pending.take()
    }

    fn reserve_invocation(&mut self) -> Result<(), RuntimeError> {
        self.invocations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 FileCDR callback frame",
                error,
            )
        })
    }

    fn push_invocation(&mut self, invocation: FileCdrInvocation) {
        self.invocations.push(invocation);
    }

    fn take_top_invocation(
        &mut self,
        callback_id: CallbackFrameId,
    ) -> Result<FileCdrInvocation, RuntimeError> {
        if self
            .invocations
            .last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top FileCDR callback identity differs from its retained frame",
            ));
        }
        Ok(self.invocations.pop().expect("top frame was checked"))
    }

    fn restore_invocation(&mut self, invocation: FileCdrInvocation) {
        self.invocations.push(invocation);
    }

    pub(crate) fn code_references(&self) -> impl Iterator<Item = u32> + '_ {
        self.registration
            .iter()
            .map(|registration| registration.procedure)
            .chain(
                self.invocations
                    .iter()
                    .flat_map(|frame| frame.call.code_references()),
            )
    }

    pub(crate) fn has_active_invocations(&self) -> bool {
        !self.invocations.is_empty()
    }

    /// Task teardown retires only that task incarnation's registration.
    pub(crate) fn retire_task(&mut self, owner: OwnerId) -> bool {
        if self
            .registration
            .is_some_and(|registration| registration.owner == owner)
        {
            self.registration = None;
            true
        } else {
            false
        }
    }
}

impl Win16State {
    /// Snapshot a FileCDR-relevant path before DOS consumes registers or
    /// caller memory. Invalid guest pointers simply suppress the optional
    /// notification; DOS still owns the operation's result.
    pub(in crate::win16_runtime) fn capture_file_cdr_notice(
        &mut self,
        regs: &Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<FileCdrDosNotice>, RuntimeError> {
        let owner = self.current_task_owner()?;
        let procedure = self.kernel_file_system.file_cdr.callback_for(owner);
        let second_path = match regs.ah() {
            // AH=5Ah generates its filename during DOS execution. The input
            // directory is not a created-file notice; leave that callback
            // unsupported until its post-call notification ABI is verified.
            0x39 | 0x3a | 0x3c | 0x41 | 0x5b => false,
            0x43 if regs.al() != 0 => false,
            0x56 => true,
            _ => return Ok(None),
        };
        let rename = regs.ah() == 0x56;
        if procedure.is_none() && !rename {
            return Ok(None);
        }
        let mut address_space = match self.dos_call_address_space(memory, owner) {
            Ok(address_space) => address_space,
            Err(_) => return Ok(None),
        };
        let Some(source) = read_path(&mut address_space, regs.ds, regs.dx()) else {
            return Ok(None);
        };
        let destination = if second_path {
            let Some(destination) = read_path(&mut address_space, regs.es, regs.di()) else {
                return Ok(None);
            };
            Some(destination)
        } else {
            None
        };
        drop(address_space);

        let source = match self.kernel_file_system.resolve_guest_path(
            owner,
            &source,
            host.guest_code_page(),
            false,
        ) {
            Ok(path) => path,
            Err(error) if super::owner::guest_api_failure(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(source) = host.normalize_win16_dos_path(owner, &source)? else {
            return Ok(None);
        };
        let destination = match destination {
            Some(destination) => match self.kernel_file_system.resolve_guest_path(
                owner,
                &destination,
                host.guest_code_page(),
                false,
            ) {
                Ok(path) => match host.normalize_win16_dos_path(owner, &path)? {
                    Some(path) => Some(path),
                    None => return Ok(None),
                },
                Err(error) if super::owner::guest_api_failure(&error) => return Ok(None),
                Err(error) => return Err(error),
            },
            None => None,
        };
        let rename_paths = if rename {
            Some((
                source.clone(),
                destination.clone().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "DOS rename notice has no normalized destination path",
                    )
                })?,
            ))
        } else {
            None
        };
        let notification = if let Some(procedure) = procedure {
            let source_bytes = host.win16_dos_path_bytes(owner, &source)?;
            let destination_bytes = match destination.as_ref() {
                Some(destination) => host.win16_dos_path_bytes(owner, destination)?,
                None => None,
            };
            match (source_bytes, destination_bytes) {
                (Some(source_bytes), destination_bytes)
                    if destination.is_none() || destination_bytes.is_some() =>
                {
                    let mut payload = Vec::new();
                    payload
                        .try_reserve_exact(MAX_FILE_CDR_PAYLOAD_BYTES)
                        .map_err(|error| {
                            RuntimeError::with_source(
                                Kind::ResourceExhausted,
                                "reserve Win16 FileCDR path payload",
                                error,
                            )
                        })?;
                    payload.extend_from_slice(&source_bytes);
                    payload.push(0);
                    if let Some(destination) = destination_bytes {
                        payload.extend_from_slice(&destination);
                        payload.push(0);
                    }
                    (payload.len() <= MAX_FILE_CDR_PAYLOAD_BYTES).then_some(FileCdrNotice {
                        owner,
                        procedure,
                        opcode: regs.ax(),
                        payload,
                    })
                }
                _ => None,
            }
        } else {
            None
        };
        if rename || notification.is_some() {
            Ok(Some(FileCdrDosNotice {
                owner,
                rename_paths,
                notification,
            }))
        } else {
            Ok(None)
        }
    }

    /// Publish only an operation which completed through DOS without carry.
    pub(in crate::win16_runtime) fn finish_file_cdr_dos_operation(
        &mut self,
        notice: Option<FileCdrDosNotice>,
        regs: &Registers,
        action: &dos_kernel::DosAction,
    ) -> Result<(), RuntimeError> {
        let Some(notice) = notice else {
            return Ok(());
        };
        if *action == dos_kernel::DosAction::Continue && !regs.carry() {
            if self.current_task_owner()? != notice.owner {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DOS file operation crossed its Win16 TDB owner boundary",
                ));
            }
            if let Some((source, destination)) = notice.rename_paths {
                self.kernel_file_system
                    .record_successful_rename(&source, &destination)?;
            }
            if let Some(notification) = notice.notification {
                self.kernel_file_system.file_cdr.publish(notification)?;
            }
        }
        Ok(())
    }

    /// Consume a successful DOS file-hook notice and enter the registered
    /// `PASCAL VOID FAR` callback before the guest resumes its next instruction.
    pub(in crate::win16_runtime) fn begin_pending_file_cdr_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let current_owner = self.current_task_owner()?;
        let Some(notice) = self.kernel_file_system.file_cdr.take_pending() else {
            return Ok(false);
        };
        if current_owner != notice.owner {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FileCDR notification crossed its TDB owner boundary",
            ));
        }
        if !self
            .kernel_file_system
            .file_cdr
            .callback_matches(notice.owner, notice.procedure)
        {
            // A task can clear its callback while handling DOS only through
            // guest reentry, which is not possible before this synchronous
            // safe point. Treat any stale pending registration as retired.
            return Ok(false);
        }

        let guest_buffer = self.global_alloc(
            GMEM_ZEROINIT,
            u32::try_from(notice.payload.len()).map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 FileCDR path payload exceeds DWORD allocation size",
                )
            })?,
            memory,
            host,
        )?;
        if guest_buffer == 0 {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::ResourceExhausted,
                "Win16 FileCDR callback was skipped because its guest path allocation failed",
            ));
            return Ok(false);
        }
        let allocation = match self.global_handles.get(&guest_buffer).copied() {
            Some(allocation) => allocation,
            None => {
                let primary = RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 FileCDR GlobalAlloc result has no exact heap identity",
                );
                return Err(self.file_cdr_setup_error(primary, guest_buffer, None));
            }
        };
        if let Err(error) = self.kernel_file_system.file_cdr.reserve_invocation() {
            return Err(self.file_cdr_setup_error(error, guest_buffer, Some(allocation)));
        }
        let callback_id = match self.reserve_callback_frame_id() {
            Ok(callback_id) => callback_id,
            Err(error) => {
                return Err(self.file_cdr_setup_error(error, guest_buffer, Some(allocation)));
            }
        };
        if let Err(error) = self.push_callback_kind(CallbackKind::FileCdr, callback_id) {
            return Err(self.file_cdr_setup_error(error, guest_buffer, Some(allocation)));
        }

        let far_path = u32::from(guest_buffer) << 16;
        let setup = (|| {
            let pointer = self
                .selectors
                .pointer_from_far(far_path)
                .map_err(crate::runtime_error)?;
            self.selectors
                .write(memory, pointer, &notice.payload)
                .map_err(crate::runtime_error)?;
            self.enter_guest_far_callback_checked(
                cpu,
                dos,
                memory,
                notice.procedure,
                &[
                    Win16FarCallbackArgument::Word(notice.opcode),
                    Win16FarCallbackArgument::GuestPointer {
                        far: far_path,
                        access: Access::Read,
                        bytes: notice.payload.len() as u32,
                    },
                ],
                Win16FarCallbackConvention::Pascal,
                Win16FarCallbackReturn::Void,
            )
        })();
        let call = match setup {
            Ok(call) => call,
            Err(primary) => {
                let mut combined = primary;
                if let Err(cleanup) =
                    self.retire_callback_binding(CallbackKind::FileCdr, callback_id)
                {
                    combined = combined.with_cleanup(
                        "retire FileCDR callback stack after checked entry failure",
                        cleanup,
                    );
                }
                return Err(self.file_cdr_setup_error(combined, guest_buffer, Some(allocation)));
            }
        };
        self.kernel_file_system
            .file_cdr
            .push_invocation(FileCdrInvocation {
                callback_id,
                owner: notice.owner,
                guest_buffer,
                allocation,
                call,
            });
        Ok(true)
    }

    pub(in crate::win16_runtime) fn finish_file_cdr_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::FileCdr)?;
        let mut invocation = self
            .kernel_file_system
            .file_cdr
            .take_top_invocation(callback_id)?;
        let current_owner = match self.current_task_owner() {
            Ok(owner) => owner,
            Err(primary) => {
                self.kernel_file_system
                    .file_cdr
                    .restore_invocation(invocation);
                return Err(primary);
            }
        };
        if current_owner != invocation.owner {
            self.kernel_file_system
                .file_cdr
                .restore_invocation(invocation);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FileCDR callback return crossed its TDB owner boundary",
            ));
        }
        if let Err(primary) =
            self.finish_guest_far_callback_checked(cpu, dos, memory, &mut invocation.call)
        {
            self.kernel_file_system
                .file_cdr
                .restore_invocation(invocation);
            return Err(primary);
        }
        if invocation.guest_buffer != 0 {
            if let Err(primary) =
                self.release_file_cdr_buffer(invocation.guest_buffer, invocation.allocation)
            {
                self.kernel_file_system
                    .file_cdr
                    .restore_invocation(invocation);
                return Err(primary);
            }
            invocation.guest_buffer = 0;
        }
        if let Err(primary) =
            self.release_guest_far_callback_owner(&mut invocation.call, dos, memory)
        {
            self.kernel_file_system
                .file_cdr
                .restore_invocation(invocation);
            return Err(primary);
        }
        self.retire_callback_binding(CallbackKind::FileCdr, callback_id)
    }

    pub(in crate::win16_runtime) fn cancel_file_cdr_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::FileCdr)?;
        let mut invocation = self
            .kernel_file_system
            .file_cdr
            .take_top_invocation(callback_id)?;
        if let Err(primary) = self.abort_guest_far_callback_after_task_execution_ended(
            ended,
            CallbackKind::FileCdr,
            callback_id,
            cpu,
            dos,
            memory,
            &mut invocation.call,
        ) {
            self.kernel_file_system
                .file_cdr
                .restore_invocation(invocation);
            return Err(primary);
        }
        if invocation.guest_buffer != 0
            && let Err(primary) =
                self.release_file_cdr_buffer(invocation.guest_buffer, invocation.allocation)
        {
            self.kernel_file_system
                .file_cdr
                .restore_invocation(invocation);
            return Err(primary);
        }
        self.retire_callback_binding(CallbackKind::FileCdr, callback_id)
    }

    fn file_cdr_setup_error(
        &mut self,
        primary: RuntimeError,
        guest_buffer: u16,
        allocation: Option<GlobalHandle>,
    ) -> RuntimeError {
        let Some(allocation) = allocation else {
            return primary;
        };
        match self.release_file_cdr_buffer(guest_buffer, allocation) {
            Ok(()) => primary,
            Err(cleanup) => primary.with_cleanup(
                "release temporary FileCDR guest path after callback setup failure",
                cleanup,
            ),
        }
    }

    fn release_file_cdr_buffer(
        &mut self,
        guest_buffer: u16,
        allocation: GlobalHandle,
    ) -> Result<(), RuntimeError> {
        if self.global_handles.get(&guest_buffer).copied() != Some(allocation) {
            // The guest may have freed or reallocated this temporary block
            // while the callback ran. Never free a new generation at the same
            // raw HGLOBAL word.
            return Ok(());
        }
        match self.free_global_on_teardown(guest_buffer, allocation)? {
            super::super::global_memory::GlobalTeardownResult::Freed => Ok(()),
            retained => Err(retained
                .retained_error("Win16 FileCDR path buffer")
                .unwrap_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "Win16 FileCDR path buffer remained allocated",
                    )
                })),
        }
    }
}

fn read_path(
    address_space: &mut impl DosCallAddressSpace,
    segment: u16,
    offset: u16,
) -> Option<Vec<u8>> {
    let pointer = address_space.resolve_caller_pointer(segment, offset).ok()?;
    address_space
        .read_caller_terminated(pointer, 0, DOS_CDR_PATH_LIMIT, DosSpanPolicy::Linear)
        .ok()
}
