//! Deferred DOS termination must not execute its ROM IRET before owner cleanup.

#[path = "win16_execute_exit_callback_tests.rs"]
mod callback_tests;

use super::Kind;
use crate::*;
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::OwnerId;
use std::sync::Arc;

#[derive(Default)]
struct ExitHost {
    active: Option<Win16ClassicDdeOperationIdentity>,
    begins: u64,
    quiesces: usize,
    polling: bool,
    resumes: usize,
    retired: usize,
    exits: Vec<u16>,
    terminal_dos_calls: usize,
    callback_markers: Vec<u16>,
    markers_at_exit: Vec<Vec<u16>>,
    marker_requires_idle_dde: bool,
}

impl DosHost for ExitHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _file: DosHostFile, _offset: i32, _origin: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _drive: u8, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { 3 }
}

impl RuntimeHost for ExitHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
    fn win16_get_tick_count(&mut self) -> Result<u32, RuntimeError> { Ok(0) }

    fn win16_take_guest_callback(&mut self) -> Result<Option<Win16GuestCallbackEvent>, RuntimeError> {
        if self.marker_requires_idle_dde {
            assert!(self.active.is_none(), "unrelated callback admission overtook a live DDE poll");
        }
        Ok(None)
    }

    fn win16_classic_dde_begin(
        &mut self, call: Win16HostClassicDdeCall,
    ) -> Result<Win16HostClassicDdeStep, RuntimeError> {
        let owner = match call {
            Win16HostClassicDdeCall::QuiesceOwner { owner, id } => {
                assert!(id.is_none() || id == Some(Win16ClassicDdeQuiescenceId(1)));
                self.quiesces += 1;
                self.polling = false;
                owner
            }
            Win16HostClassicDdeCall::PollOwner { owner } => {
                self.polling = true;
                owner
            }
            _ => panic!("unexpected classic DDE call: {call:?}"),
        };
        assert!(self.active.is_none());
        assert!(self.exits.is_empty(), "task finalized before native ownership drained");
        self.begins += 1;
        let operation = Win16ClassicDdeOperationIdentity {
            owner, id: Win16ClassicDdeOperationId(self.begins), worker_generation: 1,
        };
        self.active = Some(operation);
        Ok(Win16HostClassicDdeStep::Started(operation))
    }

    fn win16_classic_dde_resume(
        &mut self, resume: Win16HostClassicDdeResume,
    ) -> Result<Win16HostClassicDdeStep, RuntimeError> {
        assert_eq!(self.active, Some(resume.operation));
        assert!(resume.reply.is_none());
        assert!(self.exits.is_empty());
        self.resumes += 1;
        // Keep the native worker pending across a complete safe-point turn.
        if self.resumes % 2 == 1 {
            return Ok(Win16HostClassicDdeStep::Started(resume.operation));
        }
        let operation = resume.operation;
        Ok(Win16HostClassicDdeStep::Complete {
            operation,
            result: if self.polling {
                Win16HostClassicDdeResult::Event(None)
            } else {
                Win16HostClassicDdeResult::OwnerQuiesced(Win16HostClassicDdeOwnerQuiesced {
                    owner: operation.owner, worker_generation: operation.worker_generation,
                    id: Win16ClassicDdeQuiescenceId(1), operation,
                })
            },
            source_retired: Arc::new(Win16HostClassicDdeSourceRetiredProof {
                operation, callbacks: Vec::new(),
            }),
        })
    }

    fn win16_classic_dde_source_retirement_consumed(
        &mut self, proof: &Win16HostClassicDdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        assert_eq!(self.active.take(), Some(proof.operation));
        assert!(proof.callbacks.is_empty());
        self.retired += 1;
        Ok(())
    }

    fn observe_dos_service(
        &mut self, _instruction_count: u64,
        before: &guest_core::Registers, _after: &guest_core::Registers,
    ) {
        if before.ah() == 0x30 {
            if self.marker_requires_idle_dde {
                assert!(self.active.is_none(), "guest instruction overtook a live DDE poll");
            }
            self.callback_markers.push(before.bx());
        }
        if before.ah() == 0x4c {
            self.terminal_dos_calls += 1;
        }
    }

    fn observe_win16_io(&mut self, event: &Win16IoEvent<'_>) {
        if let Win16IoEvent::TaskExit { status } = event {
            assert!(self.active.is_none());
            assert_eq!(self.retired as u64, self.begins);
            assert!(self.quiesces != 0);
            self.markers_at_exit.push(self.callback_markers.clone());
            self.exits.push(*status);
        }
    }
}

impl RuntimeDdeHost for ExitHost {
    fn win16_dde_abort(&mut self) -> Win16DdeAbortReceipt {
        Win16DdeAbortReceipt::not_started()
    }
}
impl RuntimeMciHost for ExitHost {
    fn win16_mci_quiesce_producers(
        &mut self, request: Win16HostMciProducerQuiescenceRequest,
    ) -> Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
        assert!(request.owners.registrations.is_empty());
        Ok(Win16HostMciProducerQuiescenceReceipt {
            request, source_admission_closed: true,
            source_disable_evidence: Vec::new(), live_yield_sources: Vec::new(),
            active_operations: Vec::new(), active_yields: Vec::new(), devices: Vec::new(),
            accepted_routes: Vec::new(), queued_notifications: Vec::new(),
            source_causes: Vec::new(), barrier_causes: Vec::new(), resolved_causes: Vec::new(),
        })
    }
}
impl RuntimeMidiHost for ExitHost {}
impl RuntimeNetbiosHost for ExitHost {}

fn fixture(ax: u16) -> (Runtime, OwnerId) {
    let mut image = super::super::test_support::tiny_ne_executable();
    // Module startup reloads segments from the NE image. Put the executable
    // bytes in a file-backed segment so startup cannot restore zero-fill over
    // the instruction stream under test (default NE sector shift is nine).
    image[0x80..0x82].copy_from_slice(&1_u16.to_le_bytes());
    image[0x82..0x84].copy_from_slice(&5_u16.to_le_bytes());
    image[0x86..0x88].copy_from_slice(&5_u16.to_le_bytes());
    image.resize(0x205, 0);
    let [lo, hi] = ax.to_le_bytes();
    image[0x200..].copy_from_slice(&[0xb8, lo, hi, 0xcd, 0x21]);
    let mut runtime = Runtime::load(&image, &[], br"C:\EXIT.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.tasks.current().unwrap();
    state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
        drive: 2, components: Vec::new(),
    }).unwrap();
    (runtime, owner)
}

#[test]
fn terminal_int21_at_segment_end_waits_for_classic_dde_without_iret() {
    for status in [0, 7] {
        let (mut runtime, owner) = fixture(0x4c00 | status);
        let mut host = ExitHost::default();
        // Exercise the real instruction/firmware/pump loop; outer resource
        // teardown is separate from this exit-boundary regression.
        assert_eq!(runtime.run_win16_inner(&mut host, 20).unwrap(), status as u8);
        assert_eq!(runtime.instructions, 2, "only MOV and INT may execute");
        assert!(host.resumes >= 2);
        assert_eq!(host.exits, [status]);
        assert_eq!(host.terminal_dos_calls, 1, "terminal firmware must not replay");
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.tasks.current(), Some(owner));
        assert!(state.classic_dde_task_exit_quiesced(owner));
        assert!(!state.classic_dde_task_exit_needs_pump());
    }
}

#[test]
fn guest_service_waits_for_started_classic_dde_poll_retirement() {
    for engine in [ExecutionEngine::Interpreter, ExecutionEngine::Jit] {
        let (mut runtime, _) = fixture(0x3000);
        runtime.set_execution_engine(engine);
        let mut host = ExitHost { marker_requires_idle_dde: true, ..ExitHost::default() };
        // The first MOV reaches the real scheduler, which starts a poll. The
        // following INT must wait across Started, Complete and source ACK;
        // its deliberate segment-end IRET fault then ends this observation.
        let error = runtime.run_win16_inner(&mut host, 20).unwrap_err();
        assert_eq!(error.kind(), Kind::GuestFault, "{engine:?}: {error}");
        assert_eq!(runtime.instructions, 2);
        assert_eq!(host.callback_markers.len(), 1);
        assert!(host.resumes >= 2);
        assert_eq!(host.retired as u64, host.begins);
        assert!(host.active.is_none());
    }
}

#[test]
fn started_classic_dde_poll_owns_each_turn_until_exact_source_consumption() {
    let (mut runtime, _) = fixture(0x3000);
    let mut host = ExitHost::default();
    let state = runtime.win16.as_mut().unwrap();
    // Admission, delayed progress, and a terminal still awaiting its source
    // ACK all exclude unrelated callbacks. Only consumption releases the turn.
    for _ in 0..3 {
        assert!(state.service_classic_dde_safe_point(
            &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, &mut host,
        ).unwrap());
        assert!(host.active.is_some());
        assert_eq!(host.retired, 0);
    }
    assert!(!state.service_classic_dde_safe_point(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, &mut host,
    ).unwrap());
    assert_eq!(host.begins, 1);
    assert_eq!(host.retired, 1);
    assert!(host.active.is_none());
}

#[test]
fn nonterminal_int21_at_segment_end_still_faults_on_iret() {
    let (mut runtime, _) = fixture(0x3000);
    let mut host = ExitHost::default();
    let error = runtime.run_win16_inner(&mut host, 20).unwrap_err();
    assert_eq!(error.kind(), Kind::GuestFault);
    assert!(error.to_string().contains("segment limit exceeded"), "{error}");
    assert!(error.to_string().contains("offset 0x00000005"), "{error}");
    assert_eq!(runtime.instructions, 2, "invalid ROM IRET must not retire");
    assert_eq!(host.quiesces, 0);
    assert!(host.exits.is_empty());
}

#[test]
fn deferred_exit_pump_leaves_live_toolhelp_callback_runnable() {
    let (mut runtime, _) = fixture(0x4c00);
    let state = runtime.win16.as_mut().unwrap();
    assert!(!state.classic_dde_task_exit_needs_pump());
    state.request_toolhelp_task_termination(0, None).unwrap();
    assert!(state.classic_dde_task_exit_needs_pump());
    // Both an already active callback and one entered by servicing the
    // terminal batch have this guard; neither may be skipped by continue.
    state.callback_kinds.push(super::super::CallbackKind::ToolhelpNotify);
    assert!(!state.classic_dde_task_exit_needs_pump());
    state.callback_kinds.pop();
    assert!(state.classic_dde_task_exit_needs_pump());
}

#[test]
fn terminal_int21_still_respects_outer_instruction_budget() {
    let (mut runtime, _) = fixture(0x4c00);
    let mut host = ExitHost::default();
    let error = runtime.run_win16_inner(&mut host, 2).unwrap_err();
    assert_eq!(error.kind(), Kind::ExecutionLimit);
    assert_eq!(runtime.instructions, 2);
    assert_eq!(host.quiesces, 0);
    assert!(host.exits.is_empty());
    assert!(!runtime.win16.as_ref().unwrap().classic_dde_task_exit_needs_pump());
}

#[test]
fn session_exit_old_exit_windows_terminates_guest_after_native_sources_drain() {
    use guest_core::Selector;
    use win16_abi::{ExportLookupTarget, lookup_export};
    use super::super::ImportBinding;

    // If USER.2 returns without requesting termination, the guest would run
    // INT 21h/4C07h and exit with 7 instead. The service must end it with 0.
    let (mut runtime, owner) = fixture(0x4c07);
    let mut host = ExitHost::default();
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(2)).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let mut frame = 0_u16.to_le_bytes().to_vec();
    frame.extend_from_slice(&return_cs.to_le_bytes());
    let stack = state.selectors.pointer_from_raw(
        Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp(),
    ).unwrap();
    state.selectors.write(&mut runtime.memory, stack, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);

    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, &mut host, 0).unwrap(), None);
    assert!(state.classic_dde_task_exit_needs_pump());
    assert!(host.exits.is_empty());
    assert_eq!(runtime.run_win16_inner(&mut host, 20).unwrap(), 0);
    assert_eq!(runtime.instructions, 0, "no caller instruction may run after USER.2");
    assert_eq!(host.terminal_dos_calls, 0);
    assert_eq!(host.exits, [0]);
    assert!(host.quiesces > 0);
    assert!(host.resumes >= 2);
    assert!(runtime.win16.as_ref().unwrap().classic_dde_task_exit_quiesced(owner));
}
