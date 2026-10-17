//! Real GDI service gates with owned spool tokens; no native printer effects.
use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use super::*;
use crate::{Runtime, Win16HostDc, Win16HostSpoolJob as Job};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Registers, Selector};
use std::collections::VecDeque;
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, Win16Argument as Arg,
    Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

#[derive(Default)]
struct SpoolHost {
    calls: Vec<Win16HostSpoolOperation>,
    replies: VecDeque<Result<Win16HostSpoolResult, RuntimeError>>,
}
impl DosHost for SpoolHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for SpoolHost {
    fn win16_spool(
        &mut self,
        call: Win16HostSpoolOperation,
    ) -> Result<Win16HostSpoolResult, RuntimeError> {
        self.calls.push(call);
        self.replies
            .pop_front()
            .expect("fixture supplies exact host replies")
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeDdeHost for SpoolHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for SpoolHost {}
impl crate::RuntimeMidiHost for SpoolHost {}
impl crate::RuntimeNetbiosHost for SpoolHost {}

const TOKEN: Job = Job::new(0x1234_5678_9abc);
const DATA: [u8; 5] = [0, 0xff, 0x82, 0, 0x7f];
struct Fixture {
    runtime: Runtime,
    host: SpoolHost,
    output: u32,
    title: u32,
    data: u32,
}
impl Fixture {
    fn new() -> Self {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SPOOL.NE").unwrap();
        let state = runtime.win16.as_mut().unwrap();
        let selector = state
            .selectors
            .alloc_block(
                PhysAddr(0x70000),
                256,
                AccessRights::read_write(),
                &runtime.memory,
            )
            .unwrap();
        let output = SegmentedPointer::new(selector, 0);
        let title = SegmentedPointer::new(selector, 16);
        let data = SegmentedPointer::new(selector, 64);
        state
            .selectors
            .write(&mut runtime.memory, output, b"LPT1:\0")
            .unwrap();
        state
            .selectors
            .write(&mut runtime.memory, title, &[0x82, 0xa0, 0xff, 0])
            .unwrap();
        state
            .selectors
            .write(&mut runtime.memory, data, &DATA)
            .unwrap();
        Self {
            runtime,
            host: SpoolHost::default(),
            output: output.far_value(),
            title: title.far_value(),
            data: data.far_value(),
        }
    }
    fn prepare(&mut self, ordinal: u16, args: &[Arg]) -> Registers {
        let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
            panic!("fixed Pascal frame")
        };
        self.runtime.cpu.regs.eax = 0xa1b2_a55a;
        self.runtime.cpu.regs.edx = 0xc3d4_5aa5;
        let mut expected = self.runtime.cpu.regs.clone();
        expected.set_ip(0x12);
        let mut bytes = Vec::from(0x12_u16.to_le_bytes());
        bytes.extend_from_slice(&expected.cs.to_le_bytes());
        for arg in args.iter().rev() {
            match arg {
                Arg::Word(value) => bytes.extend_from_slice(&value.to_le_bytes()),
                Arg::Dword(value) => bytes.extend_from_slice(&value.to_le_bytes()),
                Arg::Byte(_) => panic!("PRINT.H has no byte parameters"),
            }
        }
        assert_eq!(cleanup.callee_pop_bytes as usize + 4, bytes.len());
        expected.set_sp(expected.sp() + bytes.len() as u16);
        let state = self.runtime.win16.as_mut().unwrap();
        let pointer = state
            .selectors
            .pointer_from_raw(
                Selector(self.runtime.cpu.regs.ss),
                self.runtime.cpu.regs.sp(),
            )
            .unwrap();
        state
            .selectors
            .write(&mut self.runtime.memory, pointer, &bytes)
            .unwrap();
        let slot = state.bindings.len();
        state.bindings.push(ImportBinding::Supported(descriptor));
        self.runtime.cpu.regs.cs = state.gate_selector.0;
        self.runtime.cpu.regs.set_ip((slot * 2) as u16);
        expected
    }
    fn dispatch(&mut self) -> Result<Option<u8>, RuntimeError> {
        self.runtime.win16.as_mut().unwrap().dispatch(
            &mut self.runtime.cpu,
            &mut self.runtime.memory,
            &mut self.runtime.dos,
            &mut self.host,
            0,
        )
    }
    fn call(&mut self, ordinal: u16, args: &[Arg], reply: Win16HostSpoolResult, result: u16) {
        self.host.replies.push_back(Ok(reply));
        let mut expected = self.prepare(ordinal, args);
        expected.set_ax(result);
        assert_eq!(self.dispatch().unwrap(), None);
        assert_eq!(self.runtime.cpu.regs, expected);
        assert!(self.host.replies.is_empty());
    }
    fn open(&mut self) -> u16 {
        let args = [
            Arg::Dword(self.output),
            Arg::Dword(self.title),
            Arg::Word(0),
        ];
        self.call(
            240,
            &args,
            Win16HostSpoolResult::OpenJob {
                job: Some(TOKEN),
                native_error: None,
            },
            1,
        );
        assert!(
            matches!(&self.host.calls[0],Win16HostSpoolOperation::OpenJob {
            owner:OwnerId(1),output_target,document_name,legacy_argument:0
        } if output_target==b"LPT1:" && document_name==&[0x82,0xa0,0xff])
        );
        1
    }
    fn direct(&mut self, request: Request) -> Result<u32, RuntimeError> {
        self.runtime.win16.as_mut().unwrap().execute_gdi_spool(
            request,
            &mut self.runtime.memory,
            &mut self.host,
        )
    }
    fn far_at(&self, offset: u16) -> u32 {
        let state = self.runtime.win16.as_ref().unwrap();
        let base = state.selectors.pointer_from_far(self.output).unwrap();
        SegmentedPointer::new(base.selector(), offset).far_value()
    }
    fn write_guest(&mut self, offset: u16, bytes: &[u8]) {
        let far = self.far_at(offset);
        let state = self.runtime.win16.as_mut().unwrap();
        let pointer = state.selectors.pointer_from_far(far).unwrap();
        state
            .selectors
            .write(&mut self.runtime.memory, pointer, bytes)
            .unwrap();
    }
    fn read_guest(&self, offset: u16, len: usize) -> Vec<u8> {
        let far = self.far_at(offset);
        let state = self.runtime.win16.as_ref().unwrap();
        let pointer = state.selectors.pointer_from_far(far).unwrap();
        let mut bytes = vec![0; len];
        state
            .selectors
            .read(&self.runtime.memory, pointer, &mut bytes)
            .unwrap();
        bytes
    }
    fn call_local(&mut self, ordinal: u16, args: &[Arg], result: u16) {
        let calls = self.host.calls.len();
        let mut expected = self.prepare(ordinal, args);
        expected.set_ax(result);
        assert_eq!(self.dispatch().unwrap(), None);
        assert_eq!(self.runtime.cpu.regs, expected);
        assert!(self.host.replies.is_empty());
        assert_eq!(self.host.calls.len(), calls);
    }
}
fn status(succeeded: bool, native_error: Option<u32>) -> Win16HostSpoolResult {
    Win16HostSpoolResult::Status {
        succeeded,
        native_error,
    }
}

#[test]
fn gdi_spool_gate_runs_open_page_binary_write_end_close_with_word_returns() {
    let mut f = Fixture::new();
    let job = f.open();
    f.call(246, &[Arg::Word(job)], status(true, None), 1);
    let args = [
        Arg::Word(job),
        Arg::Dword(f.data),
        Arg::Word(DATA.len() as u16),
    ];
    f.call(
        241,
        &args,
        Win16HostSpoolResult::Write {
            bytes_written: 3,
            native_error: None,
        },
        3,
    );
    f.call(247, &[Arg::Word(job)], status(true, None), 1);
    f.call(243, &[Arg::Word(job)], status(true, None), 1);
    assert!(matches!(&f.host.calls[1],Win16HostSpoolOperation::StartPage {job} if *job==TOKEN));
    assert!(
        matches!(&f.host.calls[2],Win16HostSpoolOperation::Write {job,bytes} if *job==TOKEN && bytes==&DATA)
    );
    assert!(matches!(&f.host.calls[3],Win16HostSpoolOperation::EndPage {job} if *job==TOKEN));
    assert!(matches!(&f.host.calls[4],Win16HostSpoolOperation::CloseJob {job} if *job==TOKEN));
    assert!(
        !f.runtime
            .win16
            .as_ref()
            .unwrap()
            .network_print_jobs
            .contains_key(&OwnerId(1))
    );
    assert_eq!(
        f.direct(Request::StartSpoolPage { job }).unwrap(),
        GDI_ERROR
    );
    assert_eq!(f.host.calls.len(), 5);
}

#[test]
fn gdi_spool_delete_forwards_dummy_word_and_retires_only_its_exact_job() {
    let mut f = Fixture::new();
    let job = f.open();
    f.call(
        244,
        &[Arg::Word(job), Arg::Word(0x8001)],
        status(true, None),
        1,
    );
    assert!(
        matches!(&f.host.calls[1],Win16HostSpoolOperation::DeleteJob {job,legacy_argument:-32767} if *job==TOKEN)
    );
    assert_eq!(
        f.direct(Request::DeleteJob {
            job,
            legacy_argument: 0
        })
        .unwrap(),
        GDI_ERROR
    );
    assert_eq!(f.host.calls.len(), 2);
}

#[test]
fn gdi_spool_native_errors_remain_negative_sdk_statuses() {
    for (error, word) in [
        (5, 0xffff),
        (39, 0xfffc),
        (112, 0xfffc),
        (8, 0xfffb),
        (14, 0xfffb),
        (995, 0xffff),
        (1223, 0xffff),
    ] {
        let mut f = Fixture::new();
        let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(0)];
        f.call(
            240,
            &args,
            Win16HostSpoolResult::OpenJob {
                job: None,
                native_error: Some(error),
            },
            word,
        );
        let job = f.open();
        f.call(246, &[Arg::Word(job)], status(false, Some(error)), word);
        let args = [Arg::Word(job), Arg::Dword(f.data), Arg::Word(5)];
        f.call(
            241,
            &args,
            Win16HostSpoolResult::Write {
                bytes_written: 0,
                native_error: Some(error),
            },
            word,
        );
        f.call(243, &[Arg::Word(job)], status(false, Some(error)), word);
        assert_eq!(
            f.runtime.win16.as_ref().unwrap().network_print_jobs[&OwnerId(1)]
                .host_gdi_job_for_id(job),
            Some(TOKEN)
        );
        f.call(243, &[Arg::Word(job)], status(true, None), 1);
        let before = f.host.calls.len();
        assert_eq!(f.direct(Request::CloseJob { job }).unwrap(), GDI_ERROR);
        assert_eq!(f.host.calls.len(), before);
    }
}

#[test]
fn gdi_spool_unknown_wrong_kind_and_foreign_task_handles_have_no_host_effects() {
    let mut f = Fixture::new();
    let job = f.open();
    let state = f.runtime.win16.as_mut().unwrap();
    let network = state
        .network_print_jobs
        .get_mut(&OwnerId(1))
        .unwrap()
        .guest_job_id_for(Job::new(99))
        .unwrap();
    for alias in [0, 0xffff, network, 0x7fff] {
        assert_eq!(
            f.direct(Request::StartSpoolPage { job: alias }).unwrap(),
            GDI_ERROR
        );
        assert_eq!(
            f.direct(Request::EndSpoolPage { job: alias }).unwrap(),
            GDI_ERROR
        );
        assert_eq!(
            f.direct(Request::CloseJob { job: alias }).unwrap(),
            GDI_ERROR
        );
        assert_eq!(
            f.direct(Request::DeleteJob {
                job: alias,
                legacy_argument: 0
            })
            .unwrap(),
            GDI_ERROR
        );
        assert_eq!(
            f.direct(Request::WriteSpool {
                job: alias,
                byte_count: 1,
                bytes: vec![1]
            })
            .unwrap(),
            GDI_ERROR
        );
    }
    let state = f.runtime.win16.as_mut().unwrap();
    state.tasks.create(OwnerId(2), Some(OwnerId(1))).unwrap();
    state.tasks.dispatch(OwnerId(2)).unwrap();
    assert_eq!(
        f.direct(Request::StartSpoolPage { job }).unwrap(),
        GDI_ERROR
    );
    assert_eq!(f.host.calls.len(), 1);
    f.runtime
        .win16
        .as_mut()
        .unwrap()
        .tasks
        .dispatch(OwnerId(1))
        .unwrap();
    f.host.replies.push_back(Ok(status(true, None)));
    assert_eq!(f.direct(Request::StartSpoolPage { job }).unwrap(), 1);
    assert!(f.host.replies.is_empty());
}

#[test]
fn gdi_spool_zero_count_ignores_pointer_and_negative_or_mismatched_count_has_no_effect() {
    let mut f = Fixture::new();
    let job = f.open();
    f.call(
        241,
        &[Arg::Word(job), Arg::Dword(0xffff_ffff), Arg::Word(0)],
        Win16HostSpoolResult::Write {
            bytes_written: 0,
            native_error: None,
        },
        0,
    );
    assert!(
        matches!(&f.host.calls[1],Win16HostSpoolOperation::Write {bytes,..} if bytes.is_empty())
    );
    assert_eq!(
        f.direct(Request::WriteSpool {
            job,
            byte_count: -1,
            bytes: Vec::new()
        })
        .unwrap(),
        GDI_ERROR
    );
    assert_eq!(
        f.direct(Request::WriteSpool {
            job,
            byte_count: 2,
            bytes: vec![1]
        })
        .unwrap(),
        GDI_ERROR
    );
    assert_eq!(f.host.calls.len(), 2);
}

#[test]
fn gdi_spool_invalid_abort_dc_does_not_start_a_native_document() {
    let mut f = Fixture::new();
    let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(0xffff)];
    let mut expected = f.prepare(240, &args);
    expected.set_ax(0xffff);
    assert_eq!(f.dispatch().unwrap(), None);
    assert_eq!(f.runtime.cpu.regs, expected);
    assert!(f.host.calls.is_empty());
    let dc = f
        .runtime
        .win16
        .as_mut()
        .unwrap()
        .guest_gdi
        .allocate_dc(Win16HostDc(77))
        .unwrap();
    f.call(
        240,
        &[Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(dc)],
        Win16HostSpoolResult::OpenJob {
            job: Some(TOKEN),
            native_error: None,
        },
        1,
    );
}

#[test]
fn gdi_spool_host_failure_or_wrong_completion_never_commits_a_guest_return() {
    for reply in [
        Err(RuntimeError::new(
            Kind::HostFailure,
            "injected native failure",
        )),
        Ok(Win16HostSpoolResult::Write {
            bytes_written: 99,
            native_error: None,
        }),
        Ok(status(true, Some(5))),
    ] {
        let mut f = Fixture::new();
        let job = f.open();
        let _expected = f.prepare(246, &[Arg::Word(job)]);
        let before = f.runtime.cpu.regs.clone();
        f.host.replies.push_back(reply);
        assert!(f.dispatch().is_err());
        assert_eq!(f.runtime.cpu.regs, before);
        assert_eq!(
            f.runtime.win16.as_ref().unwrap().network_print_jobs[&OwnerId(1)]
                .host_gdi_job_for_id(job),
            Some(TOKEN)
        );
    }
    let mut f = Fixture::new();
    let job = f.open();
    let _expected = f.prepare(241, &[Arg::Word(job), Arg::Dword(f.data), Arg::Word(5)]);
    let before = f.runtime.cpu.regs.clone();
    f.host.replies.push_back(Ok(Win16HostSpoolResult::Write {
        bytes_written: 6,
        native_error: None,
    }));
    assert_eq!(f.dispatch().unwrap_err().kind(), Kind::InternalInvariant);
    assert_eq!(f.runtime.cpu.regs, before);
}

#[test]
fn gdi_spool_unexposed_error_token_is_released_and_owner_cleanup_retries_native_failure() {
    let mut f = Fixture::new();
    f.host.replies.extend([
        Ok(Win16HostSpoolResult::OpenJob {
            job: Some(TOKEN),
            native_error: Some(112),
        }),
        Ok(status(false, Some(5))),
    ]);
    let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(0)];
    let mut expected = f.prepare(240, &args);
    expected.set_ax(0xfffc);
    assert_eq!(f.dispatch().unwrap(), None);
    assert_eq!(f.runtime.cpu.regs, expected);
    assert!(
        matches!(&f.host.calls[1],Win16HostSpoolOperation::ReleaseNetworkJob {job} if *job==TOKEN)
    );
    f.host.replies.push_back(Ok(status(true, None)));
    f.runtime
        .win16
        .as_mut()
        .unwrap()
        .cleanup_network_print_task(OwnerId(1), &mut f.host)
        .unwrap();
    assert!(matches!(
        &f.host.calls[2],
        Win16HostSpoolOperation::ReleaseNetworkOwner { owner: OwnerId(1) }
    ));
    assert!(
        !f.runtime
            .win16
            .as_ref()
            .unwrap()
            .network_print_jobs
            .contains_key(&OwnerId(1))
    );
}

#[test]
fn gdi_spool_failed_close_keeps_alias_until_owner_cleanup_acknowledges_release() {
    let mut f = Fixture::new();
    let job = f.open();
    f.call(243, &[Arg::Word(job)], status(false, Some(5)), 0xffff);
    assert_eq!(
        f.runtime.win16.as_ref().unwrap().network_print_jobs[&OwnerId(1)].host_gdi_job_for_id(job),
        Some(TOKEN)
    );
    f.host.replies.push_back(Ok(status(false, Some(5))));
    assert!(
        f.runtime
            .win16
            .as_mut()
            .unwrap()
            .cleanup_network_print_task(OwnerId(1), &mut f.host)
            .is_err()
    );
    assert_eq!(
        f.runtime.win16.as_ref().unwrap().network_print_jobs[&OwnerId(1)].host_gdi_job_for_id(job),
        Some(TOKEN)
    );
    f.host.replies.push_back(Ok(status(true, None)));
    f.runtime
        .win16
        .as_mut()
        .unwrap()
        .cleanup_network_print_task(OwnerId(1), &mut f.host)
        .unwrap();
    assert!(matches!(
        &f.host.calls[2],
        Win16HostSpoolOperation::ReleaseNetworkOwner { owner: OwnerId(1) }
    ));
    assert!(matches!(
        &f.host.calls[3],
        Win16HostSpoolOperation::ReleaseNetworkOwner { owner: OwnerId(1) }
    ));
    assert!(
        !f.runtime
            .win16
            .as_ref()
            .unwrap()
            .network_print_jobs
            .contains_key(&OwnerId(1))
    );
}

#[test]
fn gdi_spool_failed_delete_keeps_alias_for_an_exact_retry() {
    let mut f = Fixture::new();
    let job = f.open();
    f.call(
        244,
        &[Arg::Word(job), Arg::Word(0)],
        status(false, Some(5)),
        0xffff,
    );
    assert_eq!(
        f.runtime.win16.as_ref().unwrap().network_print_jobs[&OwnerId(1)].host_gdi_job_for_id(job),
        Some(TOKEN)
    );
    f.call(244, &[Arg::Word(job), Arg::Word(0)], status(true, None), 1);
    assert!(
        !f.runtime
            .win16
            .as_ref()
            .unwrap()
            .network_print_jobs
            .contains_key(&OwnerId(1))
    );
    assert_eq!(f.host.calls.len(), 3);
    assert!(f.host.calls[1..].iter().all(|call| matches!(call,
        Win16HostSpoolOperation::DeleteJob {job,legacy_argument:0} if *job==TOKEN)));
}

#[test]
fn gdi_spool_owner_fallback_runs_even_after_empty_guest_table_was_removed() {
    let mut f = Fixture::new();
    let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(0)];
    f.call(
        240,
        &args,
        Win16HostSpoolResult::OpenJob {
            job: None,
            native_error: Some(112),
        },
        0xfffc,
    );
    f.runtime
        .win16
        .as_mut()
        .unwrap()
        .drop_empty_network_print_owner(OwnerId(1));
    assert!(
        !f.runtime
            .win16
            .as_ref()
            .unwrap()
            .network_print_jobs
            .contains_key(&OwnerId(1))
    );
    for ok in [false, true] {
        f.host
            .replies
            .push_back(Ok(status(ok, if ok { None } else { Some(5) })));
        assert_eq!(
            f.runtime
                .win16
                .as_mut()
                .unwrap()
                .cleanup_network_print_task(OwnerId(1), &mut f.host)
                .is_ok(),
            ok
        );
    }
    assert!(f.host.calls[1..].iter().all(|call| matches!(
        call,
        Win16HostSpoolOperation::ReleaseNetworkOwner { owner: OwnerId(1) }
    )));
}

#[test]
fn gdi_spool_exhausted_positive_aliases_return_outofmemory_and_release_unexposed_job() {
    let mut f = Fixture::new();
    let jobs = f
        .runtime
        .win16
        .as_mut()
        .unwrap()
        .network_print_jobs
        .entry(OwnerId(1))
        .or_default();
    for id in 1..=i16::MAX as u16 {
        assert_eq!(jobs.guest_job_id_for(Job::new(u64::from(id))).unwrap(), id);
    }
    f.host.replies.extend([
        Ok(Win16HostSpoolResult::OpenJob {
            job: Some(TOKEN),
            native_error: None,
        }),
        Ok(status(true, None)),
    ]);
    let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(0)];
    let mut expected = f.prepare(240, &args);
    expected.set_ax(0xfffb);
    assert_eq!(f.dispatch().unwrap(), None);
    assert_eq!(f.runtime.cpu.regs, expected);
    assert!(
        matches!(&f.host.calls[1],Win16HostSpoolOperation::ReleaseNetworkJob {job} if *job==TOKEN)
    );
    let jobs = &f.runtime.win16.as_ref().unwrap().network_print_jobs[&OwnerId(1)];
    assert_eq!(jobs.host_job_for_id(1), Some(Job::new(1)));
    assert_eq!(jobs.host_job_for_id(0x7fff), Some(Job::new(0x7fff)));
    assert_eq!(jobs.host_gdi_job_for_id(1), None);
}

#[test]
fn gdi_environment_get_and_set_report_size_and_leave_the_uncopied_tail() {
    let mut f = Fixture::new();
    let port = f.output;
    let source = f.far_at(96);
    let dest = f.far_at(160);
    let block = [0x41, 0, 0xff, 0x82];
    f.write_guest(96, &block);
    f.write_guest(160, &[0xcc; 16]);
    f.call_local(132, &[Arg::Dword(0), Arg::Dword(0), Arg::Word(0)], 0);
    f.call_local(132, &[Arg::Dword(port), Arg::Dword(0), Arg::Word(0)], 1);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(dest), Arg::Word(16)], 0);
    assert_eq!(f.read_guest(160, 16), vec![0xcc; 16]);
    f.call_local(
        132,
        &[Arg::Dword(port), Arg::Dword(source), Arg::Word(4)],
        4,
    );
    f.call_local(132, &[Arg::Dword(port), Arg::Dword(0), Arg::Word(4)], 0);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(0), Arg::Word(1)], 4);
    assert_eq!(f.read_guest(160, 16), vec![0xcc; 16]);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(dest), Arg::Word(4)], 4);
    let mut copied = vec![0xcc; 16];
    copied[..4].copy_from_slice(&block);
    assert_eq!(f.read_guest(160, 16), copied);
    f.write_guest(160, &[0xcc; 16]);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(dest), Arg::Word(2)], 2);
    let short = f.read_guest(160, 16);
    assert_eq!(&short[..2], &block[..2]);
    assert_eq!(&short[2..], &[0xcc; 14]);
    f.write_guest(160, &[0xcc; 16]);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(dest), Arg::Word(16)], 4);
    let wide = f.read_guest(160, 16);
    assert_eq!(&wide[..4], &block);
    assert_eq!(&wide[4..], &[0xcc; 12]);
    f.write_guest(160, &[0xcc; 16]);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(dest), Arg::Word(0)], 0);
    assert_eq!(f.read_guest(160, 16), vec![0xcc; 16]);
    f.call_local(
        132,
        &[Arg::Dword(port), Arg::Dword(0xffff_ffff), Arg::Word(0)],
        1,
    );
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(0), Arg::Word(0)], 0);
    const NAMED: [u8; 9] = *b"Laser\0\xff\x00\x82";
    let named = &NAMED;
    f.write_guest(96, named);
    f.write_guest(208, b"Laser\0");
    f.call_local(
        132,
        &[
            Arg::Dword(0),
            Arg::Dword(source),
            Arg::Word(named.len() as u16),
        ],
        named.len() as u16,
    );
    f.write_guest(160, &[0xcc; 16]);
    f.call_local(133, &[Arg::Dword(0), Arg::Dword(dest), Arg::Word(16)], 0);
    assert_eq!(f.read_guest(160, 16), vec![0xcc; 16]);
    let laser = f.far_at(208);
    f.call_local(
        133,
        &[Arg::Dword(laser), Arg::Dword(dest), Arg::Word(16)],
        named.len() as u16,
    );
    let stored = f.read_guest(160, 16);
    assert_eq!(&stored[..named.len()], &named[..]);
    assert_eq!(&stored[named.len()..], &[0xcc; 16 - NAMED.len()]);
    f.call_local(133, &[Arg::Dword(port), Arg::Dword(0), Arg::Word(0)], 0);
    assert!(f.host.calls.is_empty());
}

#[test]
fn gdi_query_abort_during_an_open_job_continues_and_leaves_the_job_open() {
    let mut f = Fixture::new();
    let dc = f
        .runtime
        .win16
        .as_mut()
        .unwrap()
        .guest_gdi
        .allocate_dc(Win16HostDc(0x51))
        .unwrap();
    let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(dc)];
    f.call(
        240,
        &args,
        Win16HostSpoolResult::OpenJob {
            job: Some(TOKEN),
            native_error: None,
        },
        1,
    );
    assert!(
        matches!(&f.host.calls[0], Win16HostSpoolOperation::OpenJob { legacy_argument, .. } if *legacy_argument == dc)
    );
    f.call_local(155, &[Arg::Word(dc), Arg::Word(0)], 1);
    f.call_local(155, &[Arg::Word(dc), Arg::Word(0xfffc)], 1);
    f.call_local(155, &[Arg::Word(0xffff), Arg::Word(0)], 0);
    assert_eq!(f.host.calls.len(), 1);
    f.call(246, &[Arg::Word(1)], status(true, None), 1);
    assert!(
        matches!(&f.host.calls[1], Win16HostSpoolOperation::StartPage { job } if *job == TOKEN)
    );
}

#[test]
fn gdi_spool_default_host_reports_an_explicit_gap() {
    let mut f = Fixture::new();
    let args = [Arg::Dword(f.output), Arg::Dword(f.title), Arg::Word(0)];
    let _expected = f.prepare(240, &args);
    let before = f.runtime.cpu.regs.clone();
    let error = f
        .runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut f.runtime.cpu,
            &mut f.runtime.memory,
            &mut f.runtime.dos,
            &mut NoHost,
            0,
        )
        .unwrap_err();
    assert_eq!(error.kind(), Kind::CompatibilityGap);
    assert_eq!(f.runtime.cpu.regs, before);
}
