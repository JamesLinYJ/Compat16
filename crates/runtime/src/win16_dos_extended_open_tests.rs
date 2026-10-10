//! Extended DOS open through protected INT/IRET and KERNEL DOS3Call.

use super::{firmware_service_at, resolve_interrupt_target};
use super::super::{
    ImportBinding, interrupt_entry,
    kernel_register_calls::{self, Win16KernelRegisterService},
    test_support::tiny_ne_executable,
};
use crate::{Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath, Win16GuestPath};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosDirectoryEntry, DosErrorCode, DosFileAccess, DosFileDisposition,
    DosFileOpenOutcome, DosFileOpenRequest, DosFileOpenResult, DosFileSharing,
    DosFileStatus, DosHost, DosHostError, DosHostFile, DosHostSearch,
    DosIoctlObjectInfo, DosSeekOrigin,
};
use guest_core::{GuestMemory, OwnerId, Registers, Selector, io::NoPorts};
use win16_abi::{Access, AccessRights, ExportLookupTarget, Win16KernelFileSystemRequest, lookup_export};

const PATH_OFFSET: u16 = 0x40;
const RETURN_IP: u16 = 0x12;

#[derive(Default)]
struct ExtendedOpenHost {
    active: Option<(OwnerId, Win16CanonicalPath)>,
    calls: Vec<(OwnerId, Win16CanonicalPath, Vec<u8>, DosFileOpenRequest)>,
    files: Vec<(Win16CanonicalPath, Vec<u8>, u8)>,
    handles: Vec<(DosHostFile, usize)>,
    next_handle: u64,
}

impl DosHost for ExtendedOpenHost {
    fn file_extended_open(
        &mut self, path: &[u8], request: DosFileOpenRequest,
    ) -> Result<DosFileOpenResult, DosHostError> {
        let (owner, directory) = self.active.clone().expect("task directory must be activated first");
        self.calls.push((owner, directory.clone(), path.to_vec(), request));
        assert_eq!(path, b"SHARED.DAT", "DS:SI must reach the protected caller string");
        let existing = self.files.iter().position(|entry| entry.0 == directory && entry.1 == path);
        let (index, outcome) = match (existing, request.disposition) {
            (Some(_), DosFileDisposition::CreateNew) => return Err(DosHostError::new(DosErrorCode::FileExists)),
            (None, DosFileDisposition::OpenExisting) => return Err(DosHostError::new(DosErrorCode::FileNotFound)),
            (Some(index), _) => (index, DosFileOpenOutcome::Opened),
            (None, _) => {
                self.files.push((directory, path.to_vec(), request.attributes));
                (self.files.len() - 1, DosFileOpenOutcome::Created)
            }
        };
        self.next_handle += 1;
        let file = DosHostFile(self.next_handle);
        self.handles.push((file, index));
        Ok(DosFileOpenResult { file, outcome })
    }
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        let entry = self.handles.iter().find(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        Ok(DosIoctlObjectInfo::File { drive: self.files[entry.1].0.drive, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        let entry = self.handles.iter().find(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        Ok(DosFileStatus {
            short_name: *b"SHARED  DAT", size: 0, position: 0,
            attributes: self.files[entry.1].2, write_time: 0, write_date: 0,
        })
    }
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        let index = self.handles.iter().position(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        self.handles.remove(index);
        Ok(())
    }
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
    fn guest_code_page(&self) -> text_codec::CodePage { text_codec::CodePage::Cp437 }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { 3 }
}

impl RuntimeHost for ExtendedOpenHost {
    fn activate_win16_dos_directory(
        &mut self, owner: OwnerId, path: &Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        self.active = Some((owner, path.clone()));
        Ok(())
    }
    fn normalize_win16_dos_path(
        &mut self, _owner: OwnerId, _path: &Win16GuestPath,
    ) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
        panic!("AX=6C00 has no verified FileCDR notification contract")
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for ExtendedOpenHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ExtendedOpenHost {}
impl crate::RuntimeMidiHost for ExtendedOpenHost {}
impl crate::RuntimeNetbiosHost for ExtendedOpenHost {}

#[derive(Clone, Copy, Debug)]
enum Route {
    ProtectedInt21,
    Dos3Call,
}

const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture() -> (Runtime, ExtendedOpenHost) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\EXTOPEN.NE").unwrap();
    let mut host = ExtendedOpenHost::default();
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.create(OwnerId(2), Some(OwnerId(1))).unwrap();
    for (owner, directory) in [(OwnerId(1), "TASK_A"), (OwnerId(2), "TASK_B")] {
        state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
            drive: 2, components: vec![directory.to_owned()],
        }).unwrap();
    }
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), PATH_OFFSET).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, 11, &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, PATH_OFFSET));
    state.selectors.write(&mut runtime.memory, pointer, b"SHARED.DAT\0").unwrap();
    let mut real_bytes = [0; 11];
    runtime.memory.read(guest_core::real_address(runtime.cpu.regs.ds, PATH_OFFSET), &mut real_bytes).unwrap();
    assert_ne!(&real_bytes, b"SHARED.DAT\0");
    // DX is an action code, never a pathname offset. These bytes cover every
    // supported DX value, so a mistaken DS:DX read cannot match SHARED.DAT.
    let wrong = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 1).unwrap();
    state.selectors.write(&mut runtime.memory, wrong, b"WRONG_DX_PATH_XX.DAT\0").unwrap();
    let code = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.cs), 8).unwrap();
    let address = state.selectors.translate(code, Access::Execute, 2, &runtime.memory).unwrap();
    runtime.memory.write(address, &[0xcd, 0x21]).unwrap();
    // Resolve the firmware alias now, before tests deliberately free DS slots.
    resolve_interrupt_target(state, 0x21, &mut runtime.memory).unwrap();
    let procedure = (u32::from(runtime.cpu.regs.cs) << 16) | 0x30;
    assert_eq!(state.execute_kernel_file_system(
        Win16KernelFileSystemRequest::FileCdr { procedure }, &mut runtime.memory, &mut host,
    ).unwrap(), 1);
    assert_eq!(state.kernel_file_system.file_cdr_query(), procedure);
    (runtime, host)
}

fn prepare(runtime: &mut Runtime, route: Route, owner: OwnerId, action: u16) -> Registers {
    let ds = runtime.cpu.regs.ds;
    let ss = runtime.cpu.regs.ss;
    let return_cs = runtime.cpu.regs.cs;
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.dispatch(owner).unwrap();
    runtime.cpu.regs = Registers {
        eax: 0xa1a1_6c00, ebx: 0xb2b2_20c2,
        ecx: 0xc3c3_0002, edx: 0xd4d4_0000 | u32::from(action),
        esp: 0xe5e5_0080, ebp: 0xf6f6_2468, esi: 0x1717_0000 | u32::from(PATH_OFFSET),
        edi: 0x2828_0010, eip: 8, eflags: 0x0ed7,
        cs: return_cs, ds, es: ds, ss, fs: 0x4242, gs: 0x5353,
    };
    let mut expected = runtime.cpu.regs.clone();
    match route {
        Route::ProtectedInt21 => expected.set_ip(10),
        Route::Dos3Call => {
            let stack = state.selectors.pointer_from_raw(Selector(ss), runtime.cpu.regs.sp()).unwrap();
            let mut frame = Vec::from(RETURN_IP.to_le_bytes());
            frame.extend_from_slice(&return_cs.to_le_bytes());
            state.selectors.write(&mut runtime.memory, stack, &frame).unwrap();
            let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(102)).unwrap();
            let slot = state.bindings.len();
            state.bindings.push(ImportBinding::Supported(descriptor));
            runtime.cpu.regs.cs = state.gate_selector.0;
            runtime.cpu.regs.set_ip((slot * 2) as u16);
            expected.set_ip(RETURN_IP);
            expected.set_sp(expected.sp() + 4);
        }
    }
    expected
}

fn call(runtime: &mut Runtime, host: &mut ExtendedOpenHost, route: Route) -> Result<(), RuntimeError> {
    match route {
        Route::ProtectedInt21 => {
            let state = runtime.win16.as_mut().unwrap();
            let segments = crate::win16_loader::Win16Segments {
                selectors: &state.selectors, memory_len: runtime.memory.len(),
            };
            assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
                &segments).unwrap(), x86_cpu::StepOutcome::Interrupt(0x21));
            state.begin_software_interrupt(0x21, &mut runtime.cpu, &mut runtime.memory)?;
            assert_eq!(firmware_service_at(state, runtime.cpu.regs.cs,
                runtime.cpu.regs.ip(), &runtime.memory)?, Some(0x21));
            assert_eq!(interrupt_entry::call_firmware_service(
                state, &mut runtime.dos, 0x21, &mut runtime.cpu.regs, &mut runtime.memory, host,
            )?, DosAction::Continue);
            assert!(!state.begin_pending_file_cdr_callback(
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host,
            )?);
            let segments = crate::win16_loader::Win16Segments {
                selectors: &state.selectors, memory_len: runtime.memory.len(),
            };
            assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
                &segments).unwrap(), x86_cpu::StepOutcome::Continue);
            assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::InterruptReturn));
            state.retire_interrupt_return(&runtime.cpu.regs)?;
        }
        Route::Dos3Call => {
            let service = runtime.win16.as_ref().unwrap()
                .kernel_register_service_at(&runtime.cpu.regs)?.unwrap();
            assert_eq!(service, Win16KernelRegisterService::Dos3Call);
            assert_eq!(kernel_register_calls::dispatch(runtime, service, host, 0)?, None);
        }
    }
    let state = runtime.win16.as_mut().unwrap();
    assert!(!state.kernel_file_system.has_active_callback());
    assert!(!state.begin_pending_file_cdr_callback(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host,
    )?);
    Ok(())
}

#[test]
fn extended_open_routes_use_si_and_activate_task_directories_a_b_a() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture();
        for (index, owner) in [OwnerId(1), OwnerId(2), OwnerId(1)].into_iter().enumerate() {
            let mut expected = prepare(&mut runtime, route, owner, 0x11);
            expected.set_ax(3 + index as u16);
            expected.set_cx(if index < 2 { 2 } else { 1 });
            expected.set_carry(false);
            call(&mut runtime, &mut host, route).unwrap();
            // Includes the full general registers, high halves, data selectors,
            // flags and the checked INT/IRET or DOS3Call far-return adjustment.
            assert_eq!(runtime.cpu.regs, expected, "{route:?}");
            assert_eq!(host.calls[index], (owner, Win16CanonicalPath {
                drive: 2, components: vec![if owner == OwnerId(1) { "TASK_A" } else { "TASK_B" }.to_owned()],
            }, b"SHARED.DAT".to_vec(), DosFileOpenRequest {
                access: DosFileAccess::ReadWrite, sharing: DosFileSharing::DenyNone,
                disposition: DosFileDisposition::OpenOrCreate, attributes: 2,
            }));
        }
        assert_eq!(host.files.len(), 2);
        assert_eq!(host.handles.len(), 3);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
        assert!(host.handles.is_empty());
    }
}

#[test]
fn extended_open_routes_preserve_registers_on_create_collision_and_missing_open() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture();
        for (action, result) in [
            (0x01, Err(DosErrorCode::FileNotFound)),
            (0x10, Ok((3, 2))),
            (0x10, Err(DosErrorCode::FileExists)),
            (0x01, Ok((4, 1))),
        ] {
            let mut expected = prepare(&mut runtime, route, OwnerId(1), action);
            let attributes = if action == 1 { 0xffff } else { 0x27 };
            runtime.cpu.regs.set_cx(attributes);
            expected.set_cx(attributes);
            match result {
                Ok((handle, outcome)) => {
                    expected.set_ax(handle);
                    expected.set_cx(outcome);
                    expected.set_carry(false);
                }
                Err(code) => {
                    runtime.cpu.regs.set_carry(false);
                    expected.set_ax(code as u16);
                    expected.set_carry(true);
                }
            }
            call(&mut runtime, &mut host, route).unwrap();
            assert_eq!(runtime.cpu.regs, expected, "{route:?} action {action:04x}");
        }
        assert_eq!(host.files.len(), 1);
        assert_eq!(host.handles.len(), 2);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
    }
}

#[test]
fn extended_open_routes_reject_replacement_and_reserved_modes_without_host_mutation() {
    for route in ROUTES {
        for (ax, bx, action, error) in [
            (0x6c00, 0x20c2, 0x02, DosErrorCode::InvalidFunction),
            (0x6c00, 0x20c2, 0x12, DosErrorCode::InvalidFunction),
            (0x6c01, 0x20c2, 0x11, DosErrorCode::InvalidFunction),
            (0x6c00, 0x40c2, 0x11, DosErrorCode::InvalidFunction),
            (0x6c00, 0x21c2, 0x11, DosErrorCode::InvalidAccess),
        ] {
            let (mut runtime, mut host) = fixture();
            let mut expected = prepare(&mut runtime, route, OwnerId(1), action);
            runtime.cpu.regs.set_ax(ax);
            runtime.cpu.regs.set_bx(bx);
            runtime.cpu.regs.set_cx(0x27);
            runtime.cpu.regs.set_carry(false);
            expected.set_bx(bx);
            expected.set_cx(0x27);
            expected.set_ax(error as u16);
            expected.set_carry(true);
            call(&mut runtime, &mut host, route).unwrap();
            assert_eq!(runtime.cpu.regs, expected, "{route:?} AX={ax:04x} BX={bx:04x} DX={action:04x}");
            assert!(host.calls.is_empty());
            assert!(host.files.is_empty());
            assert!(host.handles.is_empty());
        }
    }
}

#[test]
fn extended_open_routes_check_invalid_freed_and_recycled_path_selectors() {
    for route in ROUTES {
        for selector_case in 0..4 {
            let (mut runtime, mut host) = fixture();
            prepare(&mut runtime, route, OwnerId(1), 0x11);
            let state = runtime.win16.as_mut().unwrap();
            let selector = match selector_case {
                0 => 0,
                1 => 0xfff8,
                _ => {
                    let original = state.selectors.reference(Selector(runtime.cpu.regs.ds)).unwrap();
                    let base = state.selectors.describe(original).unwrap().base;
                    let saved = state.selectors.alloc_block(base, 0x80, AccessRights::read_only(), &runtime.memory).unwrap();
                    state.selectors.free_block(saved).unwrap();
                    if selector_case == 3 {
                        // Raw selectors are resolved anew for a synchronous call.
                        // Reusing the slot must observe its new short bound, not
                        // the retired mapping in which the path was readable.
                        let replacement = state.selectors.alloc_block(
                            base, u32::from(PATH_OFFSET) + 1, AccessRights::read_only(), &runtime.memory,
                        ).unwrap();
                        assert_eq!(replacement.raw(), saved.raw());
                        assert_ne!(replacement.generation(), saved.generation());
                    }
                    saved.raw().0
                }
            };
            runtime.cpu.regs.ds = selector;
            let error = call(&mut runtime, &mut host, route).unwrap_err();
            assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault, "{route:?} selector case {selector_case}");
            assert!(host.calls.is_empty());
            assert!(host.files.is_empty());
            assert!(host.handles.is_empty());
        }
    }
}
