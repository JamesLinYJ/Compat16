//! In-memory producer for WMF ABI and callback ownership checks.

use super::*;

#[derive(Default)]
pub(super) struct MetafileHost {
    pub(super) calls: usize,
    pub(super) commits: usize,
    pub(super) tables: Vec<Vec<Option<Win16HostGdiObject>>>,
    pub(super) enums: Vec<(u64, Win16HostDc, VecDeque<Vec<u8>>)>,
    pub(super) last_id: u64,
    pub(super) consumed: usize,
}
impl DosHost for MetafileHost {
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

impl RuntimeHost for MetafileHost {
    fn win16_metafile(&mut self, operation: Operation) -> Result<ResultValue, RuntimeError> {
        match operation {
            Operation::CallbackTable { .. } => {
                Ok(ResultValue::Table(self.tables.last().unwrap().clone()))
            }
            Operation::CommitCallbackTable { objects, .. } => {
                *self.tables.last_mut().unwrap() = objects;
                self.commits += 1;
                Ok(ResultValue::TableCommitted)
            }
            Operation::PlayRecord {
                record,
                mut objects,
                ..
            } => {
                self.calls += 1;
                match u16::from_le_bytes([record[4], record[5]]) {
                    0x02fa => {
                        objects[0] = Some(Win16HostGdiObject(0xfedc_0000_0000_0001));
                    }
                    0x01f0 => {
                        let token = objects[0].take().unwrap();
                        return Ok(ResultValue::Record {
                            success: true,
                            objects,
                            retired: vec![token],
                        });
                    }
                    _ => {}
                }
                Ok(ResultValue::Record {
                    success: true,
                    objects,
                    retired: Vec::new(),
                })
            }
            _ => panic!("unexpected WMF host operation"),
        }
    }
    fn win16_window_begin(
        &mut self,
        operation: Win16WindowOperation,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let Win16WindowOperation::EnumMetafile { dc, bits } = operation else {
            panic!("unexpected host operation")
        };
        let parsed = formats::parse_wmf(&bits).unwrap();
        let records = parsed
            .records()
            .filter(|r| !r.is_end())
            .map(|r| r.bytes().to_vec())
            .collect();
        self.last_id += 1;
        let id = self.last_id;
        self.enums.push((id, dc, records));
        self.tables
            .push(vec![None; usize::from(parsed.header().object_count)]);
        Ok(Win16WindowStep::Started {
            operation_id: Win16HostWindowOperationId(id),
            worker_generation: 1,
            kind: Win16NativeWindowOperationKind::EnumMetafile,
            step: Box::new(self.next_step(true)),
        })
    }
    fn win16_window_resume(
        &mut self,
        reply: Option<Win16WindowReply>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        Ok(self.next_step(reply.unwrap().result.value as u16 != 0))
    }
    fn win16_window_source_retirement(
        &mut self,
        operation: Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        Ok(Some(Arc::new(Win16WindowSourceRetiredProof {
            operation,
            worker_generation,
            state: Win16NativeWindowOperationState::Returned,
        })))
    }
    fn win16_window_source_retirement_consumed(
        &mut self,
        _: &Win16WindowSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        self.consumed += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl RuntimeDdeHost for MetafileHost {
    fn win16_dde_abort(&mut self) -> Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl RuntimeMciHost for MetafileHost {}
impl RuntimeMidiHost for MetafileHost {}
impl RuntimeNetbiosHost for MetafileHost {}
impl MetafileHost {
    fn next_step(&mut self, keep_going: bool) -> Win16WindowStep {
        let (id, dc, records) = self.enums.last_mut().unwrap();
        if keep_going && let Some(record) = records.pop_front() {
            return Win16WindowStep::MetafileCallback {
                operation_id: Win16HostWindowOperationId(*id),
                callback: Win16HostCallback(*id * 100 + records.len() as u64 + 1),
                dc: *dc,
                object_count: self.tables.last().unwrap().len() as u16,
                record,
                source: Win16NativeCallbackSource::Metafile { dc: *dc },
            };
        }
        let id = *id;
        self.enums.pop();
        self.tables.pop();
        Win16WindowStep::SourceRetired {
            proof: Arc::new(Win16WindowSourceRetiredProof {
                operation: Win16NativeWindowOperationProof {
                    operation_id: Win16HostWindowOperationId(id),
                    kind: Win16NativeWindowOperationKind::EnumMetafile,
                },
                worker_generation: 1,
                state: Win16NativeWindowOperationState::Returned,
            }),
            result: Box::new(Win16WindowStep::Complete(Win16WindowResult::EnumMetafile {
                success: keep_going,
                retired: Vec::new(),
            })),
        }
    }
}
