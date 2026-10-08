//! LZEXPAND calls using the task's common checked Win16 HFILE namespace.
//!
//! Compressed LZ handles are typed entries in `Win16State.files`; ordinary
//! handles remain valid inputs to LZRead/LZSeek/LZCopy/LZClose. Guest HFILEs
//! are allocated from the existing low-number range, never from a second LZ
//! number space.

use guest_core::Registers;
use guest_core::memory::Memory;
use compat_services::win16_lzexpand::{OFSTRUCT_BYTES, Win16LzFileHandle};
use win16_abi::{Win16LzExpandRequest, Win16ReturnKind};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostLzInit,
    Win16HostLzName, Win16HostLzRead};

const LZERROR_BADINHANDLE: u32 = (-1i32) as u32;
const LZERROR_BADOUTHANDLE: u32 = (-2i32) as u32;
const LZERROR_GLOBALLOC: u32 = (-5i32) as u32;
const LZERROR_BADVALUE: u32 = (-7i32) as u32;

impl Win16State {
    pub(super) fn lzexpand_compat_api(
        &mut self,
        request: Win16LzExpandRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let value = match request {
            Win16LzExpandRequest::LzStart => u32::from(host.win16_lz_start()? as u16),
            Win16LzExpandRequest::LzDone => {
                host.win16_lz_done()?;
                0
            }
            Win16LzExpandRequest::LzOpenFile { path, ofstruct, style } => {
                let pointer = self.selectors.pointer_from_far(ofstruct)
                    .map_err(crate::runtime_error)?;
                let previous = self.read_text_bytes(memory, pointer, OFSTRUCT_BYTES)?;
                let output = self.prepare_text_write(memory, pointer, OFSTRUCT_BYTES)?;
                let opened = host.win16_lz_open_file(&path, style, previous)?;
                if opened.ofstruct.len() != OFSTRUCT_BYTES {
                    if let Some(file) = opened.file {
                        let _ = host.win16_file_close(file)?;
                    }
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "host LZOpenFile returned an invalid OFSTRUCT size"));
                }
                if let Err(error) = output.commit(memory, &opened.ofstruct) {
                    if let Some(file) = opened.file {
                        let _ = host.win16_file_close(file)?;
                    }
                    return Err(error);
                }

                let mut guest_file = None;
                let value = if opened.result < 0 {
                    if opened.file.is_some() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "host LZOpenFile returned a file for a failed result"));
                    }
                    u32::from(opened.result as u16)
                } else {
                    if let Some(file) = opened.file {
                        if let Some(number) = self.allocate_file_number(file) {
                            guest_file = Some(number);
                            u32::from(number)
                        } else {
                            let _ = host.win16_file_close(file)?;
                            LZERROR_GLOBALLOC
                        }
                    } else {
                        u32::from(opened.result as u16)
                    }
                };
                host.observe_win16_io(&crate::Win16IoEvent::LzOpen {
                    path: &path, style, result: value, file: guest_file,
                });
                value
            }
            Win16LzExpandRequest::LzInit { file } => {
                let Some(number) = guest_hfile(file) else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let Some(source) = self.files.get(&number).copied() else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                // Reserve a guest slot before LZInit. Closing a just-created
                // LZ token during rollback can consume its source HFILE.
                let new_number = self.next_free_file_number();
                let value = match host.win16_lz_init(source, new_number.is_some())? {
                    Win16HostLzInit::File(initialized) if initialized == source => {
                        u32::from(number)
                    }
                    Win16HostLzInit::File(initialized) => {
                        let new_number = new_number.ok_or_else(|| RuntimeError::new(
                            Kind::InternalInvariant,
                            "host LZInit created a stream without a reserved guest handle"))?;
                        self.files.insert(new_number, initialized);
                        u32::from(new_number)
                    }
                    Win16HostLzInit::Error(error) => u32::from(error as u16),
                };
                host.observe_win16_io(&crate::Win16IoEvent::Alias {
                    operation: "lz-init", source: number, result: value,
                });
                value
            }
            Win16LzExpandRequest::LzRead { file, output, count } => {
                let Some(number) = guest_hfile(file) else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let Some(host_file) = self.files.get(&number).copied() else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let capacity = usize::from(count);
                let destination = if capacity == 0 {
                    None
                } else {
                    let pointer = self.selectors.pointer_from_far(output)
                        .map_err(crate::runtime_error)?;
                    Some((pointer, self.prepare_text_write(memory, pointer, capacity)?))
                };

                let read = host.win16_lz_read(host_file, count)?;
                let read_result = match &read {
                    Some(Win16HostLzRead::Bytes(bytes)) => bytes.len() as u32,
                    Some(Win16HostLzRead::Error(error)) => *error as i32 as u32,
                    None => LZERROR_BADINHANDLE,
                };
                host.observe_win16_io(&crate::Win16IoEvent::Transfer {
                    operation: "lz-read-native", file: number, buffer: output,
                    requested: i32::from(count), result: Some(read_result),
                });
                let bytes = match read {
                    Some(Win16HostLzRead::Bytes(bytes)) => Some(bytes),
                    Some(Win16HostLzRead::Error(error)) => {
                        return self.finish_lz(registers, return_to,
                            error as i32 as u32, return_kind);
                    }
                    None => None,
                };
                let Some(bytes) = bytes else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                if bytes.len() > capacity {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "host LZRead exceeded the requested guest byte count"));
                }
                if let Some((_, prepared)) = destination {
                    prepared.commit(memory, &bytes)?;
                }
                host.observe_win16_io(&crate::Win16IoEvent::Transfer {
                    operation: "lz-read-complete", file: number, buffer: output,
                    requested: i32::from(count), result: Some(bytes.len() as u32),
                });
                u32::from(bytes.len() as u16)
            }
            Win16LzExpandRequest::LzSeek { file, offset, origin } => {
                let Some(number) = guest_hfile(file) else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let Some(host_file) = self.files.get(&number).copied() else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let position = host.win16_lz_seek(host_file, offset, origin)?;
                let value = position.map_or(LZERROR_BADINHANDLE, |position| position as u32);
                host.observe_win16_io(&crate::Win16IoEvent::Seek {
                    operation: "lz-seek", file: number, offset, origin, result: Some(value),
                });
                value
            }
            Win16LzExpandRequest::LzClose { file } => {
                let Some(number) = guest_hfile(file) else {
                    return self.finish_lz(registers, return_to, 0, return_kind);
                };
                let Some(host_file) = self.files.get(&number).copied() else {
                    return self.finish_lz(registers, return_to, 0, return_kind);
                };
                let closed = host.win16_lz_close(host_file)?;
                let consumed_sources = closed.consumed_source.map(|source| {
                    self.files.iter().filter_map(|(&number, &file)|
                        (file == source).then_some(number)).collect::<Vec<_>>()
                }).unwrap_or_default();
                self.invalidate_file_close(host_file, closed);
                host.observe_win16_io(&crate::Win16IoEvent::LzClose {
                    file: number, closed: closed.closed, consumed_sources: &consumed_sources,
                });
                0
            }
            Win16LzExpandRequest::LzCopy { source, destination }
            | Win16LzExpandRequest::LzCopyFile { source, destination } => {
                let Some(source_number) = guest_hfile(source) else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let Some(source_file) = self.files.get(&source_number).copied() else {
                    return self.finish_lz(registers, return_to, LZERROR_BADINHANDLE, return_kind);
                };
                let Some(destination_number) = guest_hfile(destination) else {
                    return self.finish_lz(registers, return_to,
                        LZERROR_BADOUTHANDLE, return_kind);
                };
                let Some(destination_file) = self.files.get(&destination_number).copied() else {
                    return self.finish_lz(registers, return_to,
                        LZERROR_BADOUTHANDLE, return_kind);
                };
                let value = host.win16_lz_copy(source_file, destination_file)?
                    .map_or(LZERROR_BADINHANDLE, |copied| copied as u32);
                host.observe_win16_io(&crate::Win16IoEvent::Copy {
                    source: source_number, destination: destination_number, result: value,
                });
                value
            }
            Win16LzExpandRequest::LzGetExpandedName { source, output } => {
                let pointer = self.selectors.pointer_from_far(output)
                    .map_err(crate::runtime_error)?;
                match host.win16_lz_get_expanded_name(&source)? {
                    Win16HostLzName::Name(mut name) if !name.contains(&0) => {
                        let length = name.len().checked_add(1).ok_or_else(||
                            RuntimeError::new(Kind::ResourceExhausted,
                                "expanded Win16 path length overflow"))?;
                        let prepared = self.prepare_text_write(memory, pointer, length)?;
                        name.push(0);
                        prepared.commit(memory, &name)?;
                        1
                    }
                    Win16HostLzName::Name(_) => LZERROR_BADVALUE,
                    Win16HostLzName::Error(error) => error as i32 as u32,
                }
            }
        };

        self.finish_lz(registers, return_to, value, return_kind)
    }

    fn finish_lz(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
        value: u32,
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(registers, return_to.0, return_to.1,
            return_to.2, value, return_kind)
    }
}

fn guest_hfile(file: i16) -> Option<u16> {
    Win16LzFileHandle::from_signed(file)
        .map(|handle| handle.guest_word())
}
