//! Win16 task HFILE ownership and storage-query result conversion.

use super::{FIRST_GUEST_HFILE, Win16State};
use compat_services::win16_lzexpand::OFSTRUCT_BYTES;
use guest_core::memory::Memory;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDriveKind, Win16HostFile,
    Win16HostFileClose};

// Windows 3.1 GetDriveType results. Zero means the type cannot be
// determined. One means the root directory does not exist. WINDOWS.H names
// the media results 2, 3, and 4. KB Q105922 classifies RAM disks as fixed
// media and MSCDEX CD-ROMs as remote drives, so this call does not return
// the later CD-ROM or RAM-disk codes.
const DRIVE_UNKNOWN: u16 = 0;
const DRIVE_NO_ROOT_DIR: u16 = 1;
const DRIVE_REMOVABLE: u16 = 2;
const DRIVE_FIXED: u16 = 3;
const DRIVE_REMOTE: u16 = 4;

// LZEXPAND shares this HFILE table and uses negative INT16 values for errors.
// Allocate only handles representable by both KERNEL and LZEXPAND callers.
const LAST_GUEST_HFILE: u16 = i16::MAX as u16;

impl Win16State {
    pub(super) fn open_structured_file(
        &mut self, path: &[u8], ofstruct: u32, style: u16,
        memory: &mut Memory, host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(ofstruct).map_err(crate::runtime_error)?;
        let previous = self.read_text_bytes(memory, pointer, OFSTRUCT_BYTES)?;
        let output = self.prepare_text_write(memory, pointer, OFSTRUCT_BYTES)?;
        // OF_REOPEN reads its saved pathname before considering any other flag.
        let input = if style & 0x8000 != 0 {
            let saved = &previous[8..];
            &saved[..saved.iter().position(|&byte| byte == 0).unwrap_or(saved.len())]
        } else { path };
        let text = host.decode_win16_ansi(input)?;
        let search_name = (style & 0x9100 == 0 && !text.contains(['\\', '/', ':']))
            .then_some(text.as_str());
        let Some(resolved) = self.legacy_file_path(input, host)? else {
            let mut failed = previous;
            if style & 0x8000 == 0 { failed[0] = OFSTRUCT_BYTES as u8; }
            failed[2..4].copy_from_slice(&3u16.to_le_bytes());
            output.commit(memory, &failed)?;
            return Ok(super::INVALID_GUEST_HFILE);
        };
        let opened = host.win16_open_file(&resolved, search_name, style, previous)?;
        if opened.ofstruct.len() != OFSTRUCT_BYTES {
            if let Some(file) = opened.file { let _ = host.win16_file_close(file)?; }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host OpenFile returned an invalid OFSTRUCT size"));
        }
        if let Err(error) = output.commit(memory, &opened.ofstruct) {
            if let Some(file) = opened.file { let _ = host.win16_file_close(file)?; }
            return Err(error);
        }
        let result = match opened.file {
            Some(file) if opened.result >= 0 => match self.allocate_file_number(file) {
                Some(number) => number,
                None => { let _ = host.win16_file_close(file)?; super::INVALID_GUEST_HFILE }
            },
            Some(file) => {
                let _ = host.win16_file_close(file)?;
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "host OpenFile returned a file for a failed result"));
            }
            None => opened.result as u16,
        };
        host.observe_win16_io(&crate::Win16IoEvent::Open {
            path, mode: style, created: style & 0x1000 != 0, result: Some(result),
        });
        Ok(result)
    }

    pub(super) fn open_legacy_file(
        &mut self, path: &[u8], mode: u16, created: bool, host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(resolved) = self.legacy_file_path(path, host)? else {
            return Ok(super::INVALID_GUEST_HFILE);
        };
        let opened = if created {
            host.win16_file_create(&resolved, mode)
        } else {
            host.win16_file_open(&resolved, mode)
        };
        let result = match opened {
            Ok(Some(file)) => match self.allocate_file_number(file) {
                Some(number) => Ok(number),
                None => host.win16_file_close(file).map(|_| super::INVALID_GUEST_HFILE),
            },
            Ok(None) => Ok(super::INVALID_GUEST_HFILE),
            Err(error) => Err(error),
        };
        host.observe_win16_io(&crate::Win16IoEvent::Open {
            path, mode, created, result: result.as_ref().ok().copied(),
        });
        result
    }

    pub(super) fn legacy_file_path(
        &self, bytes: &[u8], host: &impl RuntimeHost,
    ) -> Result<Option<crate::Win16GuestPath>, RuntimeError> {
        let owner = self.current_task_owner()?;
        let result = host.decode_win16_ansi(bytes).and_then(|text|
            self.kernel_file_system.resolve_guest_path_text(owner, &text, false));
        match result {
            Ok(path) => Ok(Some(path)),
            Err(error) if matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn close_legacy_file(
        &mut self, file: u16, host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let network_result = self.tasks.current().and_then(|owner|
            self.network_print_hfile_is_owned(owner, file).then_some(owner));
        let result = if let Some(owner) = network_result {
            self.close_network_print_hfile(owner, file, host)
                .map(|result| result.unwrap_or(u32::from(super::INVALID_GUEST_HFILE)))
        } else { match self.files.get(&file).copied() {
            Some(native) => host.win16_file_close(native).map(|closed| {
                if self.invalidate_file_close(native, closed) { 0 }
                else { u32::from(super::INVALID_GUEST_HFILE) }
            }),
            None => Ok(u32::from(super::INVALID_GUEST_HFILE)),
        }};
        host.observe_win16_io(&crate::Win16IoEvent::Close {
            file, result: result.as_ref().ok().copied(),
        });
        result
    }

    pub(super) fn drive_type(
        &self, drive: u16, host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        Ok(guest_drive_type(host.win16_drive_kind(drive)?))
    }

    pub(super) fn allocate_file_number(&mut self, file: Win16HostFile) -> Option<u16> {
        let number = self.next_free_file_number()?;
        self.files.insert(number, file);
        Some(number)
    }

    /// Find and reserve the next slot in the allocation order without
    /// inserting a host token. Callers use this before creating host resources
    /// whose cleanup can consume an existing guest HFILE.
    pub(super) fn next_free_file_number(&mut self) -> Option<u16> {
        let span = u32::from(LAST_GUEST_HFILE - FIRST_GUEST_HFILE) + 1;
        for _ in 0..span {
            let number = self.next_file;
            self.next_file = if number >= LAST_GUEST_HFILE {
                FIRST_GUEST_HFILE
            } else {
                number + 1
            };
            let print_owned = self.network_print_jobs.values()
                .any(|jobs| jobs.owns_hfile(number));
            if !self.files.contains_key(&number) && !print_owned {
                return Some(number);
            }
        }
        None
    }

    /// Remove every guest alias for an opaque host token. This deliberately
    /// compares runtime-owned tokens instead of numeric native HANDLE values.
    pub(super) fn invalidate_host_file(&mut self, file: Win16HostFile) {
        self.files.retain(|_, mapped| *mapped != file);
    }

    /// Apply the host's unified close result to guest mappings.
    pub(super) fn invalidate_file_close(
        &mut self,
        file: Win16HostFile,
        result: Win16HostFileClose,
    ) -> bool {
        if result.closed {
            self.invalidate_host_file(file);
            if let Some(consumed_source) = result.consumed_source {
                self.invalidate_host_file(consumed_source);
            }
        }
        result.closed
    }

    pub(super) fn close_files(&mut self, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        // The host retains RAII ownership if native cleanup reports a failure.
        // Retire guest aliases and attempt every remaining key before files.
        for key in self.compat.take_registry_keys() {
            match host.win16_registry(crate::Win16HostRegistryOperation::CloseKey {
                key: crate::Win16RegistryKeyRef::Opened(key),
            }) {
                Ok(crate::Win16HostRegistryResult::CloseKey { status: 0 }) => {}
                Ok(crate::Win16HostRegistryResult::CloseKey { status }) => {
                    host.report_diagnostic(&crate::Diagnostic::warning(
                        Kind::HostFailure,
                        format!("Win16 registry cleanup returned system status {status}; native ownership remains with the host"),
                    ));
                }
                Ok(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 registry cleanup received a different operation result")),
                Err(error) => host.report_diagnostic(
                    error.with_context("Win16 registry cleanup").diagnostic()),
            }
        }
        let mut pending: std::collections::BTreeSet<Win16HostFile> =
            self.files.values().copied().collect();
        let mut first_error = None;
        while let Some(file) = pending.iter().next().copied() {
            pending.remove(&file);
            match host.win16_file_close(file) {
                Ok(result) if result.closed => {
                    self.invalidate_file_close(file, result);
                    if let Some(consumed_source) = result.consumed_source {
                        pending.remove(&consumed_source);
                    }
                }
                Ok(_) => {
                    first_error.get_or_insert_with(|| RuntimeError::new(
                        Kind::HostFailure, "native Win16 file could not be closed"));
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        // Failed host tokens and every guest alias remain available for a
        // later close attempt. An empty pending set alone does not prove close.
        first_error.map_or(Ok(()), Err)
    }
}

fn guest_drive_type(kind: Win16HostDriveKind) -> u16 {
    match kind {
        Win16HostDriveKind::Unknown => DRIVE_UNKNOWN,
        Win16HostDriveKind::MissingRoot => DRIVE_NO_ROOT_DIR,
        Win16HostDriveKind::Removable => DRIVE_REMOVABLE,
        Win16HostDriveKind::Fixed | Win16HostDriveKind::RamDisk => DRIVE_FIXED,
        Win16HostDriveKind::Remote | Win16HostDriveKind::CdRom => DRIVE_REMOTE,
    }
}

#[cfg(test)]
#[path = "win16_open_file_tests.rs"]
mod open_file_tests;

#[cfg(test)]
mod tests {
    use super::guest_drive_type;
    use crate::Win16HostDriveKind;

    #[test]
    fn get_drive_type_keeps_a_missing_root_distinct_from_unknown() {
        assert_eq!(guest_drive_type(Win16HostDriveKind::Unknown), 0);
        assert_eq!(guest_drive_type(Win16HostDriveKind::MissingRoot), 1);
        assert_eq!(guest_drive_type(Win16HostDriveKind::Removable), 2);
        assert_eq!(guest_drive_type(Win16HostDriveKind::Fixed), 3);
        assert_eq!(guest_drive_type(Win16HostDriveKind::RamDisk), 3);
        assert_eq!(guest_drive_type(Win16HostDriveKind::Remote), 4);
        assert_eq!(guest_drive_type(Win16HostDriveKind::CdRom), 4);
    }
}
