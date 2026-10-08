//! Guest WORD handles and fixed-width FindFirst/FindNext projections.

use guest_core::{OwnerId, memory::Memory};

use super::owner::{guest_api_failure, invariant};
use super::{
    WIN16_FIND_DATA_BYTES, Win16HostFileSystemCall, Win16HostFileSystemOperation,
    Win16HostFileSystemResult, Win16HostSearchId, Win16State,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn find_first_file(
        &mut self,
        owner: OwnerId,
        path: &[u8],
        find_data: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match self.capture_file_system_output(find_data, WIN16_FIND_DATA_BYTES, memory)
        {
            Ok(range) => range,
            Err(error) if guest_api_failure(&error) => return Ok(u32::from(u16::MAX)),
            Err(error) => return Err(error),
        };
        let resolved = match self.resolve_ansi_path(owner, path, true, host) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(u32::from(u16::MAX)),
            Err(error) => return Err(error),
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::FindFirst {
                search_file: resolved,
            },
        })?;
        let Win16HostFileSystemResult::FindFirst(Some(first)) = result else {
            if result == Win16HostFileSystemResult::FindFirst(None) {
                return Ok(u32::from(u16::MAX));
            }
            return Err(invariant("host FindFirst returned the wrong result"));
        };
        let wire = match first.entry.to_win16_wire() {
            Ok(wire) => wire,
            Err(primary) => {
                return Err(self.close_search_after_failure(owner, first.search, host, primary));
            }
        };
        let Some(guest_handle) = self
            .kernel_file_system
            .allocate_guest_search(owner, first.search)
        else {
            let primary = RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 task exhausted its guest search-handle words",
            );
            return match self.close_search_after_guest_failure(owner, first.search, host) {
                Ok(()) => Ok(u32::from(u16::MAX)),
                Err(cleanup) => Err(primary.with_cleanup(
                    "retire host search after Win16 FindFirst handle exhaustion",
                    cleanup,
                )),
            };
        };
        match super::super::guest_ranges::commit_guest_writes(
            self,
            memory,
            vec![(output, wire.to_vec())],
        ) {
            Ok(()) => Ok(u32::from(guest_handle)),
            Err(primary) => {
                self.kernel_file_system
                    .remove_guest_search(owner, guest_handle);
                Err(self.close_search_after_failure(owner, first.search, host, primary))
            }
        }
    }

    pub(super) fn find_next_file(
        &mut self,
        owner: OwnerId,
        guest_handle: u16,
        find_data: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match self.capture_file_system_output(find_data, WIN16_FIND_DATA_BYTES, memory)
        {
            Ok(range) => range,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let Some(search) = self.kernel_file_system.host_search(owner, guest_handle) else {
            return Ok(0);
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::FindNext { search },
        })?;
        match result {
            Win16HostFileSystemResult::FindNext(None) => Ok(0),
            Win16HostFileSystemResult::FindNext(Some(entry)) => {
                let wire = entry.to_win16_wire()?;
                super::super::guest_ranges::commit_guest_writes(
                    self,
                    memory,
                    vec![(output, wire.to_vec())],
                )?;
                Ok(1)
            }
            _ => Err(invariant("host FindNext returned the wrong result")),
        }
    }

    pub(super) fn find_close(
        &mut self,
        owner: OwnerId,
        guest_handle: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(search) = self.kernel_file_system.host_search(owner, guest_handle) else {
            return Ok(0);
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::FindClose { search },
        })?;
        match result {
            Win16HostFileSystemResult::FindClose(true) => {
                self.kernel_file_system
                    .remove_guest_search(owner, guest_handle);
                Ok(1)
            }
            Win16HostFileSystemResult::FindClose(false) => Ok(0),
            _ => Err(invariant("host FindClose returned the wrong result")),
        }
    }

    fn close_search_after_failure(
        &mut self,
        owner: OwnerId,
        search: Win16HostSearchId,
        host: &mut impl RuntimeHost,
        primary: RuntimeError,
    ) -> RuntimeError {
        match host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::FindClose { search },
        }) {
            Ok(Win16HostFileSystemResult::FindClose(true)) => primary,
            Ok(Win16HostFileSystemResult::FindClose(false)) => primary.with_cleanup(
                "close host search after Win16 FindFirst projection failure",
                invariant("host failed to close its newly-created search"),
            ),
            Ok(_) => primary.with_cleanup(
                "close host search after Win16 FindFirst projection failure",
                invariant("host FindClose returned the wrong result during cleanup"),
            ),
            Err(cleanup) => primary.with_cleanup(
                "close host search after Win16 FindFirst projection failure",
                cleanup,
            ),
        }
    }

    fn close_search_after_guest_failure(
        &mut self,
        owner: OwnerId,
        search: Win16HostSearchId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        match host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::FindClose { search },
        }) {
            Ok(Win16HostFileSystemResult::FindClose(true)) => Ok(()),
            Ok(Win16HostFileSystemResult::FindClose(false)) => Err(invariant(
                "host failed to close the search after guest handle exhaustion",
            )),
            Ok(_) => Err(invariant(
                "host FindClose returned the wrong result after guest handle exhaustion",
            )),
            Err(error) => Err(error),
        }
    }
}
