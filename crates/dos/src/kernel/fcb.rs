//! Shared FCB pattern, AL-only result and native-enumeration ownership.
use super::{
    DosKernel, directory,
    state::{DosSearchPattern, SearchKey, SearchState},
};
use crate::{DosAction, DosDirectoryEntry, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::Registers;

pub(super) fn pattern(
    fields: &[u8],
    page: text_codec::CodePage,
) -> Result<DosSearchPattern, DosErrorCode> {
    if fields.len() != 11 {
        return Err(DosErrorCode::InvalidData);
    }
    let mut pattern = DosSearchPattern {
        name: [b' '; 8],
        extension: [b' '; 3],
    };
    let base = &fields[..8];
    if base == b".       " || base == b"..      " {
        pattern.name.copy_from_slice(base);
    } else {
        directory::expand_pattern_field(base, &mut pattern.name, page)?
            .ok_or(DosErrorCode::InvalidData)?;
    }
    directory::expand_pattern_field(&fields[8..], &mut pattern.extension, page)?
        .ok_or(DosErrorCode::InvalidData)?;
    Ok(pattern)
}

impl DosKernel {
    pub(super) fn fcb_failure(&mut self, regs: &mut Registers, code: DosErrorCode) -> DosAction {
        self.remember_extended_error(code as u16);
        regs.set_al(0xff);
        DosAction::Continue
    }

    /// Close the native enumeration before publishing results or mutating any
    /// entry. Failed closes remain in the existing PSP/caller resource ledger.
    /// No guest DTA or retained pointer is involved in this private scan.
    pub(super) fn collect_fcb_matches<T>(
        &mut self,
        key: SearchKey,
        directory: &[u8],
        pattern: DosSearchPattern,
        attributes: u8,
        host: &mut impl DosHost,
        mut convert: impl FnMut(DosDirectoryEntry) -> Result<T, DosError>,
    ) -> Result<Vec<T>, DosError> {
        if let Some(old) = self.searches.get(&key).copied() {
            host.directory_search_close(old.host_search)
                .map_err(DosError::HostOperation)?;
            self.searches.remove(&key);
        }
        let search = host
            .directory_search_open(directory)
            .map_err(DosError::HostOperation)?;
        if self.searches.values().any(|s| s.host_search == search) {
            return Err(DosError::HostContractViolation(
                "FCB enumeration returned an owned search token",
            ));
        }
        let state = SearchState {
            host_search: search,
            identity: self.allocate_search_identity(),
            pattern,
            attributes,
        };
        self.searches.insert(key, state);
        let records = (|| {
            let mut records = Vec::new();
            loop {
                match directory::next_matching_entry(host, state) {
                    Ok(Some(entry)) => {
                        if records.len() >= u32::MAX as usize {
                            return Err(DosError::HostOperation(DosHostError::new(
                                DosErrorCode::InsufficientMemory,
                            )));
                        }
                        records.try_reserve(1).map_err(|error| {
                            DosError::HostOperation(DosHostError::with_source(
                                DosErrorCode::InsufficientMemory,
                                error,
                            ))
                        })?;
                        records.push(convert(entry)?);
                    }
                    Ok(None) => return Ok(records),
                    Err(directory::NextSearchError::Host(error)) => {
                        return Err(DosError::HostOperation(error));
                    }
                    Err(directory::NextSearchError::InvalidEntry) => {
                        return Err(DosError::HostContractViolation(
                            "invalid FCB directory entry",
                        ));
                    }
                }
            }
        })();
        let closed = host.directory_search_close(search);
        if closed.is_ok() {
            self.searches.remove(&key);
        }
        let records = records?;
        closed.map_err(DosError::HostOperation)?;
        Ok(records)
    }
}
