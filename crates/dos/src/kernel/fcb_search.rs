//! Classic FCB searches have AL results and a continuation separate from DTA.
//! The native backend already enumerates owned directory data. Retain that data
//! until PSP/caller teardown so copied FCBs can advance independently, even after
//! another copy exhausts or the original FCB starts a different search. No guest
//! pointer or native search handle is stored in the continuation bytes.
mod continuations;
mod layout;
use super::{
    DosKernel, directory,
    state::{SearchKey, SearchKind, SearchState},
};
use crate::{
    DosAction, DosCallAddressSpace, DosError, DosErrorCode, DosHost, DosHostError,
    DosPersistentFarPointer, DosPointerAccess, DosSpanPolicy,
};
pub(super) use continuations::Continuations;
use continuations::Snapshot;
use guest_core::Registers;
use layout::Request;

impl DosKernel {
    pub(super) fn fcb_search(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let mut request = Request::read(memory, regs.ds, regs.dx())?;
        let dta = self.caller_dta(memory)?;
        validate_dta(memory, dta, request.skip + 33)?;
        let (identity, start) = if regs.ah() == 0x11 {
            let pattern = match request.pattern(host.guest_code_page()) {
                Ok(pattern) => pattern,
                Err(code) => return Ok(self.fcb_failure(regs, code)),
            };
            let current = host.current_drive();
            if current > 25 {
                return Err(DosError::HostContractViolation("invalid FCB current drive"));
            }
            let drive = match request.bytes[0] {
                0 => current,
                1..=26 => request.bytes[0] - 1,
                _ => return Ok(self.fcb_failure(regs, DosErrorCode::UnknownUnit)),
            };
            let identity = match self.fcb_searches.reserve() {
                Ok(identity) => identity,
                Err(error) => return Ok(self.fcb_failure(regs, error.code)),
            };
            let path = [b'A' + drive, b':'];
            let key = SearchKey {
                kind: SearchKind::FcbScan,
                psp_segment: self.psp_segment,
                caller: memory.caller_id(),
                dta_segment: regs.ds,
                dta_offset: regs.dx(),
                dta_lease: 0,
            };
            // A previous failed native close remains owned and retryable.
            if let Some(old) = self.searches.get(&key).copied() {
                if let Err(error) = host.directory_search_close(old.host_search) {
                    return Ok(self.fcb_failure(regs, error.code));
                }
                self.searches.remove(&key);
            }
            let search =
                match host.directory_search_open(if drive == current { b"" } else { &path }) {
                    Ok(search) => search,
                    Err(error) => return Ok(self.fcb_failure(regs, error.code)),
                };
            if self.searches.values().any(|s| s.host_search == search) {
                return Err(DosError::HostContractViolation(
                    "FCB enumeration returned an owned search token",
                ));
            }
            let state = SearchState {
                host_search: search,
                identity: self.allocate_search_identity(),
                pattern,
                attributes: 0x1f,
            };
            self.searches.insert(key, state);
            let records = collect(host, state);
            let close = host.directory_search_close(search);
            if close.is_ok() {
                self.searches.remove(&key);
            }
            let records = match records {
                Ok(records) => records,
                Err(DosError::HostOperation(error)) => {
                    return Ok(self.fcb_failure(regs, error.code));
                }
                Err(error) => return Err(error),
            };
            if let Err(error) = close {
                return Ok(self.fcb_failure(regs, error.code));
            }
            if !records
                .iter()
                .any(|record| directory::search_attribute_matches(request.attributes, record[11]))
            {
                return Ok(self.fcb_failure(regs, DosErrorCode::NoMoreFiles));
            }
            let identity = self.fcb_searches.insert(Snapshot {
                psp: self.psp_segment,
                caller: memory.caller_id(),
                identity,
                drive: drive + 1,
                pattern,
                records,
            });
            (identity, 0)
        } else {
            match request.cookie() {
                Some(cookie) => cookie,
                None => return Ok(self.fcb_failure(regs, DosErrorCode::NoMoreFiles)),
            }
        };
        let selected = self
            .fcb_searches
            .get(self.psp_segment, memory.caller_id(), identity)
            .filter(|snapshot| {
                regs.ah() == 0x11
                    || (snapshot.drive == request.bytes[21]
                        && snapshot.pattern.name == request.bytes[1..9]
                        && snapshot.pattern.extension == request.bytes[9..12])
            })
            .and_then(|snapshot| {
                snapshot
                    .records
                    .iter()
                    .enumerate()
                    .skip(start as usize)
                    .find(|(_, record)| {
                        directory::search_attribute_matches(request.attributes, record[11])
                    })
                    .map(|(index, record)| {
                        (snapshot.drive, *record, index as u32 + 1, snapshot.pattern)
                    })
            });
        let Some((drive, record, next, pattern)) = selected else {
            return Ok(self.fcb_failure(regs, DosErrorCode::NoMoreFiles));
        };
        let (output, length) = request.result(drive, &record);
        request.publish_cookie(memory, identity, next, drive, &pattern)?;
        validate_dta(memory, dta, length)?;
        memory.write_caller_range(
            dta.pointer(),
            0,
            &output[..length],
            DosSpanPolicy::OffsetWrap,
        )?;
        regs.set_al(0);
        Ok(DosAction::Continue)
    }

    fn fcb_failure(&mut self, regs: &mut Registers, code: DosErrorCode) -> DosAction {
        self.remember_extended_error(code as u16);
        regs.set_al(0xff);
        DosAction::Continue
    }
}

fn validate_dta(
    memory: &mut impl DosCallAddressSpace,
    dta: DosPersistentFarPointer,
    length: usize,
) -> Result<(), DosError> {
    // Verify the retained selector generation first. Only the real-mode byte
    // walk wraps; protected ranges still have to fit the single live selector.
    memory.validate_persistent_range(dta, 0, 0, DosPointerAccess::Write)?;
    memory.validate_caller_range(
        dta.pointer(),
        0,
        length,
        DosPointerAccess::Write,
        DosSpanPolicy::OffsetWrap,
    )
}

fn collect(host: &mut impl DosHost, state: SearchState) -> Result<Vec<[u8; 32]>, DosError> {
    let mut records = Vec::new();
    loop {
        let entry = match directory::next_matching_entry(host, state) {
            Ok(Some(entry)) => entry,
            Ok(None) => return Ok(records),
            Err(directory::NextSearchError::Host(error)) => {
                return Err(DosError::HostOperation(error));
            }
            Err(directory::NextSearchError::InvalidEntry) => {
                return Err(DosError::HostContractViolation(
                    "invalid FCB search directory entry",
                ));
            }
        };
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
        records.push(layout::record(&entry, host.guest_code_page())?);
    }
}
