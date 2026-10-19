//! AH=60h is a string translation, not a file-existence or realpath query.
//! DOS 4 MACRO2.ASM/$NameTrans and Canonicalize build into internal storage
//! before copying the result. Existing long names use the host's same stable
//! short-name namespace as enumeration; absent names use DOS 8.3 parsing.
use super::{DosKernel, directory, memory::read_dos_c_string};
use crate::{
    DosAction, DosCallAddressSpace, DosError, DosErrorCode, DosHost, DosHostError,
    DosPointerAccess, DosSpanPolicy,
};
use guest_core::Registers;

mod components;
use components::{normalize_component, split};
const BUFFER_BYTES: usize = 128;

impl DosKernel {
    pub(super) fn canonical_name(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let source = match read_dos_c_string(memory, regs.ds, regs.si()) {
            Ok(bytes) => bytes,
            Err(DosError::MalformedGuestInput(_)) => {
                self.failure(regs, DosHostError::new(DosErrorCode::PathNotFound));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };
        let output = memory.resolve_caller_pointer(regs.es, regs.di())?;
        memory.validate_caller_range(
            output,
            0,
            BUFFER_BYTES,
            DosPointerAccess::Write,
            DosSpanPolicy::Linear,
        )?;
        let result = match translate(&source, host) {
            Ok(result) => result,
            Err(Failure::Guest(code)) => {
                self.failure(regs, DosHostError::new(code));
                return Ok(DosAction::Continue);
            }
            Err(Failure::Host(error)) => {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
            Err(Failure::Contract(message)) => {
                return Err(DosError::HostContractViolation(message));
            }
        };
        memory.write_caller_range(output, 0, &result, DosSpanPolicy::Linear)?;
        // AH is zero; AL is undocumented and varies on DOS (00/2F/5C).
        // Preserve all other registers, including the original ES:DI.
        regs.set_ax(0x005c);
        Self::success(regs);
        Ok(DosAction::Continue)
    }
}

enum Failure {
    Guest(DosErrorCode),
    Host(DosHostError),
    Contract(&'static str),
}
impl From<DosErrorCode> for Failure {
    fn from(code: DosErrorCode) -> Self {
        Self::Guest(code)
    }
}
impl From<DosHostError> for Failure {
    fn from(error: DosHostError) -> Self {
        Self::Host(error)
    }
}

fn translate(source: &[u8], host: &mut impl DosHost) -> Result<Vec<u8>, Failure> {
    let page = host.guest_code_page();
    let drive = directory::dos_path_drive(source, page)
        .map_err(|_| DosErrorCode::PathNotFound)?
        .unwrap_or(host.current_drive());
    if drive > 25 {
        return Err(Failure::Guest(DosErrorCode::PathNotFound));
    }
    let input = if source.get(1) == Some(&b':') {
        &source[2..]
    } else {
        source
    };
    if input.is_empty() {
        return Err(Failure::Guest(DosErrorCode::FileNotFound));
    }
    let mut cwd = [0; 63];
    let count = match host.directory_get_current(drive, &mut cwd) {
        Ok(count) if count <= cwd.len() => count,
        Ok(_) => {
            return Err(Failure::Contract(
                "canonical-name current directory exceeds its buffer",
            ));
        }
        Err(error) if error.code == DosErrorCode::UnknownUnit => {
            return Err(Failure::Guest(DosErrorCode::PathNotFound));
        }
        Err(error) => return Err(error.into()),
    };
    let (rooted, trailing, parts) = split(input, page)?;
    if input.len() >= 2 && matches!(input[0], b'/' | b'\\') && matches!(input[1], b'/' | b'\\') {
        // The mounted DOS host has no UNC/network-drive namespace.
        return Err(Failure::Guest(DosErrorCode::PathNotFound));
    }
    let mut components = if rooted {
        Vec::new()
    } else {
        split(&cwd[..count], page)
            .map_err(|_| Failure::Contract("malformed canonical-name host cwd"))?
            .2
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
    };
    let mut directory_end = trailing;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if part == b"." || part == b".." {
            if part == b".." && components.pop().is_none() {
                return Err(Failure::Guest(DosErrorCode::PathNotFound));
            }
            directory_end = true;
            continue;
        }
        let upper =
            text_codec::uppercase_oem_name(part, page).map_err(|_| DosErrorCode::PathNotFound)?;
        let wildcard = text_codec::encoded_characters(&upper, page)
            .any(|c| c.is_ok_and(|c| c.is_standalone_ascii(b'*') || c.is_standalone_ascii(b'?')));
        if wildcard && parts[index + 1..].iter().any(|part| !part.is_empty()) {
            return Err(Failure::Guest(DosErrorCode::PathNotFound));
        }
        let parent = pack(drive, &components, true);
        let normalized = normalize_component(part, page);
        // Valid 8.3 input is already in the published virtual namespace; it
        // requires no native existence check, even in an unreadable parent.
        let literal_short = normalized.as_ref().is_ok_and(|(name, wild)| {
            !wild
                && (name.as_slice() == upper.as_slice()
                    || Some(name.as_slice()) == upper.strip_suffix(b"."))
        });
        let component = if wildcard || literal_short {
            normalized?.0
        } else {
            match host.file_short_name(&parent, part)? {
                None => normalized?.0,
                Some(name) => {
                    if directory::short_name_fields(&name, page).is_none() {
                        return Err(Failure::Contract(
                            "canonical-name host returned an invalid short name",
                        ));
                    }
                    text_codec::uppercase_oem_name(&name, page).map_err(|_| {
                        Failure::Contract("canonical-name host returned malformed OEM bytes")
                    })?
                }
            }
        };
        components.push(component);
        directory_end = trailing;
    }
    let mut result = pack(drive, &components, directory_end);
    if result.len() >= BUFFER_BYTES {
        return Err(Failure::Guest(DosErrorCode::PathNotFound));
    }
    result.push(0);
    Ok(result)
}

fn pack(drive: u8, components: &[Vec<u8>], trailing: bool) -> Vec<u8> {
    let mut result = vec![b'A' + drive, b':', b'\\'];
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            result.push(b'\\');
        }
        result.extend_from_slice(component);
    }
    if trailing && !components.is_empty() {
        result.push(b'\\');
    }
    result
}
