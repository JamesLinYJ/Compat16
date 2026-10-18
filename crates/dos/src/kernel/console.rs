use crate::caller_address_space::{
    DosCallAddressSpace, DosFarPointer, DosPointerAccess, DosSpanPolicy,
};
use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::Registers;

use super::DosKernel;
use super::state::{Handle, StandardHandle};

impl DosKernel {
    pub(super) fn success(regs: &mut Registers) {
        regs.set_carry(false);
    }

    pub(super) fn failure(&mut self, regs: &mut Registers, error: DosHostError) {
        self.complete_service_failure(regs, error.code as u16);
    }

    pub(super) fn console_input(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
        echo: bool,
    ) -> Result<DosAction, DosError> {
        let byte = match self.read_console_byte(host) {
            Ok(byte) => byte,
            Err(error) => {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };
        regs.set_al(byte);
        if echo && !self.write_console(regs, host, &[byte])? {
            return Ok(DosAction::Continue);
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn console_output(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
        byte: u8,
    ) -> Result<DosAction, DosError> {
        match self.standard_output_bytes(host, &[byte]) {
            Ok(1) => {
                regs.set_al(byte);
            }
            Ok(_) => {
                return Err(DosError::HostContractViolation(
                    "console write returned no byte",
                ));
            }
            Err(e) => self.failure(regs, e),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn direct_console_io(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let input = regs.dl();
        if input != 0xff {
            return self.console_output(regs, host, input);
        }
        match self.direct_input_byte(host) {
            Ok(Some(byte)) => {
                regs.set_al(byte);
                regs.eflags &= !(1 << 6);
            }
            Ok(None) => {
                regs.set_al(0);
                regs.eflags |= 1 << 6;
            }
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    fn readable_standard_input(&self) -> Result<Handle, DosHostError> {
        let handle = self.handles.get(&0).copied()
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        match handle {
            Handle::Standard(StandardHandle::Input) => Ok(handle),
            Handle::Standard(_) => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
            Handle::File(_) => {
                let mode = self.file_table.file_open_mode(0)
                    .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
                match mode & 0x0007 {
                    0 | 2 => Ok(handle),
                    1 => Err(DosHostError::new(DosErrorCode::AccessDenied)),
                    _ => Err(DosHostError::new(DosErrorCode::InvalidAccess)),
                }
            }
        }
    }

    fn direct_input_byte(
        &mut self,
        host: &mut impl DosHost,
    ) -> Result<Option<u8>, DosHostError> {
        // MS-DOS 4.0 Programmer's Reference, Functions 06H/0BH/46H:
        // standard input follows handle 0 after forced duplication.
        // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
        // The console cache is owned by the host input stream; redirected
        // files use exactly one read, without a status/read race or lookahead.
        match self.readable_standard_input()? {
            Handle::Standard(StandardHandle::Input) => {
                let byte = self.poll_console_byte(host)?;
                self.pending_input = None;
                Ok(byte)
            }
            Handle::File(file) => {
                let mut byte = [0];
                match host.file_read(file, &mut byte)? {
                    0 => Ok(None),
                    1 => Ok(Some(byte[0])),
                    _ => Err(DosHostError::new(DosErrorCode::GeneralFailure)),
                }
            }
            Handle::Standard(_) => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
        }
    }

    fn standard_input_status(&mut self, host: &mut impl DosHost) -> Result<bool, DosHostError> {
        match self.readable_standard_input()? {
            Handle::Standard(StandardHandle::Input) => {
                self.poll_console_byte(host).map(|byte| byte.is_some())
            }
            Handle::File(file) => host.file_input_status(file),
            Handle::Standard(_) => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
        }
    }

    pub(super) fn poll_console_byte(
        &mut self,
        host: &mut impl DosHost,
    ) -> Result<Option<u8>, DosHostError> {
        if self.pending_input.is_none() {
            self.pending_input = host.try_read_stdin()?;
        }
        Ok(self.pending_input)
    }

    pub(super) fn read_console_byte(
        &mut self,
        host: &mut impl DosHost,
    ) -> Result<u8, DosHostError> {
        let mut byte = [0];
        // MS-DOS 4.0 Programmer's Reference, Functions 01H/07H/08H/0AH:
        // character input follows standard input, including Function 46H
        // redirection. The pending byte belongs only to the host input stream.
        // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
        let count = match self.handles.get(&0).copied() {
            Some(Handle::Standard(StandardHandle::Input)) => {
                self.read_stdin_bytes(host, &mut byte)?
            }
            Some(Handle::File(file)) => host.file_read(file, &mut byte)?,
            Some(Handle::Standard(_)) | None => {
                return Err(DosHostError::new(DosErrorCode::InvalidHandle));
            }
        };
        match count {
            1 => Ok(byte[0]),
            _ => Err(DosHostError::new(DosErrorCode::GeneralFailure)),
        }
    }

    pub(super) fn write_console(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
        mut bytes: &[u8],
    ) -> Result<bool, DosError> {
        while !bytes.is_empty() {
            match self.standard_output_bytes(host, bytes) {
                Ok(0) => {
                    return Err(DosError::HostContractViolation(
                        "console write made no progress",
                    ));
                }
                Ok(count) if count <= bytes.len() => bytes = &bytes[count..],
                Ok(_) => {
                    return Err(DosError::HostContractViolation(
                        "console write exceeded its input",
                    ));
                }
                Err(error) => {
                    self.failure(regs, error);
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn standard_output_bytes(
        &self,
        host: &mut impl DosHost,
        bytes: &[u8],
    ) -> Result<usize, DosHostError> {
        // MS-DOS 4.0 Programmer's Reference, section 1.2 and Function 46H:
        // standard-character output follows handle 1 after forced duplication.
        // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
        // Direct CON device requests use their separate device-driver path.
        match self.handles.get(&1).copied() {
            Some(Handle::Standard(StandardHandle::Output)) => host.write_stdout(bytes),
            Some(Handle::Standard(StandardHandle::Error)) => host.write_stderr(bytes),
            Some(Handle::File(file)) => {
                let written = host.file_write(file, bytes)?;
                if written == 0 && !bytes.is_empty() {
                    return Err(DosHostError::new(DosErrorCode::DiskFull));
                }
                Ok(written)
            }
            Some(Handle::Standard(StandardHandle::Input)) | None => {
                Err(DosHostError::new(DosErrorCode::InvalidHandle))
            }
        }
    }

    pub(super) fn print_dollar_string(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let pointer = memory.resolve_caller_pointer(regs.ds, regs.dx())?;
        let bytes = memory.read_caller_terminated(pointer, b'$', 65_536, DosSpanPolicy::Linear)?;
        if !self.write_console(regs, host, &bytes)? {
            return Ok(DosAction::Continue);
        }
        regs.set_al(b'$');
        Ok(DosAction::Continue)
    }

    pub(super) fn buffered_input(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let (pointer, max) = preflight_buffered_input(regs, memory)?;
        self.buffered_input_with_target(regs, memory, host, pointer, max)
    }

    fn buffered_input_with_target(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
        pointer: DosFarPointer,
        max: u8,
    ) -> Result<DosAction, DosError> {
        if max == 0 {
            memory.write_caller_range(pointer, 1, &[0], DosSpanPolicy::Linear)?;
            return Ok(DosAction::Continue);
        }
        let capacity = usize::from(max - 1);
        let mut line = Vec::with_capacity(capacity);
        loop {
            let byte = match self.read_console_byte(host) {
                Ok(byte) => byte,
                Err(error) => {
                    self.failure(regs, error);
                    return Ok(DosAction::Continue);
                }
            };
            if byte == b'\r' {
                let _ = self.write_console(regs, host, b"\r\n")?;
                break;
            }
            if line.len() < capacity {
                if !self.write_console(regs, host, &[byte])? {
                    return Ok(DosAction::Continue);
                }
                line.push(byte);
            }
        }
        let mut result = Vec::with_capacity(line.len() + 2);
        result.push(line.len() as u8);
        result.extend_from_slice(&line);
        result.push(b'\r');
        memory.write_caller_range(pointer, 1, &result, DosSpanPolicy::Linear)?;
        Ok(DosAction::Continue)
    }

    pub(super) fn input_status(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        match self.standard_input_status(host) {
            Ok(true) => regs.set_al(0xff),
            Ok(false) => regs.set_al(0),
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }

    pub(super) fn flush_and_input(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        if regs.al() == 0x0a {
            // Validate the nested output buffer before flushing stdin, which
            // changes host stream state even if the caller pointer is invalid.
            let (pointer, max) = preflight_buffered_input(regs, memory)?;
            if let Err(error) = host.flush_stdin() {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
            self.pending_input = None;
            return self.buffered_input_with_target(regs, memory, host, pointer, max);
        }
        if let Err(error) = host.flush_stdin() {
            self.failure(regs, error);
            return Ok(DosAction::Continue);
        }
        self.pending_input = None;
        match regs.al() {
            0x01 => self.console_input(regs, host, true),
            0x06 => self.direct_console_io(regs, host),
            0x07 | 0x08 => self.console_input(regs, host, false),
            _ => Ok(DosAction::Continue),
        }
    }

    pub(super) fn select_drive(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        match host.select_drive(regs.dl()) {
            Ok(()) => {
                let count = host.logical_drive_count();
                if count > 26 {
                    return Err(DosError::HostContractViolation(
                        "host reported more than 26 DOS drives",
                    ));
                }
                regs.set_al(count);
            }
            Err(error) => self.failure(regs, error),
        }
        Ok(DosAction::Continue)
    }
}

fn preflight_buffered_input(
    regs: &Registers,
    memory: &mut impl DosCallAddressSpace,
) -> Result<(DosFarPointer, u8), DosError> {
    let pointer = memory.resolve_caller_pointer(regs.ds, regs.dx())?;
    let mut max_byte = [0];
    memory.read_caller_range(pointer, 0, &mut max_byte, DosSpanPolicy::Linear)?;
    let max = max_byte[0];
    // The second byte is the returned count; remaining bytes hold text and CR.
    let output_len = usize::from(max) + 1;
    memory.validate_caller_range(
        pointer,
        1,
        output_len,
        DosPointerAccess::Write,
        DosSpanPolicy::Linear,
    )?;
    Ok((pointer, max))
}
