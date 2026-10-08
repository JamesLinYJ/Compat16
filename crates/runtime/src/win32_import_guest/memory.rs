//! Checked PE32 argument and output-buffer access for synchronous Win32 calls.

use guest_core::{PhysAddr, memory::Memory};

use crate::{DiagnosticKind as Kind, RuntimeError, Win32ImportString};

const MAX_STRING_UNITS: usize = 32_768;

pub(super) fn read_u32(memory: &mut Memory, address: u32) -> Result<u32, RuntimeError> {
    let mut bytes = [0_u8; 4];
    read_exact(memory, address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(super) fn read_exact(memory: &mut Memory, address: u32, output: &mut [u8])
    -> Result<(), RuntimeError> {
    validate(memory, address, output.len(), false)?;
    memory.read_physical(PhysAddr(address), output).map_err(|error| {
        if let Some(storage) = memory.storage_failure() { crate::runtime_error(storage) }
        else { RuntimeError::with_source(Kind::GuestFault, "read PE32 guest buffer", error) }
    })
}

pub(super) fn read_string(
    memory: &mut Memory, address: u32, wide: bool,
) -> Result<Win32ImportString, RuntimeError> {
    if address == 0 { return Err(guest_fault("PE32 string pointer is NULL")); }
    if wide {
        let mut result = Vec::new();
        result.try_reserve(64).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve PE32 UTF-16 string", error))?;
        for index in 0..MAX_STRING_UNITS {
            let offset = u32::try_from(index.checked_mul(2).ok_or_else(||
                exhausted("PE32 UTF-16 string length"))?).map_err(|_| exhausted("PE32 UTF-16 string length"))?;
            let at = address.checked_add(offset).ok_or_else(|| guest_fault("PE32 UTF-16 string wraps"))?;
            let mut bytes = [0; 2];
            read_exact(memory, at, &mut bytes)?;
            let unit = u16::from_le_bytes(bytes);
            if unit == 0 { return Ok(Win32ImportString::Wide(result)); }
            if result.len() == result.capacity() {
                result.try_reserve(64).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "grow PE32 UTF-16 string", error))?;
            }
            result.push(unit);
        }
    } else {
        let mut result = Vec::new();
        result.try_reserve(128).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve PE32 ANSI string", error))?;
        for offset in 0..MAX_STRING_UNITS {
            let offset = u32::try_from(offset).map_err(|_| exhausted("PE32 ANSI string length"))?;
            let at = address.checked_add(offset).ok_or_else(|| guest_fault("PE32 ANSI string wraps"))?;
            let mut byte = [0];
            read_exact(memory, at, &mut byte)?;
            if byte[0] == 0 { return Ok(Win32ImportString::Ansi(result)); }
            if result.len() == result.capacity() {
                result.try_reserve(128).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "grow PE32 ANSI string", error))?;
            }
            result.push(byte[0]);
        }
    }
    Err(guest_fault("PE32 string has no terminator within the Win32 path limit"))
}

pub(super) fn validate(
    memory: &mut Memory, address: u32, length: usize, write: bool,
) -> Result<(), RuntimeError> {
    if length == 0 { return Ok(()); }
    memory.validate_ram_range(PhysAddr(address), length, write).map_err(|error| {
        if let Some(storage) = memory.storage_failure() { crate::runtime_error(storage) }
        else { RuntimeError::with_source(Kind::GuestFault,
            "PE32 Win32 pointer is outside mapped guest RAM", error) }
    })
}

/// All output ranges are validated and prior bytes saved before host side
/// effects. The owned staging capacity makes post-call encoding allocation-free.
pub(super) struct GuestOutput {
    address: u32,
    original: Vec<u8>,
    staged: Vec<u8>,
}

impl GuestOutput {
    pub(super) fn new(memory: &mut Memory, address: u32, capacity: usize)
        -> Result<Self, RuntimeError> {
        if address == 0 { return Err(guest_fault("required PE32 output pointer is NULL")); }
        if capacity > u32::MAX as usize { return Err(exhausted("PE32 output buffer")); }
        validate(memory, address, capacity, true)?;
        let mut original = Vec::new();
        original.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "retain PE32 output rollback bytes", error))?;
        original.resize(capacity, 0);
        if capacity != 0 { memory.read_physical(PhysAddr(address), &mut original)
            .map_err(|error| crate::runtime_error(memory.storage_failure().unwrap_or(error)))?; }
        let mut staged = Vec::new();
        staged.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve PE32 output staging", error))?;
        Ok(Self { address, original, staged })
    }

    pub(super) fn set(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > self.original.len() {
            return Err(RuntimeError::new(Kind::HostFailure,
                "native Win32 output exceeded its guest buffer capacity"));
        }
        self.staged.clear();
        self.staged.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn set_ansi(&mut self, text: &[u8], terminate: bool) -> Result<(), RuntimeError> {
        let needed = text.len().checked_add(usize::from(terminate))
            .ok_or_else(|| exhausted("PE32 ANSI output"))?;
        if needed > self.original.len() { return Err(output_overflow()); }
        self.staged.clear();
        self.staged.extend_from_slice(text);
        if terminate { self.staged.push(0); }
        Ok(())
    }

    pub(super) fn set_wide(&mut self, text: &[u16], terminate: bool) -> Result<(), RuntimeError> {
        let units = text.len().checked_add(usize::from(terminate))
            .ok_or_else(|| exhausted("PE32 UTF-16 output"))?;
        let needed = units.checked_mul(2).ok_or_else(|| exhausted("PE32 UTF-16 output"))?;
        if needed > self.original.len() { return Err(output_overflow()); }
        self.staged.clear();
        for unit in text { self.staged.extend_from_slice(&unit.to_le_bytes()); }
        if terminate { self.staged.extend_from_slice(&0_u16.to_le_bytes()); }
        Ok(())
    }

    pub(super) fn set_wide_units(&mut self, units: &[u16]) -> Result<(), RuntimeError> {
        let needed = units.len().checked_mul(2).ok_or_else(|| exhausted("PE32 UTF-16 output"))?;
        if needed > self.original.len() { return Err(output_overflow()); }
        self.staged.clear();
        for unit in units { self.staged.extend_from_slice(&unit.to_le_bytes()); }
        Ok(())
    }

}

pub(super) fn commit(memory: &mut Memory, outputs: &mut [GuestOutput]) -> Result<(), RuntimeError> {
    for (index, output) in outputs.iter().enumerate() {
        if !output.staged.is_empty() {
            if let Err(error) = memory.write_physical(PhysAddr(output.address), &output.staged) {
                let primary = crate::runtime_error(memory.storage_failure().unwrap_or(error));
                return Err(rollback(memory, outputs, index + 1, primary));
            }
        }
    }
    Ok(())
}

fn rollback(memory: &mut Memory, outputs: &[GuestOutput], written: usize,
    primary: RuntimeError) -> RuntimeError {
    let mut failure = None;
    for output in outputs[..written].iter().rev() {
        if output.staged.is_empty() { continue; }
        if let Err(error) = memory.write_physical(PhysAddr(output.address), &output.original) {
            let cleanup = crate::runtime_error(memory.storage_failure().unwrap_or(error));
            failure = Some(match failure.take() {
                Some(previous) => combine(previous, cleanup), None => cleanup,
            });
        }
    }
    match failure {
        Some(cleanup) => combine(primary, cleanup),
        None => primary,
    }
}

fn combine(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    primary.with_cleanup("PE32 Win32 output writeback failed", cleanup)
}

fn guest_fault(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::GuestFault, message) }
fn exhausted(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::ResourceExhausted, message) }
fn output_overflow() -> RuntimeError { RuntimeError::new(Kind::HostFailure,
    "native Win32 text exceeds the preflighted guest buffer") }
