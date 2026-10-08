//! Native-backed Win16 KEYBOARD and WIFEMAN code-page calls.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16KeyboardConversion, Win16KeyboardRequest};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostKeyboardCall, Win16HostKeyboardResult};

impl Win16State {
    pub(crate) fn keyboard_compat_api(
        &self,
        request: Win16KeyboardRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16KeyboardRequest::ConvertString { conversion, source, destination } => {
                let call = match conversion {
                    Win16KeyboardConversion::AnsiToOem => Win16HostKeyboardCall::AnsiToOem { source },
                    Win16KeyboardConversion::OemToAnsi => Win16HostKeyboardCall::OemToAnsi { source },
                };
                let Win16HostKeyboardResult::Converted(mut output) = host.win16_keyboard(call)? else {
                    return Err(wrong_keyboard_result("string conversion"));
                };
                output.try_reserve(1).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "reserve Win16 keyboard conversion terminator", error))?;
                output.push(0);
                self.write_guest_bytes(memory, destination, &output)?;
                Ok(u32::from(u16::MAX))
            }
            Win16KeyboardRequest::ConvertBuffer { conversion, source, destination, byte_count } => {
                let count = usize::from(byte_count);
                if count == 0 { return Ok(1); }
                let input = self.read_guest_bytes(memory, source, count)?;
                self.preflight_guest_write(memory, destination, count)?;
                let call = match conversion {
                    Win16KeyboardConversion::AnsiToOem => Win16HostKeyboardCall::AnsiToOem { source: input },
                    Win16KeyboardConversion::OemToAnsi => Win16HostKeyboardCall::OemToAnsi { source: input },
                };
                let Win16HostKeyboardResult::Converted(output) = host.win16_keyboard(call)? else {
                    return Err(wrong_keyboard_result("buffer conversion"));
                };
                if output.len() > count {
                    return Ok(0);
                }
                self.write_guest_bytes(memory, destination, &output)?;
                Ok(1)
            }
            Win16KeyboardRequest::ToAscii { virtual_key, scan_code, key_state, output, flags } => {
                self.preflight_guest_write(memory, output, 4)?;
                let call = Win16HostKeyboardCall::ToAscii {
                    virtual_key,
                    scan_code,
                    key_state: Box::new(key_state),
                    flags,
                };
                let Win16HostKeyboardResult::ToAscii { count, characters } = host.win16_keyboard(call)? else {
                    return Err(wrong_keyboard_result("ToAscii"));
                };
                let mut bytes = [0_u8; 4];
                bytes[..2].copy_from_slice(&characters[0].to_le_bytes());
                bytes[2..].copy_from_slice(&characters[1].to_le_bytes());
                self.write_guest_bytes(memory, output, &bytes)?;
                Ok(u32::from(count as u16))
            }
            Win16KeyboardRequest::SetSpeed { speed } => {
                let Win16HostKeyboardResult::SetSpeed(value) = host.win16_keyboard(
                    Win16HostKeyboardCall::SetSpeed { speed })? else {
                    return Err(wrong_keyboard_result("SetSpeed"));
                };
                Ok(u32::from(value))
            }
            Win16KeyboardRequest::ScreenSwitchEnable { enabled: _ } => {
                // The DDK documents this as OS/2-only; it has no effect under
                // MS-DOS. The export is void, so its runtime placeholder is 0.
                Ok(0)
            }
            Win16KeyboardRequest::OemKeyScan { character } => {
                let Win16HostKeyboardResult::OemKeyScan(value) = host.win16_keyboard(
                    Win16HostKeyboardCall::OemKeyScan { character })? else {
                    return Err(wrong_keyboard_result("OemKeyScan"));
                };
                Ok(value)
            }
            Win16KeyboardRequest::VirtualKeyScan { ansi_character } => {
                let Win16HostKeyboardResult::VirtualKeyScan(value) = host.win16_keyboard(
                    Win16HostKeyboardCall::VirtualKeyScan { ansi_character })? else {
                    return Err(wrong_keyboard_result("VkKeyScan"));
                };
                Ok(u32::from(value as u16))
            }
            Win16KeyboardRequest::KeyboardType { selector } => {
                let Win16HostKeyboardResult::KeyboardType(value) = host.win16_keyboard(
                    Win16HostKeyboardCall::KeyboardType { selector })? else {
                    return Err(wrong_keyboard_result("GetKeyboardType"));
                };
                Ok(u32::from(value as u16))
            }
            Win16KeyboardRequest::MapVirtualKey { code, map_type } => {
                let Win16HostKeyboardResult::MapVirtualKey(value) = host.win16_keyboard(
                    Win16HostKeyboardCall::MapVirtualKey { code, map_type })? else {
                    return Err(wrong_keyboard_result("MapVirtualKey"));
                };
                Ok(u32::from(value as u16))
            }
            Win16KeyboardRequest::GetCodePage => {
                let Win16HostKeyboardResult::CodePage(value) = host.win16_keyboard(
                    Win16HostKeyboardCall::GetCodePage)? else {
                    return Err(wrong_keyboard_result("GetKBCodePage"));
                };
                Ok(u32::from(value as u16))
            }
            Win16KeyboardRequest::GetKeyNameText { parameter, output, capacity } => {
                let count = usize::from(capacity);
                if count == 0 { return Ok(0); }
                self.preflight_guest_write(memory, output, count)?;
                let mut initial = Vec::new();
                initial.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "allocate Win16 key-name output buffer", error))?;
                initial.resize(count, 0);
                let Win16HostKeyboardResult::KeyNameText { output: bytes, written } =
                    host.win16_keyboard(Win16HostKeyboardCall::KeyNameText { parameter, output: initial })? else {
                        return Err(wrong_keyboard_result("GetKeyNameText"));
                    };
                if bytes.len() != count || written >= count {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "host key-name result exceeds the Win16 output buffer"));
                }
                self.write_guest_bytes(memory, output, &bytes[..written + 1])?;
                Ok(u32::from(written as u16))
            }
        }
    }

    pub(crate) fn wifeman_dbcs_lead_byte(
        &self,
        value: u8,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Win16HostKeyboardResult::CodePage(code_page) = host.win16_keyboard(
            Win16HostKeyboardCall::GetCodePage)? else {
            return Err(wrong_keyboard_result("MiscIsDBCSLeadByte code-page query"));
        };
        let Win16HostKeyboardResult::IsDbcsLeadByte(is_lead) = host.win16_keyboard(
            Win16HostKeyboardCall::IsDbcsLeadByte { code_page, value })? else {
            return Err(wrong_keyboard_result("MiscIsDBCSLeadByte"));
        };
        Ok(if is_lead { 1 } else { 0 })
    }

    fn read_guest_bytes(
        &self,
        memory: &Memory,
        address: u32,
        count: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        if count == 0 { return Ok(Vec::new()); }
        let pointer = self.selectors.pointer_from_far(address).map_err(crate::runtime_error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 keyboard input copy", error))?;
        bytes.resize(count, 0);
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        Ok(bytes)
    }

    fn preflight_guest_write(
        &self,
        memory: &Memory,
        address: u32,
        count: usize,
    ) -> Result<win16_abi::SegmentedPointer, RuntimeError> {
        if count == 0 {
            return self.selectors.pointer_from_far(address).map_err(crate::runtime_error);
        }
        let pointer = self.selectors.pointer_from_far(address).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Write, count, memory)
            .map_err(crate::runtime_error)?;
        Ok(pointer)
    }

    fn write_guest_bytes(
        &self,
        memory: &mut Memory,
        address: u32,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        let pointer = self.preflight_guest_write(memory, address, bytes.len())?;
        self.selectors.write(memory, pointer, bytes).map_err(crate::runtime_error)
    }
}

fn wrong_keyboard_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        format!("host returned the wrong result for Win16 {operation}"))
}
