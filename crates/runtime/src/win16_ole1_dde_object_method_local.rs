use super::*;

pub(super) const OLE1_ERROR_BLANK: Win16Ole1Status = 7;
pub(super) const OLE1_ERROR_NOT_EQUAL: Win16Ole1Status = 17;
pub(super) const OLE1_ERROR_SIZE: Win16Ole1Status = 26;
pub(super) const OLE1_ERROR_NOT_OPEN: Win16Ole1Status = 34;
pub(super) const OT_EMBEDDED: i32 = 2;

/// `QueryReleaseMethod` codes already used by the native OLE1 object adapter.
pub(super) fn release_method_code(pending_slot: Option<u8>) -> u16 {
    match pending_slot {
        Some(1) => 1,  // OLE_DELETE
        Some(20) => 8, // OLE_CLOSE
        Some(21) => 7, // OLE_UPDATE
        Some(_) => 15, // OLE_OTHER
        None => 0,     // OLE_NONE
    }
}

/// Required NUL-terminated byte count, and whether `capacity` can hold it.
pub(super) fn query_name_plan(
    name_len: usize,
    capacity: u16,
) -> Result<(u16, bool), Win16Ole1Status> {
    let required = name_len.checked_add(1).ok_or(OLE1_ERROR_MEMORY)?;
    let required = u16::try_from(required).map_err(|_| OLE1_ERROR_SIZE)?;
    Ok((required, capacity >= required))
}

#[cfg(test)]
mod plan_tests {
    use super::{query_name_plan, release_method_code};

    #[test]
    fn embedded_query_name_reports_the_required_size() {
        assert_eq!(query_name_plan(3, 4), Ok((4, true)));
        assert_eq!(query_name_plan(3, 3), Ok((4, false)));
        assert_eq!(release_method_code(None), 0);
        assert_eq!(release_method_code(Some(20)), 8);
        assert_eq!(release_method_code(Some(11)), 15);
    }
}

fn same_object_far(left: u32, right: u32) -> bool {
    let canonical =
        |address: u32| (u32::from(((address >> 16) as u16) & !0x7) << 16) | (address & 0xffff);
    canonical(left) == canonical(right)
}

impl Win16State {
    pub(super) fn return_dde_method_gap(
        &mut self,
        cpu: &mut Cpu,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        status: Win16Ole1Status,
        context: &'static str,
    ) -> Result<Option<u8>, RuntimeError> {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            format!("DDE-backed OLE1 method returned guest status {status}: {context}"),
        ));
        self.complete_dde_method_return(cpu, return_to, status)
    }

    pub(super) fn complete_dde_method_gap_slot(
        &mut self,
        cpu: &mut Cpu,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        slot: u8,
        record: &Win16Ole1DdeObjectProxyRecord,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Option<u8>, RuntimeError> {
        if slot == 0 {
            let protocol = match arguments.get(1) {
                Some(Win16Argument::Dword(far)) => self.ole1_read_string(*far, memory).ok(),
                _ => None,
            };
            let value = if protocol
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(b"StdFileEditing"))
            {
                record.object_far
            } else {
                0
            };
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                value,
                Win16ReturnKind::FarPointer,
            );
        }
        if slot == 8 {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        }
        if slot == 37 {
            return self.object_long(cpu, return_to, record, arguments, memory);
        }
        if matches!(slot, 33 | 34 | 35) {
            return self.complete_dde_method_return(cpu, return_to, OLE1_OK);
        }
        let status =
            super::super::object_proxy::object_method_gap_status(slot).ok_or_else(|| {
                dde_error(
                    Kind::InternalInvariant,
                    "DDE-backed OLE1 slot has no documented status mapping",
                )
            })?;
        let detail = super::super::object_proxy::object_method_gap_context(slot)
            .unwrap_or("DDE-backed object method is not implemented by the current client adapter");
        self.return_dde_method_gap(cpu, host, return_to, status, detail)
    }

    fn object_long(
        &mut self,
        cpu: &mut Cpu,
        return_to: (u16, u16, u32),
        record: &Win16Ole1DdeObjectProxyRecord,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Option<u8>, RuntimeError> {
        let (Some(Win16Argument::Word(flags)), Some(Win16Argument::Dword(data_far))) =
            (arguments.get(1), arguments.get(2))
        else {
            return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_ADDRESS);
        };
        let get = *flags & 2 != 0;
        let set = *flags & 1 != 0;
        if !get && !set {
            return self.complete_dde_method_return(cpu, return_to, OLE1_OK);
        }
        let pointer = match self.selectors.pointer_from_far(*data_far) {
            Ok(pointer) => pointer,
            Err(_) => return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_ADDRESS),
        };
        if (set
            && self
                .selectors
                .address_within(pointer, win16_abi::Access::Read, 4, memory.size_bytes())
                .is_err())
            || (get
                && self
                    .selectors
                    .address_within(pointer, win16_abi::Access::Write, 4, memory.size_bytes())
                    .is_err())
        {
            return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_ADDRESS);
        }
        let replacement = if set {
            let mut bytes = [0; 4];
            if self.selectors.read(memory, pointer, &mut bytes).is_err() {
                return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_ADDRESS);
            }
            Some(i32::from_le_bytes(bytes))
        } else {
            None
        };
        let current = self
            .ole1_client_documents
            .dde_object_proxies
            .iter_mut()
            .find(|current| current.id == record.id)
            .ok_or_else(|| {
                dde_error(
                    Kind::InvalidInput,
                    "DDE object proxy retired during ObjectLong",
                )
            })?;
        let field = if *flags & 4 != 0 {
            &mut current.handler_data
        } else {
            &mut current.app_data
        };
        if get
            && self
                .selectors
                .write(memory, pointer, &field.to_le_bytes())
                .is_err()
        {
            return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_ADDRESS);
        }
        if let Some(value) = replacement {
            *field = value;
        }
        self.complete_dde_method_return(cpu, return_to, OLE1_OK)
    }

    /// Synchronous embedded-object methods. `None` means the slot needs a DDE
    /// transaction or the compatibility-gap return.
    pub(super) fn local_dde_method_status(
        &mut self,
        record: &Win16Ole1DdeObjectProxyRecord,
        slot: u8,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Option<Win16Ole1Status>, RuntimeError> {
        let status = match slot {
            8 => Some(OLE1_OK),
            14 | 22 | 24 | 25 => Some(super::super::OLE1_ERROR_NOT_LINK),
            15 => Some(self.dde_equal(record, arguments)),
            21 | 32 | 33 | 34 => Some(OLE1_OK),
            26 => Some(self.dde_rename(record, arguments, memory)?),
            27 => Some(self.dde_query_name(record, arguments, memory)?),
            28 => Some(self.dde_query_type(arguments, memory)?),
            29 => Some(self.dde_query_bounds(record, arguments, memory)?),
            30 => Some(self.dde_query_size(arguments, memory)?),
            31 => Some(if record.closed {
                OLE1_ERROR_NOT_OPEN
            } else {
                OLE1_OK
            }),
            _ => None,
        };
        Ok(status)
    }

    fn dde_equal(
        &self,
        record: &Win16Ole1DdeObjectProxyRecord,
        arguments: &[Win16Argument],
    ) -> Win16Ole1Status {
        let Some(Win16Argument::Dword(other)) = arguments.get(1) else {
            return OLE1_ERROR_ADDRESS;
        };
        if same_object_far(record.object_far, *other) {
            OLE1_OK
        } else {
            OLE1_ERROR_NOT_EQUAL
        }
    }

    fn dde_rename(
        &mut self,
        record: &Win16Ole1DdeObjectProxyRecord,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Win16Ole1Status, RuntimeError> {
        let Some(Win16Argument::Dword(name_far)) = arguments.get(1) else {
            return Ok(OLE1_ERROR_ADDRESS);
        };
        let name = match self.ole1_read_string(*name_far, memory) {
            Ok(name) => name,
            Err(status) => return Ok(status),
        };
        let current = self
            .ole1_client_documents
            .dde_object_proxies
            .iter_mut()
            .find(|current| current.id == record.id)
            .ok_or_else(|| {
                dde_error(Kind::InvalidInput, "DDE object proxy retired during Rename")
            })?;
        current.object_name = name;
        Ok(OLE1_OK)
    }

    fn dde_query_name(
        &self,
        record: &Win16Ole1DdeObjectProxyRecord,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Win16Ole1Status, RuntimeError> {
        let (Some(Win16Argument::Dword(name_far)), Some(Win16Argument::Dword(size_far))) =
            (arguments.get(1), arguments.get(2))
        else {
            return Ok(OLE1_ERROR_ADDRESS);
        };
        let mut size_bytes = [0; 2];
        if self
            .read_dde_guest(*size_far, &mut size_bytes, memory)
            .is_err()
        {
            return Ok(OLE1_ERROR_ADDRESS);
        }
        let (required, fits) =
            match query_name_plan(record.object_name.len(), u16::from_le_bytes(size_bytes)) {
                Ok(plan) => plan,
                Err(status) => return Ok(status),
            };
        if fits {
            let mut bytes = Vec::new();
            if bytes
                .try_reserve_exact(record.object_name.len() + 1)
                .is_err()
            {
                return Ok(OLE1_ERROR_MEMORY);
            }
            bytes.extend_from_slice(&record.object_name);
            bytes.push(0);
            if self.write_dde_guest(*name_far, &bytes, memory).is_err() {
                return Ok(OLE1_ERROR_ADDRESS);
            }
        }
        if self
            .write_dde_guest(*size_far, &required.to_le_bytes(), memory)
            .is_err()
        {
            return Ok(OLE1_ERROR_ADDRESS);
        }
        Ok(if fits { OLE1_OK } else { OLE1_ERROR_SIZE })
    }

    fn dde_query_type(
        &self,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Win16Ole1Status, RuntimeError> {
        let Some(Win16Argument::Dword(output_far)) = arguments.get(1) else {
            return Ok(OLE1_ERROR_ADDRESS);
        };
        if self
            .write_dde_guest(*output_far, &OT_EMBEDDED.to_le_bytes(), memory)
            .is_err()
        {
            return Ok(OLE1_ERROR_ADDRESS);
        }
        Ok(OLE1_OK)
    }

    fn dde_query_bounds(
        &self,
        record: &Win16Ole1DdeObjectProxyRecord,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Win16Ole1Status, RuntimeError> {
        let Some(Win16Argument::Dword(output_far)) = arguments.get(1) else {
            return Ok(OLE1_ERROR_ADDRESS);
        };
        let Some(bounds) = record.bounds else {
            if self
                .guest_span(*output_far, win16_abi::Access::Write, 8, memory)
                .is_err()
            {
                return Ok(OLE1_ERROR_ADDRESS);
            }
            return Ok(OLE1_ERROR_BLANK);
        };
        if self.write_dde_guest(*output_far, &bounds, memory).is_err() {
            return Ok(OLE1_ERROR_ADDRESS);
        }
        Ok(OLE1_OK)
    }

    fn dde_query_size(
        &self,
        arguments: &[Win16Argument],
        memory: &mut Memory,
    ) -> Result<Win16Ole1Status, RuntimeError> {
        let Some(Win16Argument::Dword(output_far)) = arguments.get(1) else {
            return Ok(OLE1_ERROR_ADDRESS);
        };
        if self
            .guest_span(*output_far, win16_abi::Access::Write, 4, memory)
            .is_err()
        {
            return Ok(OLE1_ERROR_ADDRESS);
        }
        Ok(OLE1_ERROR_BLANK)
    }

    pub(super) fn read_dde_rect(
        &self,
        far: u32,
        memory: &mut Memory,
    ) -> Result<[u8; 8], Win16Ole1Status> {
        let mut rect = [0; 8];
        self.read_dde_guest(far, &mut rect, memory)?;
        Ok(rect)
    }

    pub(super) fn read_dde_execute_command(
        &mut self,
        handle_word: u16,
        memory: &mut Memory,
    ) -> Result<Result<Vec<u8>, Win16Ole1Status>, RuntimeError> {
        if handle_word == 0 {
            return Ok(Err(OLE1_ERROR_ADDRESS));
        }
        let handle = match self
            .heap
            .resolve_handle(guest_core::GuestHandle(handle_word))
        {
            Ok(handle) => handle,
            Err(_) => return Ok(Err(OLE1_ERROR_ADDRESS)),
        };
        let info = match self.heap.info(handle) {
            Ok(info) => info,
            Err(_) => return Ok(Err(OLE1_ERROR_ADDRESS)),
        };
        if info.discarded {
            return Ok(Err(OLE1_ERROR_ADDRESS));
        }
        if info.size == 0 || info.size > u32::from(u16::MAX) {
            return Ok(Err(OLE1_ERROR_MEMORY));
        }
        let pointer = match self.heap.lock(handle, &mut self.selectors, memory) {
            Ok(pointer) => pointer,
            Err(_) => return Ok(Err(OLE1_ERROR_ADDRESS)),
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(info.size as usize).is_err() {
            let _ = self.heap.unlock(handle, &mut self.selectors);
            return Ok(Err(OLE1_ERROR_MEMORY));
        }
        bytes.resize(info.size as usize, 0);
        let read = self.selectors.read(memory, pointer, &mut bytes);
        self.heap.unlock(handle, &mut self.selectors).map_err(|_| {
            dde_error(
                Kind::InternalInvariant,
                "OLE1 Execute global unlock failed after a checked lock",
            )
        })?;
        if read.is_err() {
            return Ok(Err(OLE1_ERROR_ADDRESS));
        }
        let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
            return Ok(Err(OLE1_ERROR_COMMAND));
        };
        let command = bytes[..=end].to_vec();
        if command.len() < 2 || command[0] != b'[' {
            return Ok(Err(OLE1_ERROR_COMMAND));
        }
        Ok(Ok(command))
    }

    fn read_dde_guest(
        &self,
        far: u32,
        bytes: &mut [u8],
        memory: &mut Memory,
    ) -> Result<(), Win16Ole1Status> {
        let pointer = self.guest_span(far, win16_abi::Access::Read, bytes.len(), memory)?;
        self.selectors
            .read(memory, pointer, bytes)
            .map_err(|_| OLE1_ERROR_ADDRESS)
    }

    fn write_dde_guest(
        &self,
        far: u32,
        bytes: &[u8],
        memory: &mut Memory,
    ) -> Result<(), Win16Ole1Status> {
        let pointer = self.guest_span(far, win16_abi::Access::Write, bytes.len(), memory)?;
        self.selectors
            .write(memory, pointer, bytes)
            .map_err(|_| OLE1_ERROR_ADDRESS)
    }

    fn guest_span(
        &self,
        far: u32,
        access: win16_abi::Access,
        len: usize,
        memory: &mut Memory,
    ) -> Result<win16_abi::SegmentedPointer, Win16Ole1Status> {
        if far == 0 {
            return Err(OLE1_ERROR_ADDRESS);
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        self.selectors
            .address_within(pointer, access, len, memory.size_bytes())
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        Ok(pointer)
    }

    pub(super) fn decode_dde_host_name(
        &self,
        far: u32,
        memory: &mut Memory,
    ) -> Result<Vec<u8>, Win16Ole1Status> {
        if far == 0 {
            return Ok(Vec::new());
        }
        self.ole1_read_string(far, memory)
    }
}
