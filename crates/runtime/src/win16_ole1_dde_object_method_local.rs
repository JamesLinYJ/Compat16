use super::*;

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
        let status = super::super::object_proxy::object_method_gap_status(slot).ok_or_else(|| {
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
