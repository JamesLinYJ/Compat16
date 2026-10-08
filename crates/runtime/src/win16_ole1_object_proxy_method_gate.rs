//! Checked 39-slot OLE1 native object method gate entry.

use super::*;

impl Win16State {
    /// Entry for the 39 checked client OLEOBJECT method gates. Its Pascal stack is
    /// decoded from the SDK OLE.H declarations above, including the DWORD FAR
    /// `this` argument. Every slot has an explicit native/local implementation
    /// or a checked guest-visible failure with a method-specific diagnostic.
    pub(in crate::win16_runtime) fn begin_ole1_object_proxy_method(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        object_proxy_id: u64,
        slot: u8,
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(abi) = OBJECT_METHOD_ABI.get(usize::from(slot)).copied() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native OLE1 gate targets a non-public OLEOBJECT slot",
            ));
        };
        let (signature_storage, signature_len) = method_signature(slot).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "OLE1 method ABI slot is missing")
        })?;
        if signature_len != abi.arguments.len() + 1 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 method ABI signature length is inconsistent",
            ));
        }
        let signature = &signature_storage[..signature_len];
        let stack = self
            .selectors
            .pointer_from_raw(guest_core::Selector(cpu.regs.ss), cpu.regs.sp())
            .map_err(crate::runtime_error)?;
        let frame = Win16CallFrame::new(stack, ReturnAddressWidth::Far);
        let cleanup = frame
            .cleanup(Win16CallingConvention::Pascal, signature)
            .map_err(crate::runtime_error)?;
        let return_to = self.far_return(&cpu.regs, memory, cleanup.callee_pop_bytes)?;
        let arguments = frame
            .decode_arguments(
                &self.selectors,
                memory,
                Win16CallingConvention::Pascal,
                signature,
            )
            .map_err(crate::runtime_error)?;
        let this_far = match arguments.first() {
            Some(Win16Argument::Dword(value)) => *value,
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 public method decoder did not produce the FAR this argument",
                ));
            }
        };
        let record = self
            .ole1_client_documents
            .native_object_proxies
            .iter()
            .find(|record| record.id == object_proxy_id)
            .copied();
        let Some(record) = record else {
            let dde_record = self
                .ole1_client_documents
                .dde_object_proxies
                .iter()
                .find(|record| record.id == object_proxy_id)
                .cloned();
            let Some(dde_record) = dde_record else {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "OLE1 object gate has no live checked proxy record",
                ));
            };
            if canonical_far(this_far) != canonical_far(dde_record.object_far)
                || !self.validate_ole1_dde_object_proxy(&dde_record, slot, memory)?
            {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "OLE1 DDE object gate received a stale or mismatched FAR proxy",
                ));
            }
            return self.begin_ole1_dde_object_method(
                cpu, dos, memory, host, dde_record, slot, &arguments, return_to,
            );
        };
        if canonical_far(this_far) != canonical_far(record.object_far)
            || !validation::validate(self, record, slot, memory)?
        {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "OLE1 native object gate received a stale or mismatched FAR proxy",
            ));
        }
        let result = match slot {
            1 | 11 | 20 | 21 => {
                return self.begin_ole1_typed_object_method(
                    cpu, dos, memory, host, record, slot, &arguments, return_to,
                );
            }
            24 => u32::from(local_methods::query_link_update_options(
                self, record, &arguments, memory,
            )),
            25 => {
                let (status, gap) = local_methods::set_link_update_options(record, &arguments);
                if let Some(context) = gap {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        format!(
                            "OLE1 client object slot 25 SetLinkUpdateOptions returned guest OLE status {status}: {context}"
                        ),
                    ));
                }
                u32::from(status)
            }
            33 => u32::from(local_methods::query_release_status(self, record)),
            34 => u32::from(local_methods::query_release_error(self, record)),
            35 => u32::from(local_methods::query_release_method(self, record)),
            37 => u32::from(local_methods::object_long(self, record, &arguments, memory)),
            _ => {
                let description = method_abi::method_compatibility_gap(slot).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 39-slot gate reached an unmapped slot outside the client table",
                    )
                })?;
                let result = match slot {
                    // SDK value-returning methods use null for no matching
                    // protocol and format zero for end-of-enumeration.
                    0 | 8 => 0,
                    _ => u32::from(method_abi::method_compatibility_status(slot).ok_or_else(
                        || {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "OLE1 method gap has no documented guest failure status",
                            )
                        },
                    )?),
                };
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!(
                        "OLE1 client object slot {slot} returned guest value {result:#x}: {description}"
                    ),
                ));
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    result,
                    match abi.result {
                        OLE1ObjectMethodReturn::FarPointer => Win16ReturnKind::FarPointer,
                        OLE1ObjectMethodReturn::StatusWord
                        | OLE1ObjectMethodReturn::ClipFormatWord => Win16ReturnKind::Word,
                    },
                );
            }
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            result,
            match abi.result {
                OLE1ObjectMethodReturn::FarPointer => Win16ReturnKind::FarPointer,
                OLE1ObjectMethodReturn::StatusWord | OLE1ObjectMethodReturn::ClipFormatWord => {
                    Win16ReturnKind::Word
                }
            },
        )
    }
}
