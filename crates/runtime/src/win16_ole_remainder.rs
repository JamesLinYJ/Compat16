//! Runtime for OLE stack exports that were declaration-only.
//!
//! Guest selectors stay on the caller's stack. This module does not read them
//! and does not turn them into host pointers. A call the host cannot perform
//! returns the SDK failure value and does not write guest memory.

use win16_abi::{Win16OleRemainderModule, Win16ReturnKind};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const E_NOTIMPL: u32 = 0x8000_4001;
/// `OLE_ERROR_GENERIC` from the Windows 3.1 `OLESTATUS` enumeration. `OLE_OK` is 0.
const OLE_ERROR_GENERIC: u32 = 19;
/// Windows 3.1 OLE 2.01 `MAKELONG(rup, rmm)` with `rup` 639 and `rmm` 23.
const OLE2_01_BUILD: u32 = (23 << 16) | 639;

impl Win16State {
    pub(super) fn ole_remainder(
        &mut self,
        module: Win16OleRemainderModule,
        ordinal: u16,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let value = self.ole_remainder_value(module, ordinal, return_kind)?;
        if !is_defined_result(module, ordinal)
            && self.ole_remainder_reported.insert((module as u8, ordinal))
        {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "{module:?} ordinal {ordinal} {} and does not write guest memory",
                    failure_name(module, return_kind)
                ),
            ));
        }
        Ok(value)
    }

    fn ole_remainder_value(
        &self,
        module: Win16OleRemainderModule,
        ordinal: u16,
        return_kind: Win16ReturnKind,
    ) -> Result<u32, RuntimeError> {
        if is_version(module, ordinal) {
            return Ok(OLE2_01_BUILD);
        }
        if is_builtin_entry(module, ordinal) {
            return Ok(1);
        }
        // Guest task identity, the same kind of id KERNEL reports. Not a host process id.
        if matches!((module, ordinal), (Win16OleRemainderModule::Compobj, 34)) {
            return Ok(u32::from(self.current_task_handle()?));
        }
        Ok(match return_kind {
            Win16ReturnKind::Word | Win16ReturnKind::Void => 0,
            Win16ReturnKind::Dword
            | Win16ReturnKind::FarPointer
            | Win16ReturnKind::RegisterContext => match module {
                Win16OleRemainderModule::OleCli | Win16OleRemainderModule::OleSvr => {
                    OLE_ERROR_GENERIC
                }
                _ => E_NOTIMPL,
            },
        })
    }
}

fn is_version(module: Win16OleRemainderModule, ordinal: u16) -> bool {
    matches!(
        (module, ordinal),
        (Win16OleRemainderModule::Ole2, 1)
            | (Win16OleRemainderModule::Compobj, 1)
            | (Win16OleRemainderModule::Typelib, 15)
    )
}

fn is_builtin_entry(module: Win16OleRemainderModule, ordinal: u16) -> bool {
    matches!(
        (module, ordinal),
        (Win16OleRemainderModule::Ole2, 5)
            | (Win16OleRemainderModule::Ole2, 524)
            | (Win16OleRemainderModule::Ole2Nls, 11)
            | (Win16OleRemainderModule::OleSvr, 32)
            | (Win16OleRemainderModule::Compobj, 116)
    )
}

fn is_defined_result(module: Win16OleRemainderModule, ordinal: u16) -> bool {
    is_version(module, ordinal)
        || is_builtin_entry(module, ordinal)
        || matches!((module, ordinal), (Win16OleRemainderModule::Compobj, 34))
}

fn failure_name(module: Win16OleRemainderModule, return_kind: Win16ReturnKind) -> &'static str {
    match return_kind {
        Win16ReturnKind::Void => "is void",
        Win16ReturnKind::Word => "returns zero",
        Win16ReturnKind::Dword | Win16ReturnKind::FarPointer | Win16ReturnKind::RegisterContext => {
            match module {
                Win16OleRemainderModule::OleCli | Win16OleRemainderModule::OleSvr => {
                    "returns OLE_ERROR_GENERIC"
                }
                _ => "returns E_NOTIMPL",
            }
        }
    }
}
