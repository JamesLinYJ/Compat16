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
        name: &str,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let value = self.ole_remainder_value(module, ordinal, return_kind, name)?;
        if !is_defined_result(module, ordinal)
            && self.ole_remainder_reported.insert((module as u8, ordinal))
        {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "{module:?} ordinal {ordinal} {} and does not write guest memory",
                    failure_name(module, return_kind, name)
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
        name: &str,
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
            | Win16ReturnKind::RegisterContext => {
                if returns_scalar_zero(name) {
                    0
                } else if matches!(
                    module,
                    Win16OleRemainderModule::OleCli | Win16OleRemainderModule::OleSvr
                ) {
                    OLE_ERROR_GENERIC
                } else {
                    E_NOTIMPL
                }
            }
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

/// Pointer, handle, count, BOOL, and `LRESULT` results. Zero is the failure.
/// `E_NOTIMPL` is reserved for HRESULT contracts because `0x80004001` is a
/// non-null guest far pointer.
fn returns_scalar_zero(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if upper.ends_with("WNDPROC") || upper.ends_with("WINDOWPROC") || upper.ends_with("DLGPROC") {
        return true;
    }
    if upper == "ENUMFONTFUNC" {
        return true;
    }
    if let Some((owner, suffix)) = upper.rsplit_once('_') {
        if !owner.is_empty()
            && matches!(
                suffix,
                "ADDREF"
                    | "RELEASE"
                    | "ALLOC"
                    | "REALLOC"
                    | "FREE"
                    | "GETSIZE"
                    | "DIDALLOC"
                    | "HEAPMINIMIZE"
            )
        {
            return true;
        }
    }
    matches!(
        upper.as_str(),
        "ISVALIDINTERFACE" | "COISOLE1CLASS" | "COMEMALLOC" | "LOOKUPETASK" | "LHASHVALOFNAMESYS"
    )
}

fn failure_name(
    module: Win16OleRemainderModule,
    return_kind: Win16ReturnKind,
    name: &str,
) -> &'static str {
    match return_kind {
        Win16ReturnKind::Void => "is void",
        Win16ReturnKind::Word => "returns zero",
        Win16ReturnKind::Dword | Win16ReturnKind::FarPointer | Win16ReturnKind::RegisterContext => {
            if returns_scalar_zero(name) {
                "returns zero"
            } else {
                match module {
                    Win16OleRemainderModule::OleCli | Win16OleRemainderModule::OleSvr => {
                        "returns OLE_ERROR_GENERIC"
                    }
                    _ => "returns E_NOTIMPL",
                }
            }
        }
    }
}
