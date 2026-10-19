//! Runtime for library exports and leftover OLE rows that had no call.
//!
//! Binding ids are `6000000`–`6999999`, plus `9200000`–`9299999` for library
//! signatures recovered from public Microsoft documentation. Guest selectors
//! stay on the caller's stack. This module does not read them and does not
//! turn them into host pointers. A call the host cannot perform returns the
//! SDK failure value.

use guest_core::memory::Memory;
use win16_abi::{Win16ExportDescriptor, Win16ReturnKind};
use x86_cpu::Cpu;

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

/// Network DDE has no host service. `NDDE_NOT_IMPLEMENTED` is 14.
const NDDE_NOT_IMPLEMENTED: u32 = 14;
/// `NERR_NetNotStarted` (2102): the workstation driver is not installed.
const NERR_NET_NOT_STARTED: u32 = 2102;
/// `MMSYSERR_NOTSUPPORTED` from the Windows 3.1 multimedia headers.
const MMSYSERR_NOTSUPPORTED: u32 = 8;
const E_NOTIMPL: u32 = 0x8000_4001;
/// `CLR_NONE`. No image list has a background color.
const CLR_NONE: u32 = 0xFFFF_FFFF;
/// Documented not-found or creation-failure index, the 16-bit value -1.
const INDEX_NOT_FOUND: u32 = 0xFFFF;
/// Windows 3.1 `mmsystemGetVersion`: major 3, minor 10.
const MMSYSTEM_310: u32 = 0x030A;

impl Win16State {
    pub(super) fn library_remainder(
        &mut self,
        ordinal: u16,
        descriptor: &Win16ExportDescriptor,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let module = descriptor.module();
        let name = descriptor.name();
        if name.eq_ignore_ascii_case("mmTaskYield") {
            // Same host yield as KERNEL `OldYield`. There is still one guest task.
            self.kernel_old_yield(host)?;
            return Ok(0);
        }
        let value = if name.eq_ignore_ascii_case("mmGetCurrentTask") {
            u32::from(self.current_task_handle()?)
        } else if name.eq_ignore_ascii_case("mmsystemGetVersion") {
            MMSYSTEM_310
        } else {
            failure_value(module, name, descriptor.return_kind)
        };
        if !is_defined(name)
            && self
                .library_remainder_reported
                .insert((module_key(module), ordinal))
        {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "{module} ordinal {ordinal} {name} {} and does not write guest memory",
                    failure_phrase(module, name, descriptor.return_kind)
                ),
            ));
        }
        Ok(value)
    }

    /// Register-context glue has no stack arguments. AX and DX return zero.
    pub(super) fn fail_library_register_remainder(
        &mut self,
        cpu: &mut Cpu,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        descriptor: &Win16ExportDescriptor,
    ) -> Result<Option<u8>, RuntimeError> {
        let ordinal = descriptor.ordinal();
        let module = descriptor.module();
        let name = descriptor.name();
        if self
            .library_remainder_reported
            .insert((module_key(module), ordinal))
        {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "{module} ordinal {ordinal} {name} returns zero and does not install a callback"
                ),
            ));
        }
        let (return_selector, return_offset, return_sp) = self.far_return(&cpu.regs, memory, 0)?;
        self.complete_return(
            &mut cpu.regs,
            return_selector,
            return_offset,
            return_sp,
            0,
            Win16ReturnKind::Dword,
        )
    }
}

fn is_defined(name: &str) -> bool {
    name.eq_ignore_ascii_case("mmGetCurrentTask")
        || name.eq_ignore_ascii_case("mmsystemGetVersion")
        || name.eq_ignore_ascii_case("DllEntryPoint")
        || name.eq_ignore_ascii_case("WEP")
}

fn failure_value(module: &str, name: &str, return_kind: Win16ReturnKind) -> u32 {
    let module = module.to_ascii_uppercase();
    let upper = name.to_ascii_uppercase();
    if upper == "DLLENTRYPOINT" || upper == "WEP" {
        return 1;
    }
    if module == "NDDEAPI" {
        if upper.contains("ISVALID") || upper == "NDDEGETWINDOW" {
            return 0;
        }
        return NDDE_NOT_IMPLEMENTED;
    }
    if module == "NETAPI" {
        return NERR_NET_NOT_STARTED;
    }
    if module == "MMSYSTEM" && matches!(upper.as_str(), "MMTASKCREATE" | "MMTHREADCREATE") {
        return MMSYSERR_NOTSUPPORTED;
    }
    if module == "COMMCTRL" {
        if matches!(
            upper.as_str(),
            "IMAGELIST_SETBKCOLOR" | "IMAGELIST_GETBKCOLOR"
        ) {
            return CLR_NONE;
        }
        if matches!(
            upper.as_str(),
            "LBITEMFROMPT"
                | "IMAGELIST_ADD"
                | "IMAGELIST_ADDICON"
                | "IMAGELIST_REPLACEICON"
                | "PROPERTYSHEET"
                | "DPA_GETPTRINDEX"
                | "DPA_INSERTPTR"
                | "DPA_SEARCH"
        ) {
            return INDEX_NOT_FOUND;
        }
    }
    if ole_hresult_module(&module)
        && matches!(
            return_kind,
            Win16ReturnKind::Dword | Win16ReturnKind::RegisterContext
        )
    {
        return E_NOTIMPL;
    }
    0
}

fn failure_phrase(module: &str, name: &str, return_kind: Win16ReturnKind) -> &'static str {
    let module = module.to_ascii_uppercase();
    let upper = name.to_ascii_uppercase();
    if module == "NDDEAPI" && !(upper.contains("ISVALID") || upper == "NDDEGETWINDOW") {
        return "returns NDDE_NOT_IMPLEMENTED";
    }
    if module == "NETAPI" {
        return "returns NERR_NetNotStarted";
    }
    if module == "MMSYSTEM" && matches!(upper.as_str(), "MMTASKCREATE" | "MMTHREADCREATE") {
        return "returns MMSYSERR_NOTSUPPORTED";
    }
    if module == "WINNLS" && upper == "WINNLSGETIMEHOTKEY" {
        return "returns zero because no IME hotkey is published";
    }
    if module == "COMMCTRL"
        && matches!(
            upper.as_str(),
            "IMAGELIST_SETBKCOLOR" | "IMAGELIST_GETBKCOLOR"
        )
    {
        return "returns CLR_NONE";
    }
    if module == "COMMCTRL"
        && matches!(
            upper.as_str(),
            "LBITEMFROMPT"
                | "IMAGELIST_ADD"
                | "IMAGELIST_ADDICON"
                | "IMAGELIST_REPLACEICON"
                | "PROPERTYSHEET"
                | "DPA_GETPTRINDEX"
                | "DPA_INSERTPTR"
                | "DPA_SEARCH"
        )
    {
        return "returns -1";
    }
    if ole_hresult_module(&module)
        && matches!(
            return_kind,
            Win16ReturnKind::Dword | Win16ReturnKind::RegisterContext
        )
    {
        return "returns E_NOTIMPL";
    }
    match return_kind {
        Win16ReturnKind::Void => "is void",
        _ => "returns zero",
    }
}

fn ole_hresult_module(module: &str) -> bool {
    matches!(
        module,
        "OLE2"
            | "OLE2CONV"
            | "OLE2DISP"
            | "OLE2NLS"
            | "OLE2PROX"
            | "OLE2THK"
            | "COMPOBJ"
            | "STORAGE"
            | "TYPELIB"
    )
}

fn module_key(module: &str) -> u8 {
    match module.to_ascii_uppercase().as_str() {
        "COMMCTRL" => 1,
        "COMMDLG" => 2,
        "CTL3D" => 3,
        "CTL3DV2" => 4,
        "MMSYSTEM" => 5,
        "MSACM" => 6,
        "NDDEAPI" => 7,
        "NETAPI" => 8,
        "RMPATCH" => 9,
        "SHELL" => 10,
        "TOOLHELP" => 11,
        "WIFEMAN" => 12,
        "WIN87EM" => 13,
        "WINNLS" => 14,
        "WINOLDAP" => 15,
        "OLE2" => 16,
        _ => 255,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_remainder_contract_ndde_and_netapi_are_sdk_failures() {
        assert_eq!(
            failure_value("NDDEAPI", "NDdeShareAdd", Win16ReturnKind::Word),
            14
        );
        assert_eq!(
            failure_value("NDDEAPI", "NDdeIsValidShareName", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("NDDEAPI", "NDdeGetWindow", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("NETAPI", "NetWkstaGetInfo", Win16ReturnKind::Word),
            2102
        );
    }

    #[test]
    fn library_remainder_contract_indexes_colors_and_hresults_fail() {
        assert_eq!(
            failure_value("COMMCTRL", "LBITEMFROMPT", Win16ReturnKind::Word),
            0xFFFF
        );
        assert_eq!(
            failure_value("COMMCTRL", "IMAGELIST_GETBKCOLOR", Win16ReturnKind::Dword),
            0xFFFF_FFFF
        );
        assert_eq!(
            failure_value("COMMCTRL", "IMAGELIST_DESTROY", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("OLE2", "OLECREATELINK", Win16ReturnKind::Dword),
            0x8000_4001
        );
        assert_eq!(
            failure_value("OLE2", "ISACCELERATOR", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("MMSYSTEM", "mmTaskCreate", Win16ReturnKind::Dword),
            8
        );
        assert_eq!(
            failure_value("MMSYSTEM", "DllEntryPoint", Win16ReturnKind::Dword),
            1
        );
        assert_eq!(
            failure_value("SHELL", "AboutDlgProc", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("SHELL", "RESTARTDIALOG", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("WINNLS", "WINNLSGETIMEHOTKEY", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_phrase("WINNLS", "WINNLSGETIMEHOTKEY", Win16ReturnKind::Word),
            "returns zero because no IME hotkey is published"
        );
        assert_eq!(
            failure_value("TOOLHELP", "Local32Info", Win16ReturnKind::Word),
            0
        );
        assert_eq!(
            failure_value("TOOLHELP", "Local32Next", Win16ReturnKind::Word),
            0
        );
    }
}
