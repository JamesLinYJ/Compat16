//! Owned requests for the OLE2DISP scalar and variant conversion exports.
//!
//! Guest FAR values are resolved before a request is built. Floats stay as
//! raw bits until the Windows ABI call, and Win16 strings own copied bytes.

use crate::win16_automation_values::Win16AutomationValue;

/// Narrow host callback surface used by the guest transaction. A single
/// mutable host can report diagnostics and convert without overlapping
/// closure captures or buffering warnings.
pub(crate) trait Win16AutomationConversionServices {
    fn report_diagnostic(&mut self, diagnostic: crate::Diagnostic);

    fn convert(
        &mut self,
        operation: Win16Ole2DispConversionOperation,
    ) -> Result<Win16Ole2DispConversionResult, crate::RuntimeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Ole2DispConversionInput {
    I2(i16),
    I4(i32),
    R4Bits(u32),
    R8Bits(u64),
    CurrencyBits(u64),
    DateBits(u64),
    Bool(i16),
    Ui1(u8),
    AnsiString(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Win16Ole2DispConversionOperation {
    VarFrom {
        ordinal: u16,
        input: Win16Ole2DispConversionInput,
        locale: Option<Win16Ole2DispLocale>,
    },
    VariantChangeType {
        source: Win16AutomationValue,
        target_vartype: u16,
        flags: u16,
        lcid: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16Ole2DispLocale {
    pub lcid: u32,
    /// The Var*From* contract uses ULONG even though VariantChangeType uses
    /// USHORT. Keep this value 32-bit end-to-end.
    pub dw_flags: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Win16Ole2DispConversionValue {
    I2(i16),
    I4(i32),
    R4Bits(u32),
    R8Bits(u64),
    CurrencyBits(u64),
    DateBits(u64),
    Bstr(Option<Vec<u8>>),
    Ui1(u8),
    Variant(Win16AutomationValue),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Win16Ole2DispConversionResult {
    pub hresult: u32,
    /// Present only after HRESULT success. A missing value on success is an
    /// internal adapter invariant failure in the guest-side transaction.
    pub value: Option<Win16Ole2DispConversionValue>,
}
