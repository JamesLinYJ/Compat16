//! Owned call records for the OLE2DISP scalar and VARIANT conversions.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Ole2DispConvertInput {
    I2(i16),
    I4(i32),
    R4Bits(u32),
    R8Bits(u64),
    CurrencyBits(u64),
    DateBits(u64),
    Bool(i16),
    Ui1(u8),
    AnsiString(Option<Vec<u8>>),
    /// Opaque Win16 interface FAR value. Runtime must never cast it to a host
    /// pointer; without a COM lease bridge it returns E_NOTIMPL and warns.
    InterfaceFar(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16Ole2DispLocaleFlags {
    pub lcid: u32,
    pub dw_flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Ole2DispConvertOperation {
    VarFrom {
        ordinal: u16,
        input: Win16Ole2DispConvertInput,
        locale: Option<Win16Ole2DispLocaleFlags>,
        output_far: u32,
    },
    VariantChangeType {
        destination_far: u32,
        source_far: u32,
        target_vartype: u16,
        flags: u16,
        lcid: Option<u32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16Ole2DispConvertCall {
    pub operation: Win16Ole2DispConvertOperation,
}
