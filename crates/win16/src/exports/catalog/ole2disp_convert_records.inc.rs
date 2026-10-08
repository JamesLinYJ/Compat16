// These Win16 descriptors follow the project-owned ole2disp.spec. The local
// Windows SDK 3.1 reference contains no OLE2DISP declarations; modern Microsoft
// OleAut signatures below govern only the native host ABI.
macro_rules! export_catalog_with_ole2disp_convert {
    ($($existing:tt)*) => {
        export_catalog_with_ole2disp! {
            $($existing)*
            Ole2DispVariantChangeType => OLE2DISP_VARIANT_CHANGE_TYPE:
                ("OLE2DISP", 12u16, Stack, ole2disp_convert::VARIANT_CHANGE_TYPE, Dword);
            Ole2DispVarI2FromI4 => OLE2DISP_VAR_I2_FROM_I4:
                ("OLE2DISP", 43u16, Stack, ole2disp_convert::VAR_I2_FROM_I4, Dword);
            Ole2DispVarI2FromR4 => OLE2DISP_VAR_I2_FROM_R4:
                ("OLE2DISP", 44u16, Stack, ole2disp_convert::VAR_I2_FROM_R4, Dword);
            Ole2DispVarI2FromR8 => OLE2DISP_VAR_I2_FROM_R8:
                ("OLE2DISP", 45u16, Stack, ole2disp_convert::VAR_I2_FROM_R8, Dword);
            Ole2DispVarI2FromCy => OLE2DISP_VAR_I2_FROM_CY:
                ("OLE2DISP", 46u16, Stack, ole2disp_convert::VAR_I2_FROM_CY, Dword);
            Ole2DispVarI2FromDate => OLE2DISP_VAR_I2_FROM_DATE:
                ("OLE2DISP", 47u16, Stack, ole2disp_convert::VAR_I2_FROM_DATE, Dword);
            Ole2DispVarI2FromStr => OLE2DISP_VAR_I2_FROM_STR:
                ("OLE2DISP", 48u16, Stack, ole2disp_convert::VAR_I2_FROM_STR, Dword);
            Ole2DispVarI2FromBool => OLE2DISP_VAR_I2_FROM_BOOL:
                ("OLE2DISP", 50u16, Stack, ole2disp_convert::VAR_I2_FROM_BOOL, Dword);
            Ole2DispVarI4FromStr => OLE2DISP_VAR_I4_FROM_STR:
                ("OLE2DISP", 56u16, Stack, ole2disp_convert::VAR_I4_FROM_STR, Dword);
            Ole2DispVarR4FromR8 => OLE2DISP_VAR_R4_FROM_R8:
                ("OLE2DISP", 61u16, Stack, ole2disp_convert::VAR_R4_FROM_R8, Dword);
            Ole2DispVarR4FromStr => OLE2DISP_VAR_R4_FROM_STR:
                ("OLE2DISP", 64u16, Stack, ole2disp_convert::VAR_R4_FROM_STR, Dword);
            Ole2DispVarR8FromStr => OLE2DISP_VAR_R8_FROM_STR:
                ("OLE2DISP", 72u16, Stack, ole2disp_convert::VAR_R8_FROM_STR, Dword);
            Ole2DispVarDateFromStr => OLE2DISP_VAR_DATE_FROM_STR:
                ("OLE2DISP", 80u16, Stack, ole2disp_convert::VAR_DATE_FROM_STR, Dword);
            Ole2DispVarCyFromStr => OLE2DISP_VAR_CY_FROM_STR:
                ("OLE2DISP", 88u16, Stack, ole2disp_convert::VAR_CY_FROM_STR, Dword);
            Ole2DispVarBstrFromI2 => OLE2DISP_VAR_BSTR_FROM_I2:
                ("OLE2DISP", 91u16, Stack, ole2disp_convert::VAR_BSTR_FROM_I2, Dword);
            Ole2DispVarBstrFromI4 => OLE2DISP_VAR_BSTR_FROM_I4:
                ("OLE2DISP", 92u16, Stack, ole2disp_convert::VAR_BSTR_FROM_I4, Dword);
            Ole2DispVarBstrFromR4 => OLE2DISP_VAR_BSTR_FROM_R4:
                ("OLE2DISP", 93u16, Stack, ole2disp_convert::VAR_BSTR_FROM_R4, Dword);
            Ole2DispVarBstrFromR8 => OLE2DISP_VAR_BSTR_FROM_R8:
                ("OLE2DISP", 94u16, Stack, ole2disp_convert::VAR_BSTR_FROM_R8, Dword);
            Ole2DispVarBstrFromCy => OLE2DISP_VAR_BSTR_FROM_CY:
                ("OLE2DISP", 95u16, Stack, ole2disp_convert::VAR_BSTR_FROM_CY, Dword);
            Ole2DispVarBstrFromDate => OLE2DISP_VAR_BSTR_FROM_DATE:
                ("OLE2DISP", 96u16, Stack, ole2disp_convert::VAR_BSTR_FROM_DATE, Dword);
            Ole2DispVarBstrFromDisp => OLE2DISP_VAR_BSTR_FROM_DISP:
                ("OLE2DISP", 97u16, Stack, ole2disp_convert::VAR_BSTR_FROM_DISP, Dword);
            Ole2DispVarBstrFromBool => OLE2DISP_VAR_BSTR_FROM_BOOL:
                ("OLE2DISP", 98u16, Stack, ole2disp_convert::VAR_BSTR_FROM_BOOL, Dword);
            Ole2DispVariantChangeTypeEx => OLE2DISP_VARIANT_CHANGE_TYPE_EX:
                ("OLE2DISP", 108u16, Stack, ole2disp_convert::VARIANT_CHANGE_TYPE_EX, Dword);
            Ole2DispVarUI1FromI2 => OLE2DISP_VAR_UI1_FROM_I2:
                ("OLE2DISP", 116u16, Stack, ole2disp_convert::VAR_UI1_FROM_I2, Dword);
            Ole2DispVarUI1FromI4 => OLE2DISP_VAR_UI1_FROM_I4:
                ("OLE2DISP", 117u16, Stack, ole2disp_convert::VAR_UI1_FROM_I4, Dword);
            Ole2DispVarUI1FromR4 => OLE2DISP_VAR_UI1_FROM_R4:
                ("OLE2DISP", 118u16, Stack, ole2disp_convert::VAR_UI1_FROM_R4, Dword);
            Ole2DispVarUI1FromR8 => OLE2DISP_VAR_UI1_FROM_R8:
                ("OLE2DISP", 119u16, Stack, ole2disp_convert::VAR_UI1_FROM_R8, Dword);
            Ole2DispVarUI1FromCy => OLE2DISP_VAR_UI1_FROM_CY:
                ("OLE2DISP", 120u16, Stack, ole2disp_convert::VAR_UI1_FROM_CY, Dword);
            Ole2DispVarUI1FromDate => OLE2DISP_VAR_UI1_FROM_DATE:
                ("OLE2DISP", 121u16, Stack, ole2disp_convert::VAR_UI1_FROM_DATE, Dword);
            Ole2DispVarUI1FromStr => OLE2DISP_VAR_UI1_FROM_STR:
                ("OLE2DISP", 122u16, Stack, ole2disp_convert::VAR_UI1_FROM_STR, Dword);
            Ole2DispVarUI1FromDisp => OLE2DISP_VAR_UI1_FROM_DISP:
                ("OLE2DISP", 123u16, Stack, ole2disp_convert::VAR_UI1_FROM_DISP, Dword);
            Ole2DispVarUI1FromBool => OLE2DISP_VAR_UI1_FROM_BOOL:
                ("OLE2DISP", 124u16, Stack, ole2disp_convert::VAR_UI1_FROM_BOOL, Dword);
            Ole2DispVarI2FromUI1 => OLE2DISP_VAR_I2_FROM_UI1:
                ("OLE2DISP", 125u16, Stack, ole2disp_convert::VAR_I2_FROM_UI1, Dword);
            Ole2DispVarBstrFromUI1 => OLE2DISP_VAR_BSTR_FROM_UI1:
                ("OLE2DISP", 131u16, Stack, ole2disp_convert::VAR_BSTR_FROM_UI1, Dword);
        }
    };
}
