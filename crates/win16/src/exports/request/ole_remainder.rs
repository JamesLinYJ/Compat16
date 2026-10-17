//! OLE stack exports that were declaration-only.
//!
//! The ordinal identifies the catalog row. Guest far pointers stay on the
//! stack and are not stored as host pointers.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16OleRemainderModule {
    Ole2,
    Ole2Conv,
    Ole2Disp,
    Ole2Nls,
    Ole2Prox,
    Ole2Thk,
    OleCli,
    OleSvr,
    Compobj,
    Storage,
    Typelib,
}

impl Win16OleRemainderModule {
    pub fn from_catalog_name(module: &str) -> Option<Self> {
        Some(match module {
            "OLE2" => Self::Ole2,
            "OLE2CONV" => Self::Ole2Conv,
            "OLE2DISP" => Self::Ole2Disp,
            "OLE2NLS" => Self::Ole2Nls,
            "OLE2PROX" => Self::Ole2Prox,
            "OLE2THK" => Self::Ole2Thk,
            "OLECLI" => Self::OleCli,
            "OLESVR" => Self::OleSvr,
            "COMPOBJ" => Self::Compobj,
            "STORAGE" => Self::Storage,
            "TYPELIB" => Self::Typelib,
            _ => return None,
        })
    }
}
