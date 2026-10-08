//! Inventory-typed Win16 `CTL3D.DLL` and `CTL3DV2.DLL` requests.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16Ctl3dModule {
    Ctl3d,
    Ctl3dV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16Ctl3dArgument {
    Word(u16),
    SignedWord(i16),
    Dword(u32),
    FarPointer(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16Ctl3dRequest {
    pub module: Win16Ctl3dModule,
    pub ordinal: u16,
    pub name: Option<&'static str>,
    pub arguments: Vec<Win16Ctl3dArgument>,
}
