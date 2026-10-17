//! Typed WINMEM32 guest calls. FAR output addresses remain guest values until
//! the runtime validates and writes them through the selector table.

use crate::{Win16Argument, Win16Error};

/// Version 1.00, as declared by the Windows 3.1 SDK header.
pub const WINMEM32_VERSION_1_00: u16 = 0x0100;
pub const WINMEM32_MAX_OBJECT_BYTES: u32 = 0x0400_0000;
pub const WINMEM32_MAX_16BIT_ALIAS_BYTES: u32 = 0x0001_0000;
pub const WINMEM32_INVALID_FUNCTION: u16 = 1;
pub const WINMEM32_INVALID_FLAGS: u16 = 2;
pub const WINMEM32_INVALID_ARGUMENT: u16 = 3;
pub const WINMEM32_INSUFFICIENT_SELECTORS: u16 = 4;
pub const WINMEM32_INSUFFICIENT_MEMORY: u16 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16Winmem32Request {
    GetVersion,
    Global32Alloc { size: u32, selector_output: u32, max_size: u32, flags: u16 },
    Global32Realloc { selector: u16, new_size: u32, flags: u16 },
    Global32Free { selector: u16, flags: u16 },
    Global16PointerAlloc {
        selector: u16,
        offset: u32,
        alias_output: u32,
        size: u32,
        flags: u16,
    },
    Global16PointerFree { selector: u16, alias: u32, flags: u16 },
    Global32CodeAlias { selector: u16, alias_output: u32, flags: u16 },
    Global32CodeAliasFree { selector: u16, alias: u16, flags: u16 },
}

pub fn decode_winmem32(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16Winmem32Request>, Win16Error> {
    let expected = match ordinal {
        1 => 0,
        2 => 4,
        3 | 7 | 8 => 3,
        4 => 2,
        5 => 5,
        6 => 3,
        _ => return Ok(None),
    };
    if arguments.len() != expected {
        return Err(Win16Error::InvalidRange);
    }

    let request = match ordinal {
        1 => Win16Winmem32Request::GetVersion,
        2 => Win16Winmem32Request::Global32Alloc {
            size: dword(arguments, 0)?, selector_output: dword(arguments, 1)?,
            max_size: dword(arguments, 2)?, flags: word(arguments, 3)?,
        },
        3 => Win16Winmem32Request::Global32Realloc {
            selector: word(arguments, 0)?, new_size: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        4 => Win16Winmem32Request::Global32Free {
            selector: word(arguments, 0)?, flags: word(arguments, 1)?,
        },
        5 => Win16Winmem32Request::Global16PointerAlloc {
            selector: word(arguments, 0)?, offset: dword(arguments, 1)?,
            alias_output: dword(arguments, 2)?, size: dword(arguments, 3)?,
            flags: word(arguments, 4)?,
        },
        6 => Win16Winmem32Request::Global16PointerFree {
            selector: word(arguments, 0)?, alias: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        7 => Win16Winmem32Request::Global32CodeAlias {
            selector: word(arguments, 0)?, alias_output: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        8 => Win16Winmem32Request::Global32CodeAliasFree {
            selector: word(arguments, 0)?, alias: word(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        _ => unreachable!("recognized WINMEM32 ordinal was checked above"),
    };
    Ok(Some(request))
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

#[cfg(test)]
mod tests {
    use super::{WINMEM32_VERSION_1_00, Win16Winmem32Request, decode_winmem32};
    use crate::exports::{
        ExportArgumentType, ExportImplementationState, ExportReturnModifier,
        lookup_export_metadata, resolve_export,
    };
    use crate::{
        ArgumentKind, ExportCallingConvention, ExportLookupTarget, Win16Argument, Win16Error,
        Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup, Win16ParameterType,
        Win16ReturnKind, lookup_export,
    };

    fn word(value: u16) -> Win16Argument {
        Win16Argument::Word(value)
    }

    fn dword(value: u32) -> Win16Argument {
        Win16Argument::Dword(value)
    }

    #[test]
    fn eight_winmem32_exports_bind_as_far_pascal_words() {
        let expected = [
            (
                1_u16,
                "GetWinMem32Version",
                Win16ExportId::Winmem32GetVersion,
                0_u16,
                &[] as &[ExportArgumentType],
            ),
            (
                2,
                "Global32Alloc",
                Win16ExportId::Winmem32Global32Alloc,
                14,
                &[
                    ExportArgumentType::Long,
                    ExportArgumentType::Pointer,
                    ExportArgumentType::Long,
                    ExportArgumentType::Word,
                ],
            ),
            (
                3,
                "Global32Realloc",
                Win16ExportId::Winmem32Global32Realloc,
                8,
                &[
                    ExportArgumentType::Word,
                    ExportArgumentType::Long,
                    ExportArgumentType::Word,
                ],
            ),
            (
                4,
                "Global32Free",
                Win16ExportId::Winmem32Global32Free,
                4,
                &[ExportArgumentType::Word, ExportArgumentType::Word],
            ),
            (
                5,
                "Global16PointerAlloc",
                Win16ExportId::Winmem32Global16PointerAlloc,
                16,
                &[
                    ExportArgumentType::Word,
                    ExportArgumentType::Long,
                    ExportArgumentType::Pointer,
                    ExportArgumentType::Long,
                    ExportArgumentType::Word,
                ],
            ),
            (
                6,
                "Global16PointerFree",
                Win16ExportId::Winmem32Global16PointerFree,
                8,
                &[
                    ExportArgumentType::Word,
                    ExportArgumentType::Long,
                    ExportArgumentType::Word,
                ],
            ),
            (
                7,
                "Global32CodeAlias",
                Win16ExportId::Winmem32Global32CodeAlias,
                8,
                &[
                    ExportArgumentType::Word,
                    ExportArgumentType::Pointer,
                    ExportArgumentType::Word,
                ],
            ),
            (
                8,
                "Global32CodeAliasFree",
                Win16ExportId::Winmem32Global32CodeAliasFree,
                6,
                &[
                    ExportArgumentType::Word,
                    ExportArgumentType::Word,
                    ExportArgumentType::Word,
                ],
            ),
        ];
        for (ordinal, name, id, popped, arguments) in expected {
            let by_ordinal =
                lookup_export(b"WINMEM32", ExportLookupTarget::Ordinal(ordinal)).unwrap();
            let by_name =
                lookup_export(b"winmem32.dll", ExportLookupTarget::Name(name.as_bytes())).unwrap();
            assert_eq!(by_ordinal, by_name);
            assert_eq!(by_ordinal.id, id);
            assert_eq!(by_ordinal.ordinal(), ordinal);
            assert_eq!(by_ordinal.name(), name);
            assert_eq!(by_ordinal.module(), "WINMEM32");
            assert_eq!(by_ordinal.abi_kind, Win16ExportAbiKind::Stack);
            assert_eq!(
                by_ordinal.calling_convention,
                ExportCallingConvention::Pascal
            );
            assert_eq!(by_ordinal.return_kind, Win16ReturnKind::Word);
            assert_eq!(
                by_ordinal.stack_cleanup,
                Win16ExportStackCleanup::Fixed(crate::StackCleanup {
                    callee_pop_bytes: popped,
                    caller_pop_bytes: 0,
                }),
            );
            assert!(by_ordinal.parameters.iter().all(|parameter| {
                matches!(parameter.kind, ArgumentKind::Word | ArgumentKind::Dword)
            }));
            let metadata =
                lookup_export_metadata(b"WINMEM32", ExportLookupTarget::Ordinal(ordinal)).unwrap();
            let abi = metadata.abi.unwrap();
            assert_eq!(abi.arguments, arguments);
            assert_eq!(abi.return_modifier, ExportReturnModifier::Ret16);
            assert_eq!(
                resolve_export(b"WINMEM32", ExportLookupTarget::Ordinal(ordinal))
                    .unwrap()
                    .state,
                ExportImplementationState::BoundToRequest,
            );
        }
        let alloc = lookup_export(b"WINMEM32", ExportLookupTarget::Ordinal(2)).unwrap();
        assert_eq!(
            alloc.parameters[1].parameter_type,
            Win16ParameterType::FarPointer
        );
        assert_eq!(alloc.parameters[0].kind, ArgumentKind::Dword);
        assert_eq!(alloc.parameters[3].kind, ArgumentKind::Word);
    }

    #[test]
    fn decode_winmem32_keeps_guest_far_addresses_unresolved() {
        assert_eq!(
            decode_winmem32(1, &[]).unwrap(),
            Some(Win16Winmem32Request::GetVersion)
        );
        assert_eq!(WINMEM32_VERSION_1_00, 0x0100);
        assert_eq!(
            decode_winmem32(
                5,
                &[
                    word(0x1f),
                    dword(0x10008),
                    dword(0x12340000),
                    dword(16),
                    word(0)
                ]
            )
            .unwrap(),
            Some(Win16Winmem32Request::Global16PointerAlloc {
                selector: 0x1f,
                offset: 0x10008,
                alias_output: 0x12340000,
                size: 16,
                flags: 0,
            }),
        );
        assert_eq!(decode_winmem32(9, &[]).unwrap(), None);
        assert_eq!(
            decode_winmem32(2, &[dword(1), dword(2), dword(3)]).unwrap_err(),
            Win16Error::InvalidRange
        );
        assert_eq!(
            decode_winmem32(4, &[dword(1), word(0)]).unwrap_err(),
            Win16Error::InvalidRange
        );
    }
}
