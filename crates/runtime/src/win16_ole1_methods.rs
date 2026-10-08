//! OLE1 public object-method descriptors and guest-pointer preflight.
//!
//! Public export ordinals map to the Windows 3.1 `OLEOBJECTVTBL` slots here.
//! This module validates guest addresses and prepares callback arguments; it
//! never converts a guest address to a host pointer or enters guest code.

use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer};

use super::super::far_callback::{Win16FarCallbackArgument, Win16FarCallbackReturn};
use super::{OLE1_ERROR_ADDRESS, OLE1_ERROR_OBJECT, Win16State};

pub(super) const OLEOBJECT_BYTES: usize = 4;
const OLEOBJECTVTBL_ENTRY_BYTES: u32 = 4;
// OLE.H declares the complete client table through public ObjectLong and the
// internal-only ChangeData entry. The SERVERONLY layout is a distinct type;
// even methods whose public wrapper never calls the tail slots must validate
// the full 39-entry client wire region.
const OLEOBJECTVTBL_ENTRY_COUNT: u32 = 39;
const OLEOBJECTVTBL_BYTES: u32 = OLEOBJECTVTBL_ENTRY_COUNT * OLEOBJECTVTBL_ENTRY_BYTES;

#[derive(Clone, Copy)]
pub(super) enum Ole1MethodArgument {
    Word,
    Dword,
    Input { bytes: u32 },
    OptionalInput { bytes: u32 },
    Output { bytes: u32 },
    InOut { bytes: u32 },
    Object,
    InputString,
    ValidateOnlyString,
    OutputString { length_argument: usize },
    Palette,
}

#[derive(Clone, Copy)]
pub(super) struct Ole1MethodContract {
    pub(super) slot: u32,
    pub(super) arguments: &'static [Ole1MethodArgument],
    pub(super) callback_return: Win16FarCallbackReturn,
    pub(super) null_on_failure: bool,
}

const NO_ARGUMENTS: &[Ole1MethodArgument] = &[];
const CLONE_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::Input { bytes: 4 },
    Ole1MethodArgument::Dword,
    Ole1MethodArgument::InputString,
    Ole1MethodArgument::Output { bytes: 4 },
];
const COPY_FROM_LINK_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::ValidateOnlyString,
    Ole1MethodArgument::Input { bytes: 4 },
    Ole1MethodArgument::Dword,
    Ole1MethodArgument::InputString,
    Ole1MethodArgument::Output { bytes: 4 },
];
const OBJECT_CONVERT_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::InputString,
    Ole1MethodArgument::Input { bytes: 4 },
    Ole1MethodArgument::Dword,
    Ole1MethodArgument::InputString,
    Ole1MethodArgument::Output { bytes: 4 },
];
const HOST_NAME_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::InputString,
    Ole1MethodArgument::InputString,
];
const RECT_INPUT_ARGUMENTS: &[Ole1MethodArgument] = &[Ole1MethodArgument::Input { bytes: 8 }];
const RECT_OUTPUT_ARGUMENTS: &[Ole1MethodArgument] = &[Ole1MethodArgument::Output { bytes: 8 }];
const OUTPUT_DWORD_ARGUMENTS: &[Ole1MethodArgument] = &[Ole1MethodArgument::Output { bytes: 4 }];
const DRAW_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::Word,
    Ole1MethodArgument::Input { bytes: 8 },
    // SDK 3.1 CLIDEMO passes NULL for OleDraw's lpWBounds argument.
    Ole1MethodArgument::OptionalInput { bytes: 8 },
    Ole1MethodArgument::Word,
];
const ACTIVATE_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::Word,
    Ole1MethodArgument::Word,
    Ole1MethodArgument::Word,
    Ole1MethodArgument::Word,
    Ole1MethodArgument::Input { bytes: 8 },
];
const LINK_OPTIONS_OUTPUT_ARGUMENTS: &[Ole1MethodArgument] =
    &[Ole1MethodArgument::Output { bytes: 2 }];
const FORMAT_ARGUMENTS: &[Ole1MethodArgument] = &[Ole1MethodArgument::Word];
const GET_DATA_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::Word,
    Ole1MethodArgument::Output { bytes: 2 },
];
const SET_DATA_ARGUMENTS: &[Ole1MethodArgument] =
    &[Ole1MethodArgument::Word, Ole1MethodArgument::Word];
const STRING_ARGUMENTS: &[Ole1MethodArgument] = &[Ole1MethodArgument::InputString];
const QUERY_NAME_ARGUMENTS: &[Ole1MethodArgument] = &[
    Ole1MethodArgument::OutputString { length_argument: 1 },
    Ole1MethodArgument::InOut { bytes: 2 },
];
const PALETTE_ARGUMENTS: &[Ole1MethodArgument] = &[Ole1MethodArgument::Palette];
const EXECUTE_ARGUMENTS: &[Ole1MethodArgument] =
    &[Ole1MethodArgument::Word, Ole1MethodArgument::Word];

pub(super) fn ole1_method_contract(ordinal: u16) -> Option<Ole1MethodContract> {
    let (slot, arguments, callback_return, null_on_failure) = match ordinal {
        2 => (10, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        3 => (
            12,
            &[Ole1MethodArgument::Input { bytes: 4 }][..],
            Win16FarCallbackReturn::Word,
            false,
        ),
        6 => (13, CLONE_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        7 => (
            14,
            COPY_FROM_LINK_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        8 => (
            15,
            &[Ole1MethodArgument::Object][..],
            Win16FarCallbackReturn::Word,
            false,
        ),
        13 => (16, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        14 => (
            28,
            OUTPUT_DWORD_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        15 => (11, HOST_NAME_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        16 => (
            6,
            &[Ole1MethodArgument::Word][..],
            Win16FarCallbackReturn::Word,
            false,
        ),
        17 => (7, RECT_INPUT_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        18 => (
            29,
            RECT_OUTPUT_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        19 => (17, DRAW_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        20 => (31, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        21 => (18, ACTIVATE_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        22 => (21, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        23 => (22, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        24 => (
            24,
            LINK_OPTIONS_OUTPUT_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        25 => (25, FORMAT_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        // OLECLIPFORMAT has no status channel: preflight failure means no
        // format, never a nonzero OLE error interpreted as a format identifier.
        26 => (8, FORMAT_ARGUMENTS, Win16FarCallbackReturn::Word, true),
        27 => (20, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        28 => (4, GET_DATA_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        29 => (5, SET_DATA_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        30 => (0, STRING_ARGUMENTS, Win16FarCallbackReturn::Dword, true),
        31 => (32, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        32 => (
            23,
            OBJECT_CONVERT_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        35 => (33, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        36 => (34, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        37 => (35, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        40 => (1, NO_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        46 => (26, STRING_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        48 => (
            27,
            QUERY_NAME_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        49 => (9, PALETTE_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        50 => (36, FORMAT_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        56 => (
            30,
            OUTPUT_DWORD_ARGUMENTS,
            Win16FarCallbackReturn::Word,
            false,
        ),
        57 => (19, EXECUTE_ARGUMENTS, Win16FarCallbackReturn::Word, false),
        _ => return None,
    };
    Some(Ole1MethodContract {
        slot,
        arguments,
        callback_return,
        null_on_failure,
    })
}

pub(super) fn client_document_argument(ordinal: u16) -> Option<usize> {
    match ordinal {
        6 => Some(1),
        7 | 32 => Some(2),
        _ => None,
    }
}

/// Parameter position of the SDK's `LPOLECLIENT` argument. Clone is
/// `(object, client, document, name, output)`; CopyFromLink and ObjectConvert
/// are `(object, protocol, client, document, name, output)`.
pub(super) fn client_pointer_argument(ordinal: u16) -> Option<usize> {
    match ordinal {
        6 => Some(0),
        7 | 32 => Some(1),
        _ => None,
    }
}

pub(super) fn required_protocol(ordinal: u16) -> Option<(usize, &'static [u8])> {
    match ordinal {
        7 => Some((0, b"StdFileEditing")),
        _ => None,
    }
}

/// Win3.1 SDK 3.1 SRVRDEMO's `ObjQueryProtocol` documents both protocol
/// results as `OLEOBJECT` structures with protocol-specific vtables.
pub(super) fn is_known_oleobject_protocol(protocol: &[u8]) -> bool {
    protocol.eq_ignore_ascii_case(b"StdFileEditing") || protocol.eq_ignore_ascii_case(b"StdExecute")
}

impl Win16State {
    pub(super) fn ole1_object_vtable(
        &self,
        object_far: u32,
        memory: &mut Memory,
    ) -> Result<u32, u16> {
        if self
            .ole1_client_documents
            .is_opaque_protocol_alias(object_far)
        {
            return Err(OLE1_ERROR_OBJECT);
        }
        self.ole1_object_vtable_wire(object_far, memory)
    }

    /// Validate the OLEOBJECT wire layout independently of protocol-alias
    /// policy. QueryProtocol may return the same address for more than one
    /// protocol; callers validate this layout only when the queried protocol
    /// is documented as an OLEOBJECT interface.
    pub(super) fn ole1_object_vtable_wire(
        &self,
        object_far: u32,
        memory: &mut Memory,
    ) -> Result<u32, u16> {
        if object_far == 0 {
            return Err(OLE1_ERROR_OBJECT);
        }
        let object = self
            .selectors
            .pointer_from_far(object_far)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        self.selectors
            .translate(object, Access::Read, OLEOBJECT_BYTES, memory)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        let mut object_bytes = [0_u8; OLEOBJECT_BYTES];
        self.selectors
            .read(memory, object, &mut object_bytes)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        let vtable_far = u32::from_le_bytes(object_bytes);
        if vtable_far == 0 {
            return Err(OLE1_ERROR_OBJECT);
        }
        let vtable = self
            .selectors
            .pointer_from_far(vtable_far)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        self.selectors
            .translate(vtable, Access::Read, OLEOBJECTVTBL_BYTES as usize, memory)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        Ok(vtable_far)
    }

    pub(super) fn ole1_method_address(
        &self,
        vtable_far: u32,
        slot: u32,
        memory: &mut Memory,
    ) -> Result<u32, u16> {
        if vtable_far == 0 {
            return Err(OLE1_ERROR_OBJECT);
        }

        let vtable = self
            .selectors
            .pointer_from_far(vtable_far)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        let slot_offset = slot
            .checked_mul(OLEOBJECTVTBL_ENTRY_BYTES)
            .ok_or(OLE1_ERROR_OBJECT)?;
        let method_slot = self
            .selectors
            .add_bytes(vtable, slot_offset)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        self.selectors
            .translate(method_slot, Access::Read, OLEOBJECT_BYTES, memory)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        let mut method_bytes = [0_u8; OLEOBJECT_BYTES];
        self.selectors
            .read(memory, method_slot, &mut method_bytes)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        let method_far = u32::from_le_bytes(method_bytes);
        if method_far == 0 {
            return Err(OLE1_ERROR_OBJECT);
        }
        let method = self
            .selectors
            .pointer_from_far(method_far)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        self.selectors
            .translate(method, Access::Execute, 1, memory)
            .map_err(|_| OLE1_ERROR_OBJECT)?;
        Ok(method_far)
    }

    pub(super) fn ole1_string_matches(
        &self,
        far: u32,
        expected: &[u8],
        memory: &mut Memory,
    ) -> Result<bool, u16> {
        if far == 0 {
            return Err(OLE1_ERROR_ADDRESS);
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        for index in 0..=expected.len() {
            let offset = u32::try_from(index).map_err(|_| OLE1_ERROR_ADDRESS)?;
            let byte_pointer = self
                .selectors
                .add_bytes(pointer, offset)
                .map_err(|_| OLE1_ERROR_ADDRESS)?;
            self.selectors
                .translate(byte_pointer, Access::Read, 1, memory)
                .map_err(|_| OLE1_ERROR_ADDRESS)?;
            let mut byte = [0_u8; 1];
            self.selectors
                .read(memory, byte_pointer, &mut byte)
                .map_err(|_| OLE1_ERROR_ADDRESS)?;
            let Some(expected_byte) = expected.get(index) else {
                return Ok(byte[0] == 0);
            };
            if !byte[0].eq_ignore_ascii_case(expected_byte) {
                return Ok(false);
            }
        }
        Ok(false)
    }

    pub(super) fn append_ole1_callback_arguments(
        &self,
        callback_arguments: &mut Vec<Win16FarCallbackArgument>,
        arguments: &[u32],
        specifications: &[Ole1MethodArgument],
        memory: &mut Memory,
    ) -> Result<(), u16> {
        for (argument, specification) in arguments.iter().zip(specifications) {
            if let Some(callback_argument) =
                self.ole1_callback_argument(*argument, *specification, arguments, memory)?
            {
                callback_arguments.push(callback_argument);
            }
        }
        Ok(())
    }

    fn ole1_callback_argument(
        &self,
        value: u32,
        specification: Ole1MethodArgument,
        method_arguments: &[u32],
        memory: &mut Memory,
    ) -> Result<Option<Win16FarCallbackArgument>, u16> {
        match specification {
            Ole1MethodArgument::Word => Ok(Some(Win16FarCallbackArgument::Word(
                u16::try_from(value).map_err(|_| OLE1_ERROR_ADDRESS)?,
            ))),
            Ole1MethodArgument::Dword => Ok(Some(Win16FarCallbackArgument::Dword(value))),
            Ole1MethodArgument::Input { bytes } => {
                self.checked_ole1_pointer(value, Access::Read, bytes, OLE1_ERROR_ADDRESS, memory)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Read,
                    bytes,
                }))
            }
            Ole1MethodArgument::OptionalInput { .. } if value == 0 => {
                // Keep the FAR parameter's four-byte stack slot without
                // translating selector zero as a real guest pointer.
                Ok(Some(Win16FarCallbackArgument::Dword(0)))
            }
            Ole1MethodArgument::OptionalInput { bytes } => {
                self.checked_ole1_pointer(value, Access::Read, bytes, OLE1_ERROR_ADDRESS, memory)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Read,
                    bytes,
                }))
            }
            Ole1MethodArgument::Output { bytes } => {
                self.checked_ole1_pointer(value, Access::Write, bytes, OLE1_ERROR_ADDRESS, memory)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Write,
                    bytes,
                }))
            }
            Ole1MethodArgument::InOut { bytes } => {
                self.checked_ole1_pointer(value, Access::Read, bytes, OLE1_ERROR_ADDRESS, memory)?;
                self.checked_ole1_pointer(value, Access::Write, bytes, OLE1_ERROR_ADDRESS, memory)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Write,
                    bytes,
                }))
            }
            Ole1MethodArgument::Object => {
                self.ole1_object_vtable(value, memory)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Read,
                    bytes: OLEOBJECT_BYTES as u32,
                }))
            }
            Ole1MethodArgument::InputString => {
                let string = self.ole1_read_string(value, memory)?;
                let bytes = u32::try_from(string.len() + 1).map_err(|_| OLE1_ERROR_ADDRESS)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Read,
                    bytes,
                }))
            }
            Ole1MethodArgument::ValidateOnlyString => {
                self.ole1_read_string(value, memory)?;
                Ok(None)
            }
            Ole1MethodArgument::OutputString { length_argument } => {
                let length_far = method_arguments
                    .get(length_argument)
                    .copied()
                    .ok_or(OLE1_ERROR_ADDRESS)?;
                let length_pointer = self.checked_ole1_pointer(
                    length_far,
                    Access::Read,
                    2,
                    OLE1_ERROR_ADDRESS,
                    memory,
                )?;
                let mut length_bytes = [0_u8; 2];
                self.selectors
                    .read(memory, length_pointer, &mut length_bytes)
                    .map_err(|_| OLE1_ERROR_ADDRESS)?;
                let capacity = u32::from(u16::from_le_bytes(length_bytes));
                self.checked_ole1_pointer(
                    value,
                    Access::Write,
                    capacity.max(1),
                    OLE1_ERROR_ADDRESS,
                    memory,
                )?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Write,
                    bytes: capacity.max(1),
                }))
            }
            Ole1MethodArgument::Palette => {
                let palette =
                    self.checked_ole1_pointer(value, Access::Read, 4, OLE1_ERROR_ADDRESS, memory)?;
                let mut header = [0_u8; 4];
                self.selectors
                    .read(memory, palette, &mut header)
                    .map_err(|_| OLE1_ERROR_ADDRESS)?;
                let entries = u32::from(u16::from_le_bytes([header[2], header[3]]));
                let bytes = 4_u32
                    .checked_add(entries.checked_mul(4).ok_or(OLE1_ERROR_ADDRESS)?)
                    .ok_or(OLE1_ERROR_ADDRESS)?;
                self.checked_ole1_pointer(value, Access::Read, bytes, OLE1_ERROR_ADDRESS, memory)?;
                Ok(Some(Win16FarCallbackArgument::GuestPointer {
                    far: value,
                    access: Access::Read,
                    bytes,
                }))
            }
        }
    }

    pub(super) fn checked_ole1_pointer(
        &self,
        far: u32,
        access: Access,
        bytes: u32,
        status: u16,
        memory: &mut Memory,
    ) -> Result<SegmentedPointer, u16> {
        if far == 0 {
            return Err(status);
        }
        let pointer = self.selectors.pointer_from_far(far).map_err(|_| status)?;
        self.selectors
            .translate(pointer, access, bytes as usize, memory)
            .map_err(|_| status)?;
        Ok(pointer)
    }

    pub(super) fn ole1_read_string(&self, far: u32, memory: &mut Memory) -> Result<Vec<u8>, u16> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        let mut output = Vec::new();
        for index in 0..=u16::MAX {
            let byte_pointer = self
                .selectors
                .add_bytes(pointer, u32::from(index))
                .map_err(|_| OLE1_ERROR_ADDRESS)?;
            self.selectors
                .translate(byte_pointer, Access::Read, 1, memory)
                .map_err(|_| OLE1_ERROR_ADDRESS)?;
            let mut byte = [0_u8; 1];
            self.selectors
                .read(memory, byte_pointer, &mut byte)
                .map_err(|_| OLE1_ERROR_ADDRESS)?;
            if byte[0] == 0 {
                return Ok(output);
            }
            output
                .try_reserve(1)
                .map_err(|_| super::OLE1_ERROR_MEMORY)?;
            output.push(byte[0]);
        }
        Err(OLE1_ERROR_ADDRESS)
    }
}
