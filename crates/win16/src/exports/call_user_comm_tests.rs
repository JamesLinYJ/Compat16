//! USER.200–215 and USER.245: SDK widths and owned guest bytes.

use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorRef, SelectorTable, Win16ApiRequest, Win16CallFrame, Win16Error,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind, Win16UserCommRequest,
    Win16UserRequest, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

struct Fixture {
    memory: Memory,
    selectors: SelectorTable,
    stack: SelectorRef,
    next_base: u32,
}

impl Fixture {
    fn new() -> Self {
        let memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 64, AccessRights::read_write(), &memory)
            .unwrap();
        Self {
            memory,
            selectors,
            stack,
            next_base: 0x2000,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> u32 {
        let base = self.next_base;
        self.next_base += 0x100;
        self.memory.write(PhysAddr(base), bytes).unwrap();
        let selector = self
            .selectors
            .alloc_block(
                PhysAddr(base),
                bytes.len() as u32,
                AccessRights::read_only(),
                &self.memory,
            )
            .unwrap();
        SegmentedPointer::new(selector, 0).far_value()
    }

    fn call(&mut self, ordinal: u16, slots: &[Slot]) -> Result<Win16ApiRequest, Win16Error> {
        let mut frame = vec![0x34, 0x12, 0x78, 0x56];
        for slot in slots.iter().rev() {
            match slot {
                Slot::Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
                Slot::Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
                Slot::Byte(value) => {
                    frame.extend_from_slice(&(u16::from(*value) | 0xab00).to_le_bytes())
                }
            }
        }
        self.memory.write(PhysAddr(0x1000), &frame).unwrap();
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        decode_export_call(
            descriptor,
            Win16CallFrame::new(
                SegmentedPointer::new(self.stack, 0),
                ReturnAddressWidth::Far,
            ),
            &self.selectors,
            &self.memory,
        )
        .map(|decoded| decoded.request)
    }
}

enum Slot {
    Word(u16),
    Dword(u32),
    Byte(u8),
}

fn comm(request: Win16UserCommRequest) -> Win16ApiRequest {
    Win16ApiRequest::User(Win16UserRequest::Comm(request))
}

#[test]
fn comm_exports_keep_sdk_names_widths_and_pascal_cleanup() {
    for (ordinal, name, ret, pop, kinds) in [
        (
            200,
            "OpenComm",
            Win16ReturnKind::Word,
            8,
            vec![ArgumentKind::Dword, ArgumentKind::Word, ArgumentKind::Word],
        ),
        (
            201,
            "SetCommState",
            Win16ReturnKind::Word,
            4,
            vec![ArgumentKind::Dword],
        ),
        (
            202,
            "GetCommState",
            Win16ReturnKind::Word,
            6,
            vec![ArgumentKind::Word, ArgumentKind::Dword],
        ),
        (
            203,
            "GetCommError",
            Win16ReturnKind::Word,
            6,
            vec![ArgumentKind::Word, ArgumentKind::Dword],
        ),
        (
            204,
            "ReadComm",
            Win16ReturnKind::Word,
            8,
            vec![ArgumentKind::Word, ArgumentKind::Dword, ArgumentKind::Word],
        ),
        (
            205,
            "WriteComm",
            Win16ReturnKind::Word,
            8,
            vec![ArgumentKind::Word, ArgumentKind::Dword, ArgumentKind::Word],
        ),
        (
            206,
            "TransmitCommChar",
            Win16ReturnKind::Word,
            4,
            vec![ArgumentKind::Word, ArgumentKind::Byte],
        ),
        (
            207,
            "CloseComm",
            Win16ReturnKind::Word,
            2,
            vec![ArgumentKind::Word],
        ),
        (
            208,
            "SetCommEventMask",
            Win16ReturnKind::FarPointer,
            4,
            vec![ArgumentKind::Word, ArgumentKind::Word],
        ),
        (
            209,
            "GetCommEventMask",
            Win16ReturnKind::Word,
            4,
            vec![ArgumentKind::Word, ArgumentKind::Word],
        ),
        (
            210,
            "SetCommBreak",
            Win16ReturnKind::Word,
            2,
            vec![ArgumentKind::Word],
        ),
        (
            211,
            "ClearCommBreak",
            Win16ReturnKind::Word,
            2,
            vec![ArgumentKind::Word],
        ),
        (
            212,
            "UngetCommChar",
            Win16ReturnKind::Word,
            4,
            vec![ArgumentKind::Word, ArgumentKind::Byte],
        ),
        (
            213,
            "BuildCommDCB",
            Win16ReturnKind::Word,
            8,
            vec![ArgumentKind::Dword, ArgumentKind::Dword],
        ),
        (
            214,
            "EscapeCommFunction",
            Win16ReturnKind::Dword,
            4,
            vec![ArgumentKind::Word, ArgumentKind::Word],
        ),
        (
            215,
            "FlushComm",
            Win16ReturnKind::Word,
            4,
            vec![ArgumentKind::Word, ArgumentKind::Word],
        ),
        (
            245,
            "EnableCommNotification",
            Win16ReturnKind::Word,
            8,
            vec![
                ArgumentKind::Word,
                ArgumentKind::Word,
                ArgumentKind::Word,
                ArgumentKind::Word,
            ],
        ),
    ] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let named = lookup_export(b"user.exe", ExportLookupTarget::Name(name.as_bytes())).unwrap();
        assert_eq!(descriptor.id, named.id);
        assert_eq!(
            descriptor.calling_convention,
            ExportCallingConvention::Pascal
        );
        assert_eq!(descriptor.return_kind, ret);
        assert_eq!(
            descriptor
                .parameters
                .iter()
                .map(|parameter| parameter.kind)
                .collect::<Vec<_>>(),
            kinds
        );
        let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
            panic!("communications exports use a fixed Pascal frame");
        };
        assert_eq!(
            (cleanup.callee_pop_bytes, cleanup.caller_pop_bytes),
            (pop, 0)
        );
    }
    let open = lookup_export(b"USER", ExportLookupTarget::Ordinal(200)).unwrap();
    assert_eq!(
        open.parameters[0].parameter_type,
        Win16ParameterType::FarString
    );
    assert_eq!(open.id as u32, 1285);
    let state = lookup_export(b"USER", ExportLookupTarget::Ordinal(201)).unwrap();
    assert_eq!(
        state.parameters[0].parameter_type,
        Win16ParameterType::FarBuffer
    );
    let mask = lookup_export(b"USER", ExportLookupTarget::Ordinal(208)).unwrap();
    assert_eq!(mask.return_kind, Win16ReturnKind::FarPointer);
    let escape = lookup_export(b"USER", ExportLookupTarget::Ordinal(214)).unwrap();
    assert_eq!(escape.return_kind, Win16ReturnKind::Dword);
    assert_eq!(escape.id as u32, 1299);
    let notify = lookup_export(b"USER", ExportLookupTarget::Ordinal(245)).unwrap();
    assert_eq!(
        notify.parameters[0].parameter_type,
        Win16ParameterType::SignedScalar
    );
    assert_eq!(notify.id as u32, 1301);
}

#[test]
fn open_comm_owns_the_ansi_device_bytes() {
    let mut fixture = Fixture::new();
    let device = fixture.bytes(b"COM1:\0");
    assert_eq!(
        fixture
            .call(
                200,
                &[Slot::Dword(device), Slot::Word(0x40), Slot::Word(0x20)]
            )
            .unwrap(),
        comm(Win16UserCommRequest::Open {
            device: b"COM1:".to_vec(),
            in_queue: 0x40,
            out_queue: 0x20,
        })
    );
    assert!(
        fixture
            .call(
                200,
                &[Slot::Dword(0xffff_ffff), Slot::Word(1), Slot::Word(1)]
            )
            .is_err()
    );
}

#[test]
fn set_comm_state_copies_the_packed_dcb_and_write_skips_a_nonpositive_count() {
    let mut fixture = Fixture::new();
    let dcb = fixture.bytes(&[0x11; 25]);
    assert_eq!(
        fixture.call(201, &[Slot::Dword(dcb)]).unwrap(),
        comm(Win16UserCommRequest::SetState {
            dcb: vec![0x11; 25]
        })
    );
    let short = fixture.bytes(&[0x11; 24]);
    assert!(fixture.call(201, &[Slot::Dword(short)]).is_err());
    for count in [0_u16, 0xffff] {
        assert_eq!(
            fixture
                .call(
                    205,
                    &[Slot::Word(7), Slot::Dword(0xffff_ffff), Slot::Word(count)]
                )
                .unwrap(),
            comm(Win16UserCommRequest::Write {
                id: 7,
                bytes: Vec::new()
            })
        );
    }
}

#[test]
fn transmit_and_escape_keep_the_low_byte_and_signed_function() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture
            .call(206, &[Slot::Word(0), Slot::Byte(0x41)])
            .unwrap(),
        comm(Win16UserCommRequest::Transmit { id: 0, byte: 0x41 })
    );
    assert_eq!(
        fixture
            .call(214, &[Slot::Word(0x80), Slot::Word(0x8000)])
            .unwrap(),
        comm(Win16UserCommRequest::Escape {
            id: 0x80,
            function: i16::MIN
        })
    );
}
