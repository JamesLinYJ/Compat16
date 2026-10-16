use super::*;
use crate::AccessRights;
use crate::exports::{Win16Parameter, Win16ParameterType};
use guest_core::{MemoryError, PhysAddr};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryAccess {
    Validate(u32, usize),
    Read(u32, usize),
}

struct RecordingMemory {
    bytes: Vec<u8>,
    accesses: RefCell<Vec<MemoryAccess>>,
    denied: Option<u32>,
}

impl RecordingMemory {
    fn new(size: usize) -> Self {
        Self { bytes: vec![0; size], accesses: RefCell::new(Vec::new()), denied: None }
    }
}

impl GuestMemory for RecordingMemory {
    fn len(&self) -> u32 { self.bytes.len() as u32 }

    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.accesses.borrow_mut().push(MemoryAccess::Validate(address.0, length));
        let end = address.0.checked_add(u32::try_from(length).unwrap())
            .ok_or(MemoryError::AddressOverflow)?;
        if end > self.len() || self.denied.is_some_and(|byte| address.0 <= byte && byte < end) {
            return Err(MemoryError::OutOfBounds { address: address.0, length });
        }
        Ok(())
    }

    fn read(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        self.accesses.borrow_mut().push(MemoryAccess::Read(address.0, output.len()));
        let start = address.0 as usize;
        let input = self.bytes.get(start..start + output.len())
            .ok_or(MemoryError::OutOfBounds { address: address.0, length: output.len() })?;
        output.copy_from_slice(input);
        Ok(())
    }

    fn write(&mut self, _: PhysAddr, _: &[u8]) -> Result<(), MemoryError> {
        panic!("argument decoding must not write memory")
    }
}

const PARAMETERS: [Win16Parameter; 3] = [
    Win16Parameter { name: "byte", kind: ArgumentKind::Byte, parameter_type: Win16ParameterType::Scalar },
    Win16Parameter { name: "word", kind: ArgumentKind::Word, parameter_type: Win16ParameterType::Scalar },
    Win16Parameter { name: "dword", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::Scalar },
];

fn compare_decoders(
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &RecordingMemory,
    convention: Win16CallingConvention,
    parameters: &[Win16Parameter],
) -> Result<Vec<Win16Argument>, Win16Error> {
    let signature: Vec<_> = parameters.iter().map(|parameter| parameter.kind).collect();
    memory.accesses.borrow_mut().clear();
    let from_slice = frame.decode_arguments(selectors, memory, convention, &signature);
    let slice_accesses = memory.accesses.take();
    let from_parameters = frame.decode_arguments_iter(
        selectors, memory, convention, parameters.iter().map(|parameter| parameter.kind),
    );
    assert_eq!(from_slice, from_parameters);
    assert_eq!(slice_accesses, *memory.accesses.borrow());
    from_parameters
}

#[test]
fn descriptor_iterator_preserves_mixed_arguments_and_physical_read_order() {
    for width in [ReturnAddressWidth::Near, ReturnAddressWidth::Far] {
        for convention in [Win16CallingConvention::Pascal, Win16CallingConvention::Cdecl] {
            let mut memory = RecordingMemory::new(0x10000);
            let mut selectors = SelectorTable::new().unwrap();
            let selector = selectors.alloc_block(PhysAddr(0), 0x10000, AccessRights::read_only(), &memory).unwrap();
            // End exactly at 64 KiB; Pascal reads the last declared argument first.
            let start = 0x10000 - width.bytes() - 8;
            let argument_start = (start + width.bytes()) as usize;
            let (bytes, sizes) = match convention {
                Win16CallingConvention::Pascal => ([0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xef, 0xff], [4, 2, 2]),
                Win16CallingConvention::Cdecl => ([0xef, 0xff, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12], [2, 2, 4]),
            };
            memory.bytes[argument_start..].copy_from_slice(&bytes);
            let frame = Win16CallFrame::new(SegmentedPointer::new(selector, start as u16), width);
            assert_eq!(compare_decoders(frame, &selectors, &memory, convention, &PARAMETERS).unwrap(),
                [Win16Argument::Byte(0xef), Win16Argument::Word(0x9abc), Win16Argument::Dword(0x12345678)]);
            let mut expected = vec![MemoryAccess::Validate(start, width.bytes() as usize)];
            let mut address = argument_start as u32;
            for size in sizes {
                expected.push(MemoryAccess::Validate(address, size));
                expected.push(MemoryAccess::Read(address, size));
                address += size as u32;
            }
            assert_eq!(*memory.accesses.borrow(), expected);
            assert_eq!(frame.cleanup(convention, &[ArgumentKind::Byte, ArgumentKind::Word, ArgumentKind::Dword]).unwrap(),
                match convention {
                    Win16CallingConvention::Pascal => StackCleanup { callee_pop_bytes: 8, caller_pop_bytes: 0 },
                    Win16CallingConvention::Cdecl => StackCleanup { callee_pop_bytes: 0, caller_pop_bytes: 8 },
                });
            let wrapped = Win16CallFrame::new(SegmentedPointer::new(selector, start as u16 + 1), width);
            assert_eq!(compare_decoders(wrapped, &selectors, &memory, convention, &PARAMETERS),
                Err(Win16Error::StackOffsetWrap { offset: start as u16 + 1, length: width.bytes() + 8 }));
            assert!(memory.accesses.borrow().is_empty());
        }
    }
}

#[test]
fn descriptor_iterator_validates_empty_frames_and_return_address_first() {
    for width in [ReturnAddressWidth::Near, ReturnAddressWidth::Far] {
        for convention in [Win16CallingConvention::Pascal, Win16CallingConvention::Cdecl] {
            let mut memory = RecordingMemory::new(16);
            let mut selectors = SelectorTable::new().unwrap();
            let selector = selectors.alloc_block(PhysAddr(0), 16, AccessRights::read_only(), &memory).unwrap();
            let frame = Win16CallFrame::new(SegmentedPointer::new(selector, 0), width);
            assert_eq!(compare_decoders(frame, &selectors, &memory, convention, &[]).unwrap(), []);
            assert_eq!(*memory.accesses.borrow(), [MemoryAccess::Validate(0, width.bytes() as usize)]);
            memory.denied = Some(width.bytes() - 1);
            for parameters in [&PARAMETERS[..], &[][..]] {
                assert_eq!(compare_decoders(frame, &selectors, &memory, convention, parameters),
                    Err(Win16Error::Memory(MemoryError::OutOfBounds { address: 0, length: width.bytes() as usize })));
                assert_eq!(*memory.accesses.borrow(), [MemoryAccess::Validate(0, width.bytes() as usize)]);
            }
        }
    }
}

#[test]
fn descriptor_iterator_rejects_truncated_byte_slots_and_return_addresses() {
    for width in [ReturnAddressWidth::Near, ReturnAddressWidth::Far] {
        for convention in [Win16CallingConvention::Pascal, Win16CallingConvention::Cdecl] {
            for segment_bytes in [width.bytes() - 1, width.bytes() + 1] {
                let memory = RecordingMemory::new(16);
                let mut selectors = SelectorTable::new().unwrap();
                let selector = selectors.alloc_block(PhysAddr(0), segment_bytes, AccessRights::read_only(), &memory).unwrap();
                let frame = Win16CallFrame::new(SegmentedPointer::new(selector, 0), width);
                let (offset, length, expected_accesses) = if segment_bytes < width.bytes() {
                    (0, width.bytes() as usize, vec![])
                } else {
                    (width.bytes(), 2, vec![MemoryAccess::Validate(0, width.bytes() as usize)])
                };
                assert_eq!(compare_decoders(frame, &selectors, &memory, convention, &PARAMETERS[..1]),
                    Err(Win16Error::LimitViolation { offset, length, limit: segment_bytes - 1 }));
                assert_eq!(*memory.accesses.borrow(), expected_accesses);
            }
        }
    }
}
