use super::*;
use crate::{AccessRights, ExportLookupTarget, Win16ReturnKind, lookup_export};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn arguments(mode: u16) -> Vec<Win16Argument> {
    vec![
        Win16Argument::Word(0),
        Win16Argument::Word(0x1234),
        Win16Argument::Dword(0xffff_0000),
        Win16Argument::Dword(0),
        Win16Argument::Dword(0),
        Win16Argument::Dword(0xffff_0000),
        Win16Argument::Dword(0),
        Win16Argument::Word(mode),
    ]
}

#[test]
fn ext_device_mode_query_ignores_unused_input_and_output_addresses() {
    let memory = Memory::with_size(0x10_0000).unwrap();
    let selectors = SelectorTable::new().unwrap();
    let request = decode_ext_device_mode(&arguments(0), &selectors, &memory).unwrap();
    assert!(matches!(
        request,
        Win16PrinterRequest::ExtDeviceMode {
            driver_instance: 0x1234,
            output: 0xffff_0000,
            input: 0xffff_0000,
            device: None,
            port: None,
            profile: None,
            mode: 0,
            ..
        }
    ));
}

#[test]
fn ext_device_mode_modify_retains_address_for_runtime_checked_copy() {
    let memory = Memory::with_size(0x10_0000).unwrap();
    let selectors = SelectorTable::new().unwrap();
    assert!(matches!(
        decode_ext_device_mode(&arguments(8), &selectors, &memory).unwrap(),
        Win16PrinterRequest::ExtDeviceMode {
            input: 0xffff_0000,
            mode: 8,
            ..
        }
    ));
    let mut arguments = arguments(8);
    arguments[5] = Win16Argument::Dword(0);
    assert!(decode_ext_device_mode(&arguments, &selectors, &memory).is_ok());
}

#[test]
fn ext_device_mode_snapshots_names_before_callbacks() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors
        .alloc_block(PhysAddr(0x1000), 512, AccessRights::read_write(), &memory)
        .unwrap();
    let mut bytes = [0_u8; 68];
    bytes[36..38].copy_from_slice(&68_u16.to_le_bytes());
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    memory
        .write(PhysAddr(0x1100), b"\x82\xa0Printer\0")
        .unwrap();
    let base = u32::from(selector.raw().0) << 16;
    let mut args = arguments(10);
    args[3] = Win16Argument::Dword(base + 256);
    args[5] = Win16Argument::Dword(base);
    let request = decode_ext_device_mode(&args, &selectors, &memory).unwrap();
    memory.write(PhysAddr(0x1100), &[0xff; 10]).unwrap();
    selectors.free_block(selector).unwrap();
    let Win16PrinterRequest::ExtDeviceMode { device, input, .. } = request else {
        panic!()
    };
    assert_eq!(device.unwrap(), b"\x82\xa0Printer");
    assert_eq!(input, base);
}

#[test]
fn ext_device_mode_descriptor_uses_original_word_result_and_fixed_frame() {
    let descriptor = lookup_export(b"WINSPOOL", ExportLookupTarget::Ordinal(90)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.parameters.len(), 8);
    assert_eq!(
        descriptor.stack_cleanup,
        crate::Win16ExportStackCleanup::Fixed(crate::StackCleanup {
            callee_pop_bytes: 26,
            caller_pop_bytes: 0,
        })
    );
}
