use super::DosKernel;
use guest_core::Registers;

fn request(operation: u8) -> Registers {
    Registers {
        eax: 0x1234_122e,
        ebx: 0x4567_8901,
        ecx: 0x2345_6789,
        edx: 0x3456_ab00 | u32::from(operation),
        edi: 0x5678_9abc,
        esi: 0x6789_abcd,
        ebp: 0x789a_bcde,
        esp: 0x89ab_cdef,
        eip: 0x9abc_def0,
        cs: 0x1111,
        ds: 0x2222,
        es: 0x3333,
        ss: 0x4444,
        fs: 0x5555,
        gs: 0x6666,
        eflags: 0xad57,
    }
}

#[test]
fn dos_message_defaults_are_unregistered_and_preserve_nonoutputs() {
    let mut dos = DosKernel::new(0x1000);
    for operation in [0, 2, 4, 6, 8] {
        let mut regs = request(operation);
        let mut expected = regs.clone();
        expected.es = 0;
        expected.set_di(0);
        expected.set_carry(false);
        assert!(dos.message_address_service(&mut regs));
        assert_eq!(regs, expected);
    }
}

#[test]
fn dos_message_slots_exchange_opaque_guest_coordinates_independently() {
    let mut dos = DosKernel::new(0x1000);
    for slot in 0..5u16 {
        let mut set = request((slot * 2 + 1) as u8);
        set.es = 0xf000 + slot;
        set.set_di(0xff00 + slot);
        let mut expected = set.clone();
        expected.set_carry(false);
        assert!(dos.message_address_service(&mut set));
        assert_eq!(set, expected);
    }
    for slot in 0..5u16 {
        let mut get = request((slot * 2) as u8);
        let mut expected = get.clone();
        expected.es = 0xf000 + slot;
        expected.set_di(0xff00 + slot);
        expected.set_carry(false);
        assert!(dos.message_address_service(&mut get));
        assert_eq!(get, expected);
    }
}

#[test]
fn dos_message_zero_set_unregisters_a_provider() {
    let mut dos = DosKernel::new(0x1000);
    let mut set = request(1);
    assert!(dos.message_address_service(&mut set));
    set.es = 0;
    set.set_di(0);
    assert!(dos.message_address_service(&mut set));
    let mut get = request(0);
    assert!(dos.message_address_service(&mut get));
    assert_eq!((get.es, get.di()), (0, 0));
}

#[test]
fn dos_message_exec_contexts_share_addresses_but_new_runtimes_do_not() {
    let mut parent = DosKernel::new(0x1000);
    let mut child = DosKernel::child_allocation_owner(&parent, 0x2000);
    let mut set = request(5);
    set.es = 0x2345;
    set.set_di(0x6789);
    assert!(child.message_address_service(&mut set));
    let mut get = request(4);
    assert!(parent.message_address_service(&mut get));
    assert_eq!((get.es, get.di()), (0x2345, 0x6789));
    let mut other = DosKernel::new(0x3000);
    let mut get = request(4);
    assert!(other.message_address_service(&mut get));
    assert_eq!((get.es, get.di()), (0, 0));
}

#[test]
fn dos_message_unimplemented_requests_do_not_change_registers_or_slots() {
    let mut dos = DosKernel::new(0x1000);
    for operation in [10, 11, 0xff] {
        let mut regs = request(operation);
        let before = regs.clone();
        assert!(!dos.message_address_service(&mut regs));
        assert_eq!(regs, before);
    }
    let mut regs = request(0);
    regs.set_ax(0x122d);
    let before = regs.clone();
    assert!(!dos.message_address_service(&mut regs));
    assert_eq!(regs, before);
}
