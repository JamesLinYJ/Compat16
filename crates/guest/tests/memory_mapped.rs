use std::cell::{Cell, RefCell};
use std::rc::Rc;

use guest_core::memory::{Memory, MemoryMappedDevice, ROM_START};
use guest_core::{GuestMemory, MemoryError, PhysAddr};

struct TestDevice {
    bytes: RefCell<Vec<u8>>,
    read_validations: Cell<u32>,
    write_validations: Cell<u32>,
    reads: Cell<u32>,
    writes: Cell<u32>,
    reject_read: Cell<bool>,
    reject_write: Cell<bool>,
}

impl TestDevice {
    fn new(length: usize) -> Self {
        Self {
            bytes: RefCell::new(vec![0; length]),
            read_validations: Cell::new(0),
            write_validations: Cell::new(0),
            reads: Cell::new(0),
            writes: Cell::new(0),
            reject_read: Cell::new(false),
            reject_write: Cell::new(false),
        }
    }
}

impl MemoryMappedDevice for TestDevice {
    fn validate_read(&self, offset: u32, length: u32) -> Result<(), MemoryError> {
        self.read_validations.set(self.read_validations.get() + 1);
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::AddressOverflow)? as usize;
        if self.reject_read.get() || end > self.bytes.borrow().len() {
            return Err(MemoryError::InvalidMapping);
        }
        Ok(())
    }

    fn validate_write(&self, offset: u32, length: u32) -> Result<(), MemoryError> {
        self.write_validations.set(self.write_validations.get() + 1);
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::AddressOverflow)? as usize;
        if self.reject_write.get() || end > self.bytes.borrow().len() {
            return Err(MemoryError::InvalidMapping);
        }
        Ok(())
    }

    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        self.reads.set(self.reads.get() + 1);
        let start = offset as usize;
        let end = start
            .checked_add(output.len())
            .ok_or(MemoryError::AddressOverflow)?;
        output.copy_from_slice(
            self.bytes
                .borrow()
                .get(start..end)
                .ok_or(MemoryError::InvalidMapping)?,
        );
        Ok(())
    }

    fn write(&self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        self.writes.set(self.writes.get() + 1);
        let start = offset as usize;
        let end = start
            .checked_add(input.len())
            .ok_or(MemoryError::AddressOverflow)?;
        self.bytes
            .borrow_mut()
            .get_mut(start..end)
            .ok_or(MemoryError::InvalidMapping)?
            .copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn raw_physical_accesses_route_to_device_and_raw_slices_cannot_bypass_it() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    let device = Rc::new(TestDevice::new(0x1000));
    memory
        .map_device(PhysAddr(0x000a_0000), 0x1000, device.clone())
        .expect("map device aperture");

    memory
        .write_physical(PhysAddr(0x000a_0020), &[0x12, 0x34])
        .expect("route physical write to device");
    let mut observed = [0; 2];
    memory
        .read_physical(PhysAddr(0x000a_0020), &mut observed)
        .expect("route physical read to device");

    assert_eq!(observed, [0x12, 0x34]);
    assert_eq!(device.reads.get(), 1);
    assert_eq!(device.writes.get(), 1);
    assert_eq!(
        memory.map_physical(PhysAddr(0x000a_0020), 2),
        Err(MemoryError::InvalidMapping)
    );
    assert!(matches!(
        memory.map_physical_mut(PhysAddr(0x000a_0020), 2),
        Err(MemoryError::InvalidMapping)
    ));
}

#[test]
fn a20_bus_routes_aliases_to_the_same_physical_device_aperture() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    let device = Rc::new(TestDevice::new(0x1000));
    memory
        .map_device(PhysAddr(0x000a_0000), 0x1000, device.clone())
        .expect("map device aperture");
    memory
        .write_physical(PhysAddr(0x001a_0010), &[0xca])
        .expect("initialize distinct raw physical byte");
    memory.set_a20_enabled(false);

    {
        let mut bus = memory.bus();
        bus.write(PhysAddr(0x001a_0010), &[0x5d])
            .expect("A20 alias should reach device");
        let mut observed = [0];
        bus.read(PhysAddr(0x001a_0010), &mut observed)
            .expect("read A20 alias from device");
        assert_eq!(observed, [0x5d]);
    }

    assert_eq!(memory.read_u8(PhysAddr(0x001a_0010)).unwrap(), 0xca);
    assert_eq!(device.writes.get(), 1);
    assert_eq!(device.reads.get(), 1);
}

#[test]
fn a20_bus_preflights_all_decoded_device_chunks_before_latch_reads() {
    let mut memory = Memory::with_size(4 * 1024 * 1024).expect("allocate test memory");
    let first = Rc::new(TestDevice::new(2));
    let second = Rc::new(TestDevice::new(2));
    memory
        .map_device(PhysAddr(0x000a_0000), 2, first.clone())
        .expect("map first decoded aperture");
    memory
        .map_device(PhysAddr(0x0020_0000), 2, second.clone())
        .expect("map second decoded aperture");
    second.reject_read.set(true);
    memory.set_a20_enabled(false);

    let bus = memory.bus();
    let mut output = vec![0xaa; 0x60002];
    assert_eq!(
        bus.read(PhysAddr(0x001a_0000), &mut output),
        Err(MemoryError::InvalidMapping)
    );
    assert_eq!(first.read_validations.get(), 1);
    assert_eq!(second.read_validations.get(), 1);
    assert_eq!(first.reads.get(), 0);
    assert_eq!(second.reads.get(), 0);
    assert!(output.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn device_mappings_reject_empty_out_of_bounds_rom_and_overlapping_ranges() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    let device = Rc::new(TestDevice::new(0x1000));

    assert_eq!(
        memory.map_device(PhysAddr(0x2000), 0, device.clone()),
        Err(MemoryError::InvalidMapping)
    );
    assert!(matches!(
        memory.map_device(PhysAddr(memory.len() - 1), 2, device.clone()),
        Err(MemoryError::OutOfBounds { .. })
    ));
    assert_eq!(
        memory.map_device(PhysAddr(ROM_START - 1), 2, device.clone()),
        Err(MemoryError::InvalidMapping)
    );
    memory
        .map_device(PhysAddr(0x3000), 0x1000, device.clone())
        .expect("map first aperture");
    assert_eq!(
        memory.map_device(PhysAddr(0x3fff), 2, device),
        Err(MemoryError::InvalidMapping)
    );
}

#[test]
fn all_device_reads_are_validated_before_any_latch_read_occurs() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    let first = Rc::new(TestDevice::new(2));
    let second = Rc::new(TestDevice::new(2));
    memory
        .map_device(PhysAddr(0x2000), 2, first.clone())
        .expect("map first device");
    memory
        .map_device(PhysAddr(0x2004), 2, second.clone())
        .expect("map second device");
    second.reject_read.set(true);

    let mut output = [0xaa; 6];
    assert_eq!(
        memory.read_physical(PhysAddr(0x2000), &mut output),
        Err(MemoryError::InvalidMapping)
    );
    assert_eq!(first.read_validations.get(), 1);
    assert_eq!(second.read_validations.get(), 1);
    assert_eq!(first.reads.get(), 0);
    assert_eq!(second.reads.get(), 0);
    assert_eq!(output, [0xaa; 6]);
}

#[test]
fn whole_write_is_validated_before_ram_or_earlier_devices_change() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    let first = Rc::new(TestDevice::new(2));
    let second = Rc::new(TestDevice::new(2));
    memory
        .map_device(PhysAddr(0x2000), 2, first.clone())
        .expect("map first device");
    memory
        .map_device(PhysAddr(0x2004), 2, second.clone())
        .expect("map second device");
    memory
        .write_physical(PhysAddr(0x1fff), &[0x71])
        .expect("initialize RAM prefix");
    memory
        .write_physical(PhysAddr(0x2002), &[0x72, 0x73])
        .expect("initialize RAM between apertures");
    second.reject_write.set(true);

    assert_eq!(
        memory.write_physical(PhysAddr(0x1fff), &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]),
        Err(MemoryError::InvalidMapping)
    );
    assert_eq!(first.write_validations.get(), 1);
    assert_eq!(second.write_validations.get(), 1);
    assert_eq!(first.writes.get(), 0);
    assert_eq!(second.writes.get(), 0);

    assert_eq!(memory.read_u8(PhysAddr(0x1fff)).unwrap(), 0x71);
    let mut gap = [0; 2];
    memory.read_physical(PhysAddr(0x2002), &mut gap).unwrap();
    assert_eq!(gap, [0x72, 0x73]);
    assert_eq!(*first.bytes.borrow(), [0, 0]);
    assert_eq!(*second.bytes.borrow(), [0, 0]);
}
