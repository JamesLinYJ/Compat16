use super::*;

#[test]
fn reserves_physical_zero_and_adjacent_regions() {
    let mut map = PhysicalArenaMap::new(0x11_0000).unwrap();
    let conventional = map
        .reserve(
            RegionKind::ConventionalMemory,
            PhysAddr(0),
            0xa_0000,
            0x10,
        )
        .unwrap();
    let video = map
        .reserve(
            RegionKind::VideoMemory,
            PhysAddr(0xa_0000),
            0x5_0000,
            0x10,
        )
        .unwrap();
    let bios = map
        .reserve(RegionKind::BiosRom, PhysAddr(0xf_0000), 0x1_0000, 0x10)
        .unwrap();

    assert_eq!(map.get(conventional).unwrap().base(), PhysAddr(0));
    assert_eq!(map.get(video).unwrap().base(), PhysAddr(0xa_0000));
    let bios_region = map.get(bios).unwrap();
    assert_eq!(bios_region.end_exclusive(), PhysAddr(0x10_0000));
    assert_eq!(map.len(), 3);
}

#[test]
fn rejects_overlapping_ranges_without_adding_them() {
    let mut map = PhysicalArenaMap::new(0x20_0000).unwrap();
    let original = map
        .reserve(RegionKind::Xms, PhysAddr(0x11_0000), 0x20_000, 0x400)
        .unwrap();

    assert!(matches!(
        map.reserve(RegionKind::Dpmi, PhysAddr(0x12_0000), 0x10_000, 0x1000),
        Err(ArenaError::Overlap {
            existing,
            existing_kind: RegionKind::Xms,
            ..
        }) if existing == original
    ));
    assert_eq!(map.len(), 1);
}

#[test]
fn checks_bounds_and_address_overflow() {
    let mut map = PhysicalArenaMap::new(0x20_0000).unwrap();
    assert_eq!(
        map.reserve(RegionKind::Win16, PhysAddr(0x1f_f000), 0x2000, 0x1000),
        Err(ArenaError::OutOfBounds {
            base: PhysAddr(0x1f_f000),
            length: 0x2000,
            memory_size: 0x20_0000,
        })
    );
    assert_eq!(
        map.reserve(RegionKind::Dpmi, PhysAddr(u32::MAX - 0xfff), 0x2000, 0x1000),
        Err(ArenaError::AddressOverflow {
            base: PhysAddr(u32::MAX - 0xfff),
            length: 0x2000,
        })
    );
    assert!(map.is_empty());
}

#[test]
fn checks_range_alignment_and_nonempty_size() {
    let mut map = PhysicalArenaMap::new(0x20_0000).unwrap();
    assert_eq!(
        map.reserve(RegionKind::Xms, PhysAddr(0x1000), 0x1000, 0),
        Err(ArenaError::InvalidAlignment { alignment: 0 })
    );
    assert_eq!(
        map.reserve(RegionKind::Xms, PhysAddr(0x1001), 0x1000, 0x1000),
        Err(ArenaError::MisalignedRange {
            base: PhysAddr(0x1001),
            length: 0x1000,
            alignment: 0x1000,
        })
    );
    assert_eq!(
        map.reserve(RegionKind::Xms, PhysAddr(0x1000), 0, 0x1000),
        Err(ArenaError::InvalidLength)
    );
}

#[test]
fn identifiers_are_stable_and_rejected_by_other_maps() {
    let mut first = PhysicalArenaMap::new(0x20_0000).unwrap();
    let mut second = PhysicalArenaMap::new(0x20_0000).unwrap();
    let id = first
        .reserve(RegionKind::Win16, PhysAddr(0x1000), 0x1000, 0x1000)
        .unwrap();
    first
        .reserve(RegionKind::Dpmi, PhysAddr(0x3000), 0x1000, 0x1000)
        .unwrap();
    second
        .reserve(RegionKind::Win16, PhysAddr(0x1000), 0x1000, 0x1000)
        .unwrap();

    assert_eq!(first.get(id).unwrap().kind(), RegionKind::Win16);
    assert_eq!(second.get(id), Err(ArenaError::ForeignMapId));
}
