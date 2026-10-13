use super::*;
use guest_core::io::{PortIo, PortWidth};
use std::fs;

fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("compat16-cmos-{name}-{}", std::process::id()))
}

#[test]
fn index_keeps_the_nmi_mask_out_of_the_register_number() {
    let cmos = CmosRtc::new();
    cmos.write_index(0x8a);
    assert_eq!(cmos.read_index(), 0x8a);
    assert_eq!(cmos.read_data() & 0x7f, 0x20);
    cmos.write_index(0x0b);
    assert_eq!(cmos.read_data() & 0x02, 0x02);
}

#[test]
fn time_bytes_follow_bcd_binary_and_hour_mode() {
    let cmos = CmosRtc::new();
    cmos.observe_host_time(23 * 3600 + 59);
    cmos.write_index(0x00);
    assert_eq!(cmos.read_data(), 0x59);
    cmos.write_index(0x04);
    assert_eq!(cmos.read_data(), 0x23);

    cmos.write_index(0x0b);
    cmos.write_data(0x00);
    cmos.write_index(0x04);
    assert_eq!(cmos.read_data(), 0x91);

    cmos.write_index(0x0b);
    cmos.write_data(0x06);
    cmos.write_index(0x00);
    assert_eq!(cmos.read_data(), 59);
    cmos.write_index(0x04);
    assert_eq!(cmos.read_data(), 23);
}

#[test]
fn register_c_reports_and_then_clears_periodic_and_alarm_flags() {
    let cmos = CmosRtc::new();
    cmos.observe_host_time(0);
    cmos.write_index(0x0a);
    cmos.write_data(0x2f);
    cmos.write_index(0x0b);
    cmos.write_data(0x42);
    let period = (1_193_182 + 1) / 2;
    assert!(cmos.advance_pit_ticks(period));
    let status = cmos.acknowledge_interrupt();
    assert_eq!(status & 0xc0, 0xc0);
    assert_eq!(cmos.acknowledge_interrupt(), 0);

    let alarm = CmosRtc::new();
    alarm.observe_host_time(0);
    assert!(alarm.enable_alarm(0x00, 0x00, 0x01));
    assert!(alarm.advance_pit_ticks(1_193_182));
    assert_eq!(alarm.acknowledge_interrupt() & 0xa0, 0xa0);
    assert!(!alarm.enable_alarm(0x00, 0x00, 0x02));
    alarm.disable_alarm();
    assert!(alarm.enable_alarm(0x00, 0x00, 0x02));
}

#[test]
fn update_in_progress_is_the_end_of_the_second() {
    let cmos = CmosRtc::new();
    let window = (1_193_182 * 244) / 1_000_000;
    assert!(!cmos.update_in_progress());
    cmos.advance_pit_ticks(1_193_182 - window);
    assert!(cmos.update_in_progress());
    assert!(cmos.read_bios_time().is_none());
}

#[test]
fn bad_checksum_reloads_the_standard_layout() {
    let path = scratch("checksum");
    let _ = fs::remove_file(&path);
    let cmos = CmosRtc::new();
    cmos.attach_file(&path);
    cmos.write_index(0x14);
    cmos.write_data(0x01);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0x14] ^= 0xff;
    fs::write(&path, &bytes).unwrap();

    let restored = CmosRtc::new();
    restored.attach_file(&path);
    assert_eq!(restored.ram(0x0e) & 0x80, 0x80);
    assert_eq!(restored.equipment_word(), 0x0020);
    assert_eq!(restored.base_memory_kib(), 640);
    assert_eq!(restored.floppy_type(), 0);
    assert_eq!(restored.fixed_disk_type(), 0);
    assert_eq!(restored.boot_order(), 0);
    let _ = fs::remove_file(&path);
}

#[test]
fn ports_70h_and_71h_address_the_shared_chip() {
    let cmos = CmosRtc::new();
    let mut ports = crate::ports::MachinePorts::with_vga_and_cmos(crate::vga::VgaDevice::new(), cmos.clone());
    ports.write(0x70, PortWidth::Byte, 0x92).unwrap();
    assert_eq!(ports.read(0x70, PortWidth::Byte).unwrap(), 0x92);
    ports.write(0x71, PortWidth::Byte, 0xf0).unwrap();
    assert_eq!(cmos.fixed_disk_type(), 0xf0);
    assert!(ports.write(0x70, PortWidth::Word, 0x1234).is_err());
}
