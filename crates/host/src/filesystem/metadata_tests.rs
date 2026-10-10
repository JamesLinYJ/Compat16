use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, SYSTEMTIME};
use windows_sys::Win32::System::Time::{
    DYNAMIC_TIME_ZONE_INFORMATION, EnumDynamicTimeZoneInformation, SystemTimeToFileTime,
};

use super::{dos_file_time, filetime, pack_dos_time};

fn calendar(year: u16, month: u16, day: u16, hour: u16, minute: u16, second: u16) -> SYSTEMTIME {
    SYSTEMTIME {
        wYear: year,
        wMonth: month,
        wDay: day,
        wHour: hour,
        wMinute: minute,
        wSecond: second,
        ..Default::default()
    }
}

fn ticks(utc: SYSTEMTIME) -> u64 {
    let mut time = filetime(0);
    // SAFETY: Input and output are initialized, disjoint Windows ABI structures.
    assert_ne!(unsafe { SystemTimeToFileTime(&utc, &mut time) }, 0);
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn fixed_zone(bias: i32) -> DYNAMIC_TIME_ZONE_INFORMATION {
    DYNAMIC_TIME_ZONE_INFORMATION {
        Bias: bias,
        // Custom settings exercise the non-Ex fixed-rule branch. Empty
        // transition months additionally disable DST in this base fixture.
        DynamicDaylightTimeDisabled: true,
        ..Default::default()
    }
}

fn seasonal_zone() -> DYNAMIC_TIME_ZONE_INFORMATION {
    DYNAMIC_TIME_ZONE_INFORMATION {
        // UTC-5 in winter and UTC-4 in summer, with explicit recurring rules:
        // second Sunday in March / first Sunday in November, at 02:00 local.
        // The fixed-rule branch uses these supplied dates. Nonzero transition
        // months still enable seasonal DST, even with dynamic history disabled.
        // https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-dynamic_time_zone_information
        DaylightDate: calendar(0, 3, 2, 2, 0, 0),
        StandardDate: calendar(0, 11, 1, 2, 0, 0),
        DaylightBias: -60,
        ..fixed_zone(300)
    }
}

fn named_zone(name: &str) -> DYNAMIC_TIME_ZONE_INFORMATION {
    // Ex resolves installed timezone history by registry key. Enumerate that
    // key, never a localized display name or the runner's selected timezone.
    let key: Vec<u16> = name.encode_utf16().collect();
    let mut zone = DYNAMIC_TIME_ZONE_INFORMATION::default();
    for index in 0..=u32::MAX {
        // SAFETY: The output is an initialized, caller-owned Windows structure.
        let result = unsafe { EnumDynamicTimeZoneInformation(index, &mut zone) };
        assert_ne!(result, ERROR_NO_MORE_ITEMS, "{name} fixture is missing");
        assert_eq!(result, ERROR_SUCCESS, "timezone enumeration failed");
        let length = zone.TimeZoneKeyName.iter().position(|&unit| unit == 0).unwrap();
        if zone.TimeZoneKeyName[..length] == key {
            zone.DynamicDaylightTimeDisabled = false;
            return zone;
        }
    }
    panic!("timezone enumeration did not terminate");
}

#[test]
fn dos_timestamp_packing_preserves_boundaries_and_field_order() {
    assert_eq!(pack_dos_time(&calendar(1980, 1, 1, 0, 0, 0)), (0, 0x0021));
    assert_eq!(pack_dos_time(&calendar(2107, 12, 31, 23, 59, 59)), (0xbf7d, 0xff9f));
    assert_eq!(pack_dos_time(&calendar(2000, 2, 29, 13, 47, 58)), (0x6dfd, 0x285d));
}

#[test]
fn dos_timestamp_packing_truncates_seconds_and_ignores_milliseconds() {
    for second in 0..60 {
        for milliseconds in [0, 1, 999] {
            let mut local = calendar(2024, 6, 15, 12, 34, second);
            local.wMilliseconds = milliseconds;
            assert_eq!(pack_dos_time(&local), (0x6440 | (second / 2), 0x58cf));
        }
    }
}

#[test]
fn dos_timestamp_packing_preserves_zero_fallback_for_unrepresentable_dates() {
    for (year, month, day) in [
        (1979, 12, 31), (2108, 1, 1), (0, 1, 1), (u16::MAX, 1, 1),
        (2024, 0, 1), (2024, 13, 1), (2024, 1, 0), (2024, 1, 32),
    ] {
        assert_eq!(pack_dos_time(&calendar(year, month, day, 12, 34, 56)), (0, 0));
    }
}

#[test]
fn dos_timestamp_native_uses_the_timestamps_season() {
    let zone = named_zone("Eastern Standard Time");
    for (month, local_hour, date) in [(1, 7, 0x582f), (7, 8, 0x58ef)] {
        let mut utc = calendar(2024, month, 15, 12, 34, 59);
        utc.wMilliseconds = 999;
        assert_eq!(dos_file_time(ticks(utc), &zone).unwrap(), ((local_hour << 11) | 0x045d, date));
    }
}

#[test]
fn dos_timestamp_native_respects_disabled_daylight_saving_time() {
    let zone = DYNAMIC_TIME_ZONE_INFORMATION {
        // Retain a valid registry key, but honor the explicitly disabled DST
        // settings rather than restoring the registered daylight transitions.
        DynamicDaylightTimeDisabled: true,
        StandardDate: SYSTEMTIME::default(),
        DaylightDate: SYSTEMTIME::default(),
        ..named_zone("Eastern Standard Time")
    };
    for (month, date) in [(1, 0x582f), (7, 0x58ef)] {
        assert_eq!(
            dos_file_time(ticks(calendar(2024, month, 15, 12, 0, 0)), &zone).unwrap(),
            (0x3800, date),
        );
    }
}

#[test]
fn dos_timestamp_native_handles_daylight_transitions() {
    let zone = named_zone("Eastern Standard Time");
    for (utc, expected) in [
        // The spring transition skips from 01:59:59 to 03:00:00.
        (calendar(2024, 3, 10, 6, 59, 59), (0x0f7d, 0x586a)),
        (calendar(2024, 3, 10, 7, 0, 0), (0x1800, 0x586a)),
        // The autumn transition repeats 01:00:00 through 01:59:59.
        (calendar(2024, 11, 3, 5, 59, 59), (0x0f7d, 0x5963)),
        (calendar(2024, 11, 3, 6, 0, 0), (0x0800, 0x5963)),
    ] {
        assert_eq!(dos_file_time(ticks(utc), &zone).unwrap(), expected);
    }
}

#[test]
fn dos_timestamp_native_applies_offsets_before_dos_range_checks() {
    // Named zones exercise Ex with UTC-5 and UTC+5:30, including local/UTC
    // dates on opposite sides of both DOS year limits.
    let west = named_zone("SA Pacific Standard Time");
    let east = named_zone("India Standard Time");
    for (zone, utc, expected) in [
        (&west, calendar(2024, 1, 1, 2, 15, 59), (0xa9fd, 0x579f)),
        (&east, calendar(2024, 2, 29, 20, 45, 59), (0x11fd, 0x5861)),
        (&west, calendar(1980, 1, 1, 4, 59, 59), (0, 0)),
        (&west, calendar(1980, 1, 1, 5, 0, 0), (0, 0x0021)),
        (&east, calendar(1979, 12, 31, 18, 30, 0), (0, 0x0021)),
        (&east, calendar(2107, 12, 31, 18, 29, 59), (0xbf7d, 0xff9f)),
        (&east, calendar(2107, 12, 31, 18, 30, 0), (0, 0)),
        (&west, calendar(2108, 1, 1, 4, 59, 59), (0xbf7d, 0xff9f)),
    ] {
        assert_eq!(dos_file_time(ticks(utc), zone).unwrap(), expected);
    }
}

#[test]
fn dos_timestamp_native_preserves_conversion_failures_as_errors() {
    // FileTimeToSystemTime rejects values with the high bit set. Do not turn an
    // API failure into the successful zero pair used for dates outside DOS.
    let zone = named_zone("UTC");
    for invalid in [0x8000_0000_0000_0000, u64::MAX] {
        assert!(dos_file_time(invalid, &zone).is_err());
    }
}

#[test]
fn dos_timestamp_native_uses_named_zone_historical_rules() {
    let zone = named_zone("Pacific Standard Time");
    // Before the 2007 rule change, March 21 was still standard time (UTC-8).
    // Applying today's recurring rules to 2006 would incorrectly return 05:00.
    // https://learn.microsoft.com/en-us/dotnet/api/system.datetime.touniversaltime
    for (year, expected) in [(2006, (0x2000, 0x3475)), (2007, (0x2800, 0x3675))] {
        assert_eq!(dos_file_time(ticks(calendar(year, 3, 21, 12, 0, 0)), &zone).unwrap(), expected);
    }
}

#[test]
fn dos_timestamp_native_uses_supplied_fixed_rules_for_custom_settings() {
    let unnamed = seasonal_zone();
    let unnamed_dynamic = DYNAMIC_TIME_ZONE_INFORMATION {
        // A missing registry key still leaves usable fixed transition fields.
        DynamicDaylightTimeDisabled: false,
        ..unnamed
    };
    let named_fixed = DYNAMIC_TIME_ZONE_INFORMATION {
        // Even with a key, disabling dynamic history selects the supplied
        // recurring rules instead of the registry's historical 2006 rules.
        TimeZoneKeyName: named_zone("Eastern Standard Time").TimeZoneKeyName,
        ..unnamed
    };
    for zone in [unnamed, unnamed_dynamic, named_fixed] {
        for (utc, expected) in [
            (calendar(2024, 1, 15, 12, 0, 0), (0x3800, 0x582f)),
            (calendar(2024, 7, 15, 12, 0, 0), (0x4000, 0x58ef)),
            (calendar(2006, 3, 21, 12, 0, 0), (0x4000, 0x3475)),
        ] {
            assert_eq!(dos_file_time(ticks(utc), &zone).unwrap(), expected);
        }
    }
}

#[test]
fn dos_timestamp_native_does_not_hide_named_dynamic_zone_lookup_errors() {
    let mut zone = seasonal_zone();
    zone.DynamicDaylightTimeDisabled = false;
    let key: Vec<u16> = "Compat16 nonexistent timezone fixture".encode_utf16().collect();
    zone.TimeZoneKeyName[..key.len()].copy_from_slice(&key);
    // The supplied fixed fields would succeed, but a named dynamic zone must
    // resolve its history. A failed lookup must remain a host error.
    assert!(dos_file_time(ticks(calendar(2024, 7, 15, 12, 0, 0)), &zone).is_err());
}

fn converted_ticks(time: u16, date: u16, zone: &DYNAMIC_TIME_ZONE_INFORMATION) -> u64 {
    let native = super::dos_to_file_time(time, date, zone).unwrap();
    let ticks = (u64::from(native.dwHighDateTime) << 32) | u64::from(native.dwLowDateTime);
    assert_eq!(dos_file_time(ticks, zone).unwrap(), (time, date));
    ticks
}

#[test]
fn dos_timestamp_set_decodes_every_valid_two_second_clock_value() {
    let zone = fixed_zone(0);
    for hour in 0..24 {
        for minute in 0..60 {
            for second in (0..60).step_by(2) {
                let local = calendar(2000, 2, 29, hour, minute, second);
                let (time, date) = pack_dos_time(&local);
                assert_eq!(converted_ticks(time, date, &zone), ticks(local));
            }
        }
    }
}

#[test]
fn dos_timestamp_set_accepts_local_year_limits_even_when_utc_crosses_them() {
    for (zone, local, utc) in [
        (fixed_zone(0), calendar(1980, 1, 1, 0, 0, 0), calendar(1980, 1, 1, 0, 0, 0)),
        (fixed_zone(0), calendar(2107, 12, 31, 23, 59, 58), calendar(2107, 12, 31, 23, 59, 58)),
        (fixed_zone(-330), calendar(1980, 1, 1, 0, 0, 0), calendar(1979, 12, 31, 18, 30, 0)),
        (fixed_zone(300), calendar(2107, 12, 31, 23, 59, 58), calendar(2108, 1, 1, 4, 59, 58)),
    ] {
        let (time, date) = pack_dos_time(&local);
        assert_eq!(converted_ticks(time, date, &zone), ticks(utc));
    }
}

#[test]
fn dos_timestamp_set_rejects_all_invalid_packed_clock_fields() {
    let zone = fixed_zone(0);
    for time in 0..=u16::MAX {
        if (time >> 11) > 23 || ((time >> 5) & 63) > 59 || (time & 31) > 29 {
            assert_eq!(super::dos_to_file_time(time, 0x21, &zone).err().expect("invalid time").code,
                dos_kernel::DosErrorCode::InvalidData, "time={time:04x}");
        }
    }
}

#[test]
fn dos_timestamp_set_rejects_invalid_months_days_and_non_leap_dates() {
    let zone = fixed_zone(0);
    let invalid = |date| {
        assert_eq!(super::dos_to_file_time(0, date, &zone).err().expect("invalid date").code,
            dos_kernel::DosErrorCode::InvalidData, "date={date:04x}");
    };
    for year in 1980..=2107 {
        let year_bits = (year - 1980) << 9;
        for month in [0, 13, 14, 15] { invalid(year_bits | (month << 5) | 1); }
        for month in 1..=12 {
            invalid(year_bits | (month << 5));
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let days = match month { 2 if leap => 29, 2 => 28, 4 | 6 | 9 | 11 => 30, _ => 31 };
            for day in (days + 1)..=31 { invalid(year_bits | (month << 5) | day); }
        }
    }
    // 2000 is a Gregorian leap century; 2100 was rejected above.
    assert_eq!(converted_ticks(0, 0x285d, &zone), ticks(calendar(2000, 2, 29, 0, 0, 0)));
    invalid(0);
}

#[test]
fn dos_timestamp_set_uses_historical_named_zone_rules_and_fixed_custom_rules() {
    let named = named_zone("Eastern Standard Time");
    let custom = seasonal_zone();
    let unnamed_dynamic = DYNAMIC_TIME_ZONE_INFORMATION {
        DynamicDaylightTimeDisabled: false,
        ..custom
    };
    let named_fixed = DYNAMIC_TIME_ZONE_INFORMATION {
        TimeZoneKeyName: named.TimeZoneKeyName,
        ..custom
    };
    for (year, named_hour) in [(2006, 13), (2007, 12)] {
        let (time, date) = pack_dos_time(&calendar(year, 3, 21, 8, 0, 0));
        assert_eq!(converted_ticks(time, date, &named), ticks(calendar(year, 3, 21, named_hour, 0, 0)));
        for zone in [&custom, &unnamed_dynamic, &named_fixed] {
            assert_eq!(converted_ticks(time, date, zone), ticks(calendar(year, 3, 21, 12, 0, 0)));
        }
    }
}

#[test]
fn dos_timestamp_set_respects_disabled_dst_with_a_named_zone_key() {
    let zone = DYNAMIC_TIME_ZONE_INFORMATION {
        DynamicDaylightTimeDisabled: true,
        StandardDate: SYSTEMTIME::default(),
        DaylightDate: SYSTEMTIME::default(),
        ..named_zone("Eastern Standard Time")
    };
    for month in [1, 7] {
        let (time, date) = pack_dos_time(&calendar(2024, month, 15, 8, 0, 0));
        assert_eq!(converted_ticks(time, date, &zone), ticks(calendar(2024, month, 15, 13, 0, 0)));
    }
}

#[test]
fn dos_timestamp_set_rejects_dst_gaps_in_fixed_and_dynamic_rules() {
    for zone in [seasonal_zone(), named_zone("Eastern Standard Time")] {
        for minute in 0..60 {
            let (time, date) = pack_dos_time(&calendar(2024, 3, 10, 2, minute, 0));
            assert_eq!(super::dos_to_file_time(time, date, &zone).err().expect("nonexistent local time").code,
                dos_kernel::DosErrorCode::InvalidData);
        }
        for (local, utc) in [
            (calendar(2024, 3, 10, 1, 59, 58), calendar(2024, 3, 10, 6, 59, 58)),
            (calendar(2024, 3, 10, 3, 0, 0), calendar(2024, 3, 10, 7, 0, 0)),
        ] {
            let (time, date) = pack_dos_time(&local);
            assert_eq!(converted_ticks(time, date, &zone), ticks(utc));
        }
    }
}

#[test]
fn dos_timestamp_set_accepts_documented_daylight_occurrence_of_repeated_hour() {
    for zone in [seasonal_zone(), named_zone("Eastern Standard Time")] {
        for minute in [0, 30, 59] {
            let (time, date) = pack_dos_time(&calendar(2024, 11, 3, 1, minute, 58));
            let daylight = ticks(calendar(2024, 11, 3, 5, minute, 58));
            let standard = ticks(calendar(2024, 11, 3, 6, minute, 58));
            assert_eq!(dos_file_time(daylight, &zone).unwrap(), (time, date));
            assert_eq!(dos_file_time(standard, &zone).unwrap(), (time, date));
            // DOS discarded which repeated-hour occurrence produced the value.
            assert_eq!(converted_ticks(time, date, &zone), daylight);
        }
    }
}

#[test]
fn dos_timestamp_set_does_not_fall_back_when_named_history_lookup_fails() {
    let mut zone = seasonal_zone();
    zone.DynamicDaylightTimeDisabled = false;
    let key: Vec<u16> = "Compat16 nonexistent timezone fixture".encode_utf16().collect();
    zone.TimeZoneKeyName[..key.len()].copy_from_slice(&key);
    let (time, date) = pack_dos_time(&calendar(2024, 7, 15, 12, 0, 0));
    assert!(super::dos_to_file_time(time, date, &zone).is_err());
    assert!(super::dos_to_file_time(time, date, &seasonal_zone()).is_ok());
}
