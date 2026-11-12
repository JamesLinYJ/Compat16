//! Native palette behavior the Win16 guest contract forwards to GDI.

use super::super::guest_text::GuestTextCodec;
use super::super::win16_gdi::Win16Dcs;
use super::super::win16_gdi_objects::Win16Objects;
use runtime::{
    Win16GdiDeviceOperation as Operation, Win16GdiDeviceResult as Value, Win16HostGdiObject,
    Win16PaletteTransferKind,
};
use windows_sys::Win32::Graphics::Gdi::PC_RESERVED;

fn run(dcs: &Win16Dcs, objects: &mut Win16Objects, operation: Operation) -> Value {
    match super::execute(dcs, objects, operation) {
        Ok(value) => value,
        Err(_) => panic!("palette adapter rejected a scalar request"),
    }
}

fn entries(value: Value) -> (i32, Vec<[u8; 4]>) {
    match value {
        Value::PaletteEntries { count, entries } => (count, entries),
        _ => panic!("palette adapter returned a different result family"),
    }
}

fn object(value: Value) -> Option<Win16HostGdiObject> {
    match value {
        Value::Object(object) => object,
        _ => panic!("palette adapter returned a different result family"),
    }
}

#[test]
fn native_palette_preserves_entries_resize_animation_and_nearest_index() {
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let mut objects = Win16Objects::new();
    let dc = dcs.create_compatible(None).unwrap().unwrap();
    let reserved = PC_RESERVED as u8;

    assert!(
        object(run(
            &dcs,
            &mut objects,
            Operation::CreatePalette {
                version: 0x0200,
                entries: vec![[1, 2, 3, 0]],
            },
        ))
        .is_none()
    );
    assert!(
        object(run(
            &dcs,
            &mut objects,
            Operation::CreatePalette {
                version: 0x0300,
                entries: Vec::new(),
            },
        ))
        .is_none()
    );

    let palette = object(run(
        &dcs,
        &mut objects,
        Operation::CreatePalette {
            version: 0x0300,
            entries: vec![[10, 20, 30, 0], [1, 2, 3, reserved]],
        },
    ))
    .expect("CreatePalette");

    let (count, got) = entries(run(
        &dcs,
        &mut objects,
        Operation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette,
            start: 0,
            count: 0,
            entries: None,
        },
    ));
    assert_eq!(count, 2);
    assert!(got.is_empty());

    let (count, got) = entries(run(
        &dcs,
        &mut objects,
        Operation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette,
            start: 0,
            count: 2,
            entries: None,
        },
    ));
    assert_eq!(count, 2);
    assert_eq!(got, [[10, 20, 30, 0], [1, 2, 3, reserved]]);

    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::PaletteEntries {
                kind: Win16PaletteTransferKind::Set,
                palette,
                start: 2,
                count: 1,
                entries: Some(vec![[9, 9, 9, 0]]),
            },
        ),
        Value::Count(0)
    ));
    let (_, unchanged) = entries(run(
        &dcs,
        &mut objects,
        Operation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette,
            start: 0,
            count: 2,
            entries: None,
        },
    ));
    assert_eq!(unchanged, [[10, 20, 30, 0], [1, 2, 3, reserved]]);

    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::ResizePalette { palette, count: 4 },
        ),
        Value::Bool(true)
    ));
    let (count, grown) = entries(run(
        &dcs,
        &mut objects,
        Operation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette,
            start: 0,
            count: 4,
            entries: None,
        },
    ));
    assert_eq!(count, 4);
    assert_eq!(grown[0], [10, 20, 30, 0]);
    assert_eq!(grown[1], [1, 2, 3, reserved]);
    assert_eq!(grown[2], [0, 0, 0, 0]);
    assert_eq!(grown[3], [0, 0, 0, 0]);
    let (count, _) = entries(run(
        &dcs,
        &mut objects,
        Operation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette,
            start: 0,
            count: 0,
            entries: None,
        },
    ));
    assert_eq!(count, 4);

    let previous = object(run(
        &dcs,
        &mut objects,
        Operation::SelectPalette {
            dc,
            palette,
            force_background: false,
        },
    ))
    .expect("SelectPalette");
    let _ = run(&dcs, &mut objects, Operation::RealizePalette { dc });

    let animated = matches!(
        run(
            &dcs,
            &mut objects,
            Operation::PaletteEntries {
                kind: Win16PaletteTransferKind::Animate,
                palette,
                start: 0,
                count: 2,
                entries: Some(vec![[255, 0, 0, 0], [0, 0, 255, reserved]]),
            },
        ),
        Value::Count(count) if count != 0
    );
    let (_, after) = entries(run(
        &dcs,
        &mut objects,
        Operation::PaletteEntries {
            kind: Win16PaletteTransferKind::Get,
            palette,
            start: 0,
            count: 2,
            entries: None,
        },
    ));
    assert_eq!(
        after[0],
        [10, 20, 30, 0],
        "entries without PC_RESERVED stay put"
    );
    if animated {
        assert_eq!(after[1], [0, 0, 255, reserved]);
    } else {
        assert_eq!(after[1], [1, 2, 3, reserved]);
    }

    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::GetNearestPaletteIndex {
                palette,
                color: 0x001e_140a,
            },
        ),
        Value::Count(0)
    ));
    let reserved_color = if animated { 0x00ff_0000 } else { 0x0003_0201 };
    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::GetNearestPaletteIndex {
                palette,
                color: reserved_color,
            },
        ),
        Value::Count(1)
    ));
    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::GetNearestPaletteIndex {
                palette: Win16HostGdiObject(u64::MAX),
                color: 0,
            },
        ),
        Value::Count(-1)
    ));

    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::UnrealizeObject { object: palette },
        ),
        Value::Bool(true)
    ));

    let (system_count, system_entries) = entries(run(
        &dcs,
        &mut objects,
        Operation::GetSystemPaletteEntries {
            dc,
            start: 0,
            count: 0,
        },
    ));
    assert!(system_count >= 0);
    assert!(system_entries.is_empty());

    let _ = run(
        &dcs,
        &mut objects,
        Operation::SelectPalette {
            dc,
            palette: previous,
            force_background: false,
        },
    );
    drop(objects);
    assert!(dcs.cleanup(dc));
}

#[test]
fn native_nearest_color_and_update_colors_match_the_device() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let dc = dcs.create_compatible(None).unwrap().unwrap();
    let lease = dcs.lease_dc(dc).unwrap().unwrap();
    let native = lease.native();
    // SAFETY: The test owns this compatible DC for these two synchronous queries.
    let nearest =
        unsafe { windows_sys::Win32::Graphics::Gdi::GetNearestColor(native, 0x0011_2233) };
    let updated = unsafe { windows_sys::Win32::Graphics::Gdi::UpdateColors(native) } != 0;
    drop(lease);

    let mut objects = Win16Objects::new();
    let images = super::super::win16_images::Win16Images::new(codec);
    match super::super::win16_drawing::execute(
        &dcs,
        &mut objects,
        &images,
        runtime::Win16DrawingOperation::GetNearestColor {
            dc,
            color: 0x0011_2233,
        },
    ) {
        Ok(runtime::Win16DrawingResult::Color(color)) => assert_eq!(color, nearest),
        Ok(_) => panic!("GetNearestColor returned a different result family"),
        Err(_) => panic!("GetNearestColor adapter failed"),
    }
    assert!(matches!(
        run(&dcs, &mut objects, Operation::UpdateColors { dc }),
        Value::Bool(value) if value == updated
    ));
    assert!(matches!(
        run(
            &dcs,
            &mut objects,
            Operation::RealizePalette {
                dc: runtime::Win16HostDc(u64::MAX),
            },
        ),
        Value::Count(0)
    ));
    assert!(dcs.cleanup(dc));
}
