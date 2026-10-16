//! Explicit native STM_SETICON ownership diagnostic; no STM_SETIMAGE inference.
//! Creates one hidden, empty-title STATIC and never shows it or supplies input.

use std::ptr;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HWND};
use windows_sys::Win32::Graphics::Gdi::DeleteObject;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CopyIcon, CreateWindowExW, DestroyIcon, DestroyWindow, GetIconInfo, HICON, ICONINFO,
    IDI_APPLICATION, IsWindow, IsWindowVisible, LoadIconW, SendMessageW,
    STM_GETICON, STM_SETICON, WS_POPUP,
};

const SS_ICON: u32 = 3;

#[derive(Clone, Copy, Debug)]
struct IconValidity {
    valid: bool,
    is_icon: bool,
    error: u32,
    bitmaps_deleted: bool,
}

fn inspect_icon(icon: HICON) -> IconValidity {
    let mut info: ICONINFO = unsafe { std::mem::zeroed() };
    unsafe { SetLastError(0) };
    let valid = !icon.is_null() && unsafe { GetIconInfo(icon, &mut info) } != 0;
    let error = unsafe { GetLastError() };
    let mut bitmaps_deleted = true;
    if valid {
        // GetIconInfo allocates these bitmap copies even for a validity probe.
        // Delete each returned object once, never the source icon's bitmaps.
        if !info.hbmMask.is_null() {
            bitmaps_deleted &= unsafe { DeleteObject(info.hbmMask) } != 0;
        }
        if !info.hbmColor.is_null() && info.hbmColor != info.hbmMask {
            bitmaps_deleted &= unsafe { DeleteObject(info.hbmColor) } != 0;
        }
    }
    IconValidity { valid, is_icon: valid && info.fIcon != 0, error, bitmaps_deleted }
}

#[derive(Debug, Default)]
struct CleanupReport {
    control_gone: bool,
    withheld: bool,
    icon_was_valid: [bool; 2],
    icon_destroyed: [bool; 2],
    bitmap_cleanup_ok: bool,
}

struct Resources {
    control: HWND,
    icons: [HICON; 2],
}

impl Resources {
    fn new() -> Self { Self { control: ptr::null_mut(), icons: [ptr::null_mut(); 2] } }

    fn destroy_control(&mut self) -> (bool, bool, u32) {
        if self.control.is_null() { return (true, true, 0); }
        unsafe { SetLastError(0) };
        let reported = unsafe { DestroyWindow(self.control) } != 0;
        let error = unsafe { GetLastError() };
        let gone = unsafe { IsWindow(self.control) } == 0;
        if gone { self.control = ptr::null_mut(); }
        (reported, gone, error)
    }

    fn cleanup(&mut self) -> CleanupReport {
        let (_, gone, _) = self.destroy_control();
        let mut report = CleanupReport {
            control_gone: gone, bitmap_cleanup_ok: true, ..CleanupReport::default()
        };
        if !gone {
            // Do not free a possibly still attached image after failed teardown.
            report.withheld = true;
            return report;
        }
        for index in 0..self.icons.len() {
            let icon = std::mem::replace(&mut self.icons[index], ptr::null_mut());
            if icon.is_null() { continue; }
            let validity = inspect_icon(icon);
            report.icon_was_valid[index] = validity.valid;
            report.bitmap_cleanup_ok &= validity.bitmaps_deleted;
            // Native destruction is the fact under investigation. Never blindly
            // DestroyIcon a second time if the control already invalidated it.
            if validity.valid {
                report.icon_destroyed[index] = unsafe { DestroyIcon(icon) } != 0;
            }
        }
        report
    }
}

impl Drop for Resources {
    fn drop(&mut self) { let _ = self.cleanup(); }
}

#[test]
#[ignore = "hidden native ownership diagnostic; dedicated CI step supplies bounded invocation"]
fn hidden_seticon_preserves_caller_owned_icons() {
    let mut resources = Resources::new();
    unsafe { SetLastError(0) };
    let shared = unsafe { LoadIconW(ptr::null_mut(), IDI_APPLICATION) };
    let load_error = unsafe { GetLastError() };
    let mut copy_errors = [0; 2];
    let mut copies_distinct = !shared.is_null();
    if !shared.is_null() {
        for (index, error) in copy_errors.iter_mut().enumerate() {
            unsafe { SetLastError(0) };
            let copied = unsafe { CopyIcon(shared) };
            *error = unsafe { GetLastError() };
            if copied.is_null() || copied == shared || resources.icons.contains(&copied) {
                // Do not arm a second destructor for a shared/duplicate result.
                copies_distinct = false;
                break;
            }
            resources.icons[index] = copied;
        }
    }
    let mut create_error = 0;
    if copies_distinct {
        unsafe { SetLastError(0) };
        resources.control = unsafe { CreateWindowExW(
            0, windows_sys::core::w!("STATIC"), windows_sys::core::w!(""),
            WS_POPUP | SS_ICON, 0, 0, 16, 16, ptr::null_mut(), ptr::null_mut(),
            GetModuleHandleW(ptr::null()), ptr::null(),
        ) };
        create_error = unsafe { GetLastError() };
    }
    let created = !resources.control.is_null();
    let hidden = created && unsafe { IsWindowVisible(resources.control) } == 0;
    let originals = resources.icons;
    let mut initial = None;
    let mut after_replacement = None;
    let mut before_set = [None; 3];
    let mut completed_sets = 0;
    let mut previous = [0usize; 3];
    let mut readback = [0usize; 3];
    if created && copies_distinct {
        initial = Some(originals.map(inspect_icon));
        for (index, icon) in [originals[0], originals[1], originals[0]].into_iter().enumerate() {
            let validity = inspect_icon(icon);
            before_set[index] = Some(validity);
            if !validity.valid || !validity.is_icon || !validity.bitmaps_deleted { break; }
            // Native Win32 message numbers and host HICONs only. This measures
            // STM_SETICON itself, without a runtime adapter or sidecar owner.
            previous[index] = unsafe { SendMessageW(resources.control, STM_SETICON, icon as usize, 0) } as usize;
            readback[index] = unsafe { SendMessageW(resources.control, STM_GETICON, 0, 0) } as usize;
            completed_sets += 1;
            if index == 1 { after_replacement = Some(originals.map(inspect_icon)); }
        }
    }
    let destruction = resources.destroy_control();
    // This isolated, one-thread fixture allocates no further icons after the
    // initial copies. These scoped validity checks are not a general proof of
    // an arbitrary raw HICON's incarnation. Never own unknown readback handles.
    let after_destruction = if copies_distinct && destruction.1 {
        Some(originals.map(inspect_icon))
    } else { None };
    let cleanup = resources.cleanup();
    drop(resources);
    eprintln!("STM_SETICON ownership probe (not STM_SETIMAGE): copies_distinct={copies_distinct}, load_error={load_error}, copy_errors={copy_errors:?}, created={created}, hidden={hidden}, create_error={create_error}");
    eprintln!("owned copies={originals:?}, completed_sets={completed_sets}, previous={previous:?}, readback={readback:?}, destroy={destruction:?}, cleanup={cleanup:?}");
    eprintln!("validity immediately before each SET: {before_set:?}");
    for (phase, snapshots) in [("initial", initial), ("after replacement", after_replacement),
        ("after control destruction", after_destruction)] {
        if let Some(snapshots) = snapshots {
            for (index, sample) in snapshots.iter().enumerate() {
                eprintln!("{phase} icon{index}: valid={}, is_icon={}, error={}, bitmaps_deleted={}",
                    sample.valid, sample.is_icon, sample.error, sample.bitmaps_deleted);
            }
        }
    }
    assert!(copies_distinct, "UNSUPPORTED/FAILED: could not obtain two distinct caller-owned CopyIcon results");
    assert!(created, "UNSUPPORTED/FAILED: hidden STATIC creation failed");
    assert!(hidden, "FAILED: ownership probe unexpectedly created a visible control");
    assert_eq!(completed_sets, 3, "UNSUPPORTED/FAILED: an owned icon became invalid before its next SET");
    assert_eq!(previous, [0, originals[0] as usize, originals[1] as usize],
        "UNSUPPORTED/FAILED: STM_SETICON previous-handle contract differs");
    assert_eq!(readback, [originals[0] as usize, originals[1] as usize, originals[0] as usize],
        "UNSUPPORTED/FAILED: STM_GETICON did not return the installed caller handle");
    assert!(destruction.0 && destruction.1, "FAILED: hidden control teardown did not complete");
    for samples in [initial, after_replacement, after_destruction] {
        assert!(samples.is_some_and(|samples| samples.iter().all(|sample|
            sample.valid && sample.is_icon && sample.bitmaps_deleted)),
            "UNSUPPORTED/FAILED: caller-owned icon did not survive or bitmap cleanup failed");
    }
    assert!(cleanup.control_gone && !cleanup.withheld && cleanup.bitmap_cleanup_ok);
    assert_eq!(cleanup.icon_was_valid, [true, true]);
    assert_eq!(cleanup.icon_destroyed, [true, true], "FAILED: explicit caller icon cleanup failed");
}
