//! Noninteractive native WMF records, callback nesting and exact object cleanup.

use super::super::super::{
    guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images,
    win16_metafile::record::play,
};
use super::*;
use runtime::{Win16HostWindowOperationId, Win16WindowReply, Win16WindowResult};
use std::sync::atomic::AtomicU64;
use windows_sys::Win32::Graphics::Gdi::{
    BLACKNESS, CreateBitmap, GetBkColor, GetObjectW, GetPixel, HBITMAP, HGDIOBJ, PatBlt,
    SelectObject,
};

struct Fixture {
    windows: Win16Windows,
    objects: Win16Objects,
    dcs: Win16Dcs,
    dc: Win16HostDc,
    bitmap: Win16HostGdiObject,
    previous: usize,
}
impl Fixture {
    fn new() -> Self {
        let codec = GuestTextCodec::new(1252).unwrap();
        let dcs = Win16Dcs::with_text_codec(codec);
        let windows = Win16Windows::new(
            dcs.clone(),
            Win16Images::new(codec),
            Arc::new(AtomicU64::new(1)),
            codec,
        );
        let dc = dcs.create_compatible(None).unwrap().unwrap();
        let mut objects = Win16Objects::new();
        // SAFETY: `CreateBitmap` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let bitmap: HBITMAP = unsafe { CreateBitmap(16, 16, 1, 32, std::ptr::null()) };
        assert!(!bitmap.is_null());
        let token = objects.adopt_owned(bitmap.cast()).unwrap().unwrap();
        let lease = dcs.lease_dc(dc).unwrap().unwrap();
        // SAFETY: SelectObject selects a GDI object this process created into a live DC.
        let previous = unsafe { SelectObject(lease.native(), bitmap.cast()) };
        assert!(!previous.is_null());
        assert_ne!(
            // SAFETY: PatBlt uses a live device context owned by this process.
            unsafe { PatBlt(lease.native(), 0, 0, 16, 16, BLACKNESS) },
            0
        );
        super::super::super::win16_gdi::flush_thread_batch();
        drop(lease);
        Self {
            windows,
            objects,
            dcs,
            dc,
            bitmap: token,
            previous: previous as usize,
        }
    }
    fn draw(
        &mut self,
        callback: Option<Win16HostCallback>,
        record: Vec<u8>,
        table: Vec<Option<Win16HostGdiObject>>,
    ) -> Vec<Option<Win16HostGdiObject>> {
        let Win16HostMetafileResult::Record {
            success, objects, ..
        } = play(&self.dcs, &mut self.objects, self.dc, record, table).unwrap()
        else {
            panic!("record result")
        };
        assert!(success);
        if let Some(callback) = callback {
            self.windows
                .commit_metafile_table(callback, &objects, &self.objects, false)
                .unwrap();
        }
        objects
    }
    fn table(&mut self, callback: Win16HostCallback) -> Vec<Option<Win16HostGdiObject>> {
        let Win16HostMetafileResult::Table(table) = self
            .windows
            .metafile_callback_table(callback, &mut self.objects)
            .unwrap()
        else {
            panic!("table result")
        };
        table
    }
    fn enumerate(
        &mut self,
        bits: Vec<u8>,
        mut callback: impl FnMut(&mut Self, Win16HostCallback, Vec<u8>) -> bool,
    ) -> (bool, Vec<Win16HostGdiObject>) {
        let mut step = self
            .windows
            .begin(
                Win16WindowOperation::EnumMetafile { dc: self.dc, bits },
                &mut self.objects,
                None,
            )
            .unwrap();
        loop {
            step = match step {
                Win16WindowStep::Started { step, .. } => *step,
                Win16WindowStep::SourceRetired { proof, result } => {
                    self.windows.source_retirement_consumed(&proof).unwrap();
                    *result
                }
                Win16WindowStep::MetafileCallback {
                    callback: id,
                    record,
                    object_count,
                    operation_id,
                    source,
                    ..
                } => {
                    assert_ne!(operation_id, Win16HostWindowOperationId(0));
                    assert_eq!(source, Win16NativeCallbackSource::Metafile { dc: self.dc });
                    assert_eq!(self.table(id).len(), usize::from(object_count));
                    let keep = callback(self, id, record);
                    let table = self.table(id);
                    self.windows
                        .commit_metafile_table(id, &table, &self.objects, true)
                        .unwrap();
                    self.windows
                        .resume(Some(reply(id, keep)), &mut self.objects)
                        .unwrap()
                }
                Win16WindowStep::Complete(Win16WindowResult::EnumMetafile { success, retired }) => {
                    return (success, retired);
                }
                other => panic!("unexpected WMF step: {other:?}"),
            };
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.windows.abort();
        if let Some(dc) = self.dcs.lease_dc(self.dc).unwrap() {
            // SAFETY: SelectObject selects a GDI object this process created into a live DC.
            unsafe {
                SelectObject(dc.native(), self.previous as HGDIOBJ);
            }
        }
        assert!(self.dcs.delete(self.dc));
        assert!(self.objects.delete(self.bitmap));
    }
}
fn reply(callback: Win16HostCallback, value: bool) -> Win16WindowReply {
    Win16WindowReply {
        callback,
        result: runtime::Win16HostMessageResult {
            dialog_result: None,
            value: u32::from(value),
            output: runtime::Win16HostMessageOutput::None,
        },
    }
}
fn record(function: u16, parameters: &[u16]) -> Vec<u8> {
    let mut bytes = ((parameters.len() + 3) as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&function.to_le_bytes());
    for p in parameters {
        bytes.extend_from_slice(&p.to_le_bytes());
    }
    bytes
}
fn stream(records: &[Vec<u8>], objects: u16) -> Vec<u8> {
    let mut bytes = vec![0; 18];
    bytes[0] = 1;
    bytes[2] = 9;
    bytes[4..6].copy_from_slice(&0x300u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&objects.to_le_bytes());
    let maximum = records
        .iter()
        .map(|r| r.len() / 2)
        .max()
        .unwrap_or(3)
        .max(3) as u32;
    bytes[12..16].copy_from_slice(&maximum.to_le_bytes());
    for r in records {
        bytes.extend_from_slice(r);
    }
    bytes.extend(record(0, &[]));
    let length = (bytes.len() / 2) as u32;
    bytes[6..10].copy_from_slice(&length.to_le_bytes());
    bytes
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_standalone_record_creates_selects_draws_and_deletes_objects() {
    let mut f = Fixture::new();
    let mut table = f.draw(None, record(0x02fa, &[0, 1, 0, 0xff, 0]), vec![None]);
    let token = table[0].unwrap();
    let native = f.objects.metafile_object(token).unwrap().unwrap();
    table = f.draw(None, record(0x012d, &[0]), table);
    table = f.draw(None, record(0x041f, &[0xff, 0, 2, 3]), table);
    let dc = f.dcs.lease_dc(f.dc).unwrap().unwrap();
    // SAFETY: GetPixel reads one pixel on a live DC.
    assert_eq!(unsafe { GetPixel(dc.native(), 3, 2) }, 0xff);
    drop(dc);
    table = f.draw(None, record(0x012d, &[0x8007]), table);
    table = f.draw(None, record(0x01f0, &[0]), table);
    assert_eq!(table, vec![None]);
    assert!(f.objects.metafile_object(token).unwrap().is_none());
    let mut data = [0u64; 16];
    assert_eq!(
        // SAFETY: GetObjectW writes into a caller-owned buffer of the byte count passed with it.
        unsafe {
            GetObjectW(
                native as _,
                std::mem::size_of_val(&data) as i32,
                data.as_mut_ptr().cast(),
            )
        },
        0
    );
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_enumeration_plays_every_record_and_retires_automatic_cleanup() {
    let mut f = Fixture::new();
    let records = vec![
        record(0x02fa, &[0, 1, 0, 0xff, 0]),
        record(0x012d, &[0]),
        record(0x0214, &[0, 0]),
        record(0x0213, &[4, 4]),
        record(0x041f, &[0xff, 0, 2, 3]),
        record(0x0201, &[0x3322, 0x11]),
    ];
    let mut observed = Vec::new();
    let mut created = None;
    let (success, retired) = f.enumerate(stream(&records, 1), |f, id, bytes| {
        observed.push(bytes.clone());
        let table = f.table(id);
        let table = f.draw(Some(id), bytes, table);
        if created.is_none() {
            created = table[0];
        }
        true
    });
    assert!(success);
    assert_eq!(observed, records, "EOF is not a callback record");
    let token = created.unwrap();
    assert!(retired.contains(&token));
    assert!(f.objects.metafile_object(token).unwrap().is_none());
    let dc = f.dcs.lease_dc(f.dc).unwrap().unwrap();
    // SAFETY: GetPixel reads one pixel on a live DC.
    assert_eq!(unsafe { GetPixel(dc.native(), 3, 2) }, 0xff);
    // EnumMetaFile restores selected objects and clipping, but preserves this
    // ordinary DC attribute. A blanket SaveDC/RestoreDC would break this.
    // SAFETY: `GetBkColor` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    assert_eq!(unsafe { GetBkColor(dc.native()) }, 0x113322);
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_early_stop_cleans_created_table_objects() {
    let mut f = Fixture::new();
    let records = [record(0x02fa, &[0, 1, 0, 0xff, 0]), record(0x012d, &[0])];
    let mut called = 0;
    let mut created = None;
    let (success, retired) = f.enumerate(stream(&records, 1), |f, id, bytes| {
        called += 1;
        let table = f.table(id);
        created = f.draw(Some(id), bytes, table)[0];
        false
    });
    assert!(!success);
    assert_eq!(called, 1);
    assert_eq!(retired, vec![created.unwrap()]);
    assert!(
        f.objects
            .metafile_object(created.unwrap())
            .unwrap()
            .is_none()
    );
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_nested_enumeration_keeps_exact_tables_and_callbacks() {
    let mut f = Fixture::new();
    let create = record(0x02fa, &[0, 1, 0, 0xff, 0]);
    let mut outer = None;
    let mut inner = None;
    let (success, retired) = f.enumerate(stream(&[create.clone()], 1), |f, id, bytes| {
        let table = f.table(id);
        outer = f.draw(Some(id), bytes, table)[0];
        let (ok, retired) = f.enumerate(stream(&[create.clone()], 1), |f, nested, bytes| {
            assert_ne!(nested, id);
            assert_eq!(f.table(nested), vec![None]);
            let table = f.table(nested);
            inner = f.draw(Some(nested), bytes, table)[0];
            true
        });
        assert!(ok);
        assert_eq!(retired, vec![inner.unwrap()]);
        assert_ne!(outer, inner);
        assert_eq!(f.table(id), vec![outer]);
        true
    });
    assert!(success);
    assert_eq!(retired, vec![outer.unwrap()]);
    assert!(f.objects.metafile_object(inner.unwrap()).unwrap().is_none());
    assert!(f.objects.metafile_object(outer.unwrap()).unwrap().is_none());
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_abort_returns_created_objects_to_native_cleanup_before_guest_reply() {
    let mut f = Fixture::new();
    let bits = stream(&[record(0x02fa, &[0, 1, 0, 0xff, 0])], 1);
    let step = f
        .windows
        .begin(
            Win16WindowOperation::EnumMetafile { dc: f.dc, bits },
            &mut f.objects,
            None,
        )
        .unwrap();
    let Win16WindowStep::Started { step, .. } = step else {
        panic!("started")
    };
    let Win16WindowStep::MetafileCallback {
        callback, record, ..
    } = *step
    else {
        panic!("callback")
    };
    let table = f.table(callback);
    let created = f.draw(Some(callback), record, table)[0].unwrap();
    let receipt = f.windows.abort().unwrap();
    assert!(
        receipt
            .cancelled_callbacks
            .iter()
            .any(|entry| entry.callback == callback)
    );
    assert!(f.objects.metafile_object(created).unwrap().is_none());
}

#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_cleanup_preserves_borrowed_stock_object_aliases() {
    let mut f = Fixture::new();
    let stock = f.objects.stock(7).unwrap().unwrap();
    let (success, retired) = f.enumerate(stream(&[record(0x0214, &[0, 0])], 1), |f, id, _| {
        f.windows
            .commit_metafile_table(id, &[Some(stock)], &f.objects, false)
            .unwrap();
        true
    });
    assert!(success);
    assert!(retired.is_empty());
    assert!(f.objects.metafile_object(stock).unwrap().is_some());
}

fn wing_bitmap(
    f: &mut Fixture,
) -> (
    Win16HostGdiObject,
    super::super::super::win16_wing_dib_storage::CreatedDibSection,
) {
    use super::super::super::{
        win16_wing_dib_header::BitmapInfoHeaderWire, win16_wing_dib_storage::Win16DibSectionOwner,
    };
    let header = BitmapInfoHeaderWire::new(40, 2, 2, 1, 32, 0, 16, 0, 0, 0, 0).into_bytes();
    let dc = f.dcs.lease_dc(f.dc).unwrap().unwrap();
    let created = Win16DibSectionOwner::create(dc.native(), &header, 16)
        .unwrap()
        .unwrap();
    let token = f
        .objects
        .adopt_dib_section(created.bitmap, Arc::clone(&created.owner))
        .unwrap()
        .unwrap();
    created.memory.validate_read(0, 4).unwrap();
    (token, created)
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_record_delete_retires_wing_shared_memory() {
    let mut f = Fixture::new();
    let (bitmap, created) = wing_bitmap(&mut f);
    let pin = created.owner.pin_native().unwrap();
    assert_eq!(
        f.draw(None, record(0x01f0, &[0]), vec![Some(bitmap)]),
        vec![None]
    );
    assert!(f.objects.metafile_object(bitmap).unwrap().is_none());
    assert!(created.memory.validate_read(0, 4).is_err());
    assert!(created.owner.pin_native().is_err());
    drop(pin);
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_enumeration_cleanup_retires_wing_storage_on_owner_thread() {
    let mut f = Fixture::new();
    let (bitmap, created) = wing_bitmap(&mut f);
    let pin = created.owner.pin_native().unwrap();
    let (success, retired) = f.enumerate(stream(&[record(0x0214, &[0, 0])], 1), |f, id, _| {
        f.windows
            .commit_metafile_table(id, &[Some(bitmap)], &f.objects, false)
            .unwrap();
        true
    });
    assert!(success);
    assert_eq!(retired, vec![bitmap]);
    assert!(created.memory.validate_read(0, 4).is_err());
    assert!(created.owner.pin_native().is_err());
    drop(pin);
}
#[test]
#[ignore = "requires native Windows GDI and callback worker; no interactive input"]
fn metafile_native_abort_acknowledges_wing_storage_after_worker_quiescence() {
    let mut f = Fixture::new();
    let (bitmap, created) = wing_bitmap(&mut f);
    let bits = stream(&[record(0x0214, &[0, 0])], 1);
    let step = f
        .windows
        .begin(
            Win16WindowOperation::EnumMetafile { dc: f.dc, bits },
            &mut f.objects,
            None,
        )
        .unwrap();
    let Win16WindowStep::Started { step, .. } = step else {
        panic!("started")
    };
    let Win16WindowStep::MetafileCallback { callback, .. } = *step else {
        panic!("callback")
    };
    f.windows
        .commit_metafile_table(callback, &[Some(bitmap)], &f.objects, false)
        .unwrap();
    let receipt = f.windows.abort().unwrap();
    assert!(
        receipt
            .cancelled_callbacks
            .iter()
            .any(|entry| entry.callback == callback)
    );
    // This is the same owner-thread acknowledgement used by RuntimeHost's
    // abort boundary, after the worker has returned its quiescence receipt.
    f.objects
        .acknowledge_metafile_storage_retirements()
        .unwrap();
    assert!(created.memory.validate_read(0, 4).is_err());
    assert!(created.owner.pin_native().is_err());
}
