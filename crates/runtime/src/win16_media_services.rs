//! Pointer-free synchronous multimedia host contracts and task-owned aliases.

use std::collections::BTreeMap;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16CallbackArgumentData,
    Win16GuestCallbackToken,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMediaIoHandle(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMediaTimeValue {
    Milliseconds(u32),
    Samples(u32),
    Bytes(u32),
    Smpte([u8; 6]),
    Midi(u32),
    Unknown { time_type: u32, value: [u8; 8] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMediaTimeOperation {
    GetSystemTime,
    GetDevCaps,
    GetTime,
    BeginPeriod { period: u16 },
    EndPeriod { period: u16 },
    /// Install a native timer. `callback` is a runtime token, not a guest FAR
    /// and not a host function pointer. `guest_timer` is the UINT this runtime
    /// returns from `timeSetEvent` and later passes as the callback's `uID`.
    SetEvent {
        delay: u16,
        resolution: u16,
        user: u32,
        periodic: bool,
        callback: Win16GuestCallbackToken,
        guest_timer: u16,
    },
    KillEvent { timer: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMediaTimeResult {
    SystemTime { result: u32, value: Win16HostMediaTimeValue },
    DevCaps { result: u32, minimum_period: u32, maximum_period: u32 },
    Time(u32),
    Period(u32),
    /// Opaque host-owned identity, not a reusable native WinMM timer id.
    /// `None` is the documented NULL timer id: the event was not created.
    SetEvent { timer: Option<u32> },
    /// `0` cancels the event. Any other value, including `TIMERR_NOCANDO`,
    /// leaves the guest timer record in place.
    Kill(u32),
}

/// Five FAR PASCAL `TIMECALLBACK` arguments in prototype order.
/// `uMsg`, `dw1`, and `dw2` stay zero: SDK 3.1 marks them reserved and does
/// not publish a value. No argument is a host pointer.
pub fn multimedia_timer_callback_arguments(
    timer: u16,
    user: u32,
) -> [Win16CallbackArgumentData; 5] {
    [
        Win16CallbackArgumentData::Word(timer),
        Win16CallbackArgumentData::Word(0),
        Win16CallbackArgumentData::Dword(user),
        Win16CallbackArgumentData::Dword(0),
        Win16CallbackArgumentData::Dword(0),
    ]
}

/// ABI-neutral copy of the five fixed DWORDs in guest MMCKINFO16.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Win16HostMmckInfo {
    pub chunk_id: u32,
    pub chunk_size: u32,
    pub form_type: u32,
    pub data_offset: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMediaOpenResult {
    File(Option<Win16HostMediaIoHandle>),
    Boolean(bool),
    Status(u32),
}

#[derive(Debug)]
pub enum Win16HostMediaIoOperation {
    Open { path: Vec<u8>, path_buffer: Option<Vec<u8>>, flags: u32 },
    Close { handle: Win16HostMediaIoHandle, flags: u16 },
    Read { handle: Win16HostMediaIoHandle, count: i32 },
    Write { handle: Win16HostMediaIoHandle, data: Vec<u8> },
    Seek { handle: Win16HostMediaIoHandle, offset: i32, origin: i16 },
    Flush { handle: Win16HostMediaIoHandle, flags: u16 },
    StringToFourCc { text: Vec<u8>, flags: u16 },
    Descend {
        handle: Win16HostMediaIoHandle,
        chunk: Win16HostMmckInfo,
        parent: Option<Win16HostMmckInfo>,
        flags: u16,
    },
    Ascend { handle: Win16HostMediaIoHandle, chunk: Win16HostMmckInfo, flags: u16 },
    CreateChunk { handle: Win16HostMediaIoHandle, chunk: Win16HostMmckInfo, flags: u16 },
    Rename { old_path: Vec<u8>, new_path: Vec<u8>, flags: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMediaIoResult {
    Open { result: Win16HostMediaOpenResult, path_buffer: Option<Vec<u8>> },
    Scalar(u32),
    Transfer { result: i32, bytes: Vec<u8> },
    Chunk { result: u32, chunk: Win16HostMmckInfo },
    FourCc(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MediaTimerRecord {
    native: Option<u32>,
    callback: Win16GuestCallbackToken,
    one_shot: bool,
}

/// Guest-visible buffered MMIO window. Pointers stay guest far values.
#[derive(Clone, Debug)]
pub(crate) struct Win16MmioBufferState {
    pub base: u32,
    pub size: u32,
    pub next: u32,
    pub end_read: u32,
    pub end_write: u32,
    pub file_offset: i32,
    pub disk_offset: i32,
    pub dirty: bool,
    pub owned: u16,
    pub info: [u32; 3],
    pub error: u16,
}

#[derive(Clone, Copy, Debug)]
struct Win16MmioFile {
    native: Win16HostMediaIoHandle,
    open_flags: u32,
}

/// Per-guest HMMIO buffers, timer-period references, and multimedia timer ids.
#[derive(Debug)]
pub struct Win16MediaServicesState {
    next_mmio_alias: u16,
    mmio_handles: BTreeMap<u16, Win16MmioFile>,
    mmio_buffers: BTreeMap<u16, Win16MmioBufferState>,
    mmio_io_procs: BTreeMap<u32, u32>,
    period_references: BTreeMap<u16, u32>,
    next_timer: u16,
    timers: BTreeMap<u16, MediaTimerRecord>,
}

impl Default for Win16MediaServicesState {
    fn default() -> Self {
        Self {
            next_mmio_alias: 1,
            mmio_handles: BTreeMap::new(),
            period_references: BTreeMap::new(),
            next_timer: 1,
            timers: BTreeMap::new(),
            mmio_buffers: BTreeMap::new(),
            mmio_io_procs: BTreeMap::new(),
        }
    }
}

impl Win16MediaServicesState {
    pub(crate) fn native_sources_quiescent(&self) -> bool {
        self.mmio_handles.is_empty() && self.mmio_buffers.is_empty()
            && self.period_references.is_empty() && self.timers.is_empty()
    }

    pub(crate) fn mmio_handle(&self, guest: u16) -> Option<Win16HostMediaIoHandle> {
        self.mmio_handles.get(&guest).map(|file| file.native)
    }

    pub(crate) fn mmio_open_flags(&self, guest: u16) -> Option<u32> {
        self.mmio_handles.get(&guest).map(|file| file.open_flags)
    }

    pub(crate) fn mmio_is_buffered(&self, guest: u16) -> bool {
        self.mmio_buffers.contains_key(&guest)
    }

    pub(crate) fn mmio_buffer(&self, guest: u16) -> Option<&Win16MmioBufferState> {
        self.mmio_buffers.get(&guest)
    }

    pub(crate) fn set_mmio_buffer(&mut self, guest: u16, buffer: Win16MmioBufferState) {
        self.mmio_buffers.insert(guest, buffer);
    }

    pub(crate) fn clear_mmio_buffer(&mut self, guest: u16) -> u16 {
        self.mmio_buffers.remove(&guest).map(|buffer| buffer.owned).unwrap_or(0)
    }

    pub(crate) fn mmio_buffer_guests(&self) -> Vec<u16> {
        self.mmio_buffers.keys().copied().collect()
    }

    /// Install, remove, or find a guest I/O procedure. The stored value is a
    /// guest far pointer, never a host address. `MMIO_GLOBALPROC` shares this
    /// table because the runtime has one guest process.
    pub(crate) fn mmio_install_io_proc(&mut self, fourcc: u32, procedure: u32, flags: u32) -> u32 {
        const INSTALL: u32 = 0x0001_0000;
        const REMOVE: u32 = 0x0002_0000;
        const FIND: u32 = 0x0004_0000;
        const GLOBAL: u32 = 0x1000_0000;
        let operation = flags & (INSTALL | REMOVE | FIND);
        if operation == FIND || operation == REMOVE {
            return if operation == FIND {
                self.mmio_io_procs.get(&fourcc).copied().unwrap_or(0)
            } else {
                self.mmio_io_procs.remove(&fourcc).unwrap_or(0)
            };
        }
        if operation != INSTALL || flags & !INSTALL & !GLOBAL != 0 || procedure == 0 || fourcc == 0 {
            return 0;
        }
        self.mmio_io_procs.insert(fourcc, procedure);
        procedure
    }

    pub(crate) fn insert_mmio(
        &mut self,
        handle: Win16HostMediaIoHandle,
        open_flags: u32,
    ) -> Option<u16> {
        if self.mmio_handles.len() >= usize::from(u16::MAX) { return None; }
        let mut candidate = self.next_mmio_alias.max(1);
        for _ in 0..=u16::MAX {
            if !self.mmio_handles.contains_key(&candidate) {
                self.mmio_handles.insert(candidate, Win16MmioFile { native: handle, open_flags });
                self.next_mmio_alias = candidate.wrapping_add(1).max(1);
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
        None
    }

    pub(crate) fn remove_mmio(&mut self, guest: u16) -> u16 {
        self.mmio_handles.remove(&guest);
        self.clear_mmio_buffer(guest)
    }

    pub(crate) fn can_begin_period(&self, period: u16) -> bool {
        self.period_references.get(&period).copied().unwrap_or(0) < u32::MAX
    }

    pub(crate) fn record_period_begin(&mut self, period: u16) {
        let count = self.period_references.entry(period).or_default();
        *count += 1;
    }

    pub(crate) fn record_period_end(&mut self, period: u16) {
        let Some(count) = self.period_references.get_mut(&period) else { return; };
        *count -= 1;
        if *count == 0 { self.period_references.remove(&period); }
    }

    pub(crate) fn reserve_timer(
        &mut self,
        callback: Win16GuestCallbackToken,
        one_shot: bool,
    ) -> Option<u16> {
        if self.timers.len() >= usize::from(u16::MAX) {
            return None;
        }
        let mut candidate = self.next_timer.max(1);
        for _ in 0..=u16::MAX {
            if candidate != 0 && !self.timers.contains_key(&candidate) {
                self.timers.insert(
                    candidate,
                    MediaTimerRecord { native: None, callback, one_shot },
                );
                self.next_timer = candidate.wrapping_add(1).max(1);
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
        None
    }

    pub(crate) fn bind_timer(&mut self, guest: u16, native: u32) -> bool {
        let Some(record) = self.timers.get_mut(&guest) else { return false; };
        if native == 0 || record.native.is_some() {
            return false;
        }
        record.native = Some(native);
        true
    }

    pub(crate) fn timer(&self, guest: u16) -> Option<(Option<u32>, Win16GuestCallbackToken)> {
        self.timers.get(&guest).map(|record| (record.native, record.callback))
    }

    pub(crate) fn remove_timer(
        &mut self,
        guest: u16,
    ) -> Option<(Option<u32>, Win16GuestCallbackToken)> {
        self.timers.remove(&guest).map(|record| (record.native, record.callback))
    }

    /// Guest id of a one-shot whose callback token matches, once its native
    /// timer exists. Periodic timers stay until `timeKillEvent`.
    pub(crate) fn one_shot_guest_for_callback(
        &self,
        callback: Win16GuestCallbackToken,
    ) -> Option<u16> {
        self.timers.iter().find_map(|(guest, record)| {
            (record.one_shot && record.native.is_some() && record.callback == callback)
                .then_some(*guest)
        })
    }

    pub(crate) fn timer_guests(&self) -> Vec<u16> {
        self.timers.keys().copied()
            .collect()
    }

    /// Best-effort task cleanup attempts every resource and returns its first
    /// failure; failed entries stay owned for a later cleanup/host Drop retry.
    pub(crate) fn retire_all(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first_error = None;
        let mut after = 0_u16;
        loop {
            let Some((guest, handle)) = self.mmio_handles
                .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                .next().map(|(guest, file)| (*guest, file.native)) else { break; };
            after = guest;
            // A failed flush or allocation release still owns its guest buffer.
            // Keep the native file open so task cleanup can retry without data loss.
            if self.mmio_buffers.contains_key(&guest) {
                keep_first(&mut first_error, RuntimeError::new(Kind::HostFailure,
                    "MMIO guest buffer must retire before its native file"));
                continue;
            }
            match host.win16_media_io(Win16HostMediaIoOperation::Close { handle, flags: 0 }) {
                Ok(Win16HostMediaIoResult::Scalar(0)) => {
                    self.mmio_handles.remove(&guest);
                }
                Ok(Win16HostMediaIoResult::Scalar(code)) => {
                    keep_first(&mut first_error, RuntimeError::new(Kind::HostFailure,
                        format!("native MMIO close failed during guest teardown (0x{code:08X})")));
                }
                Ok(_) => keep_first(&mut first_error, RuntimeError::new(Kind::InternalInvariant,
                    "MMIO teardown returned the wrong host result")),
                Err(error) => keep_first(&mut first_error, error),
            };
        }

        let mut after_period = None;
        loop {
            let next = match after_period {
                None => self.period_references.first_key_value().map(|(period, count)| (*period, *count)),
                Some(period) => self.period_references
                    .range((std::ops::Bound::Excluded(period), std::ops::Bound::Unbounded))
                    .next().map(|(period, count)| (*period, *count)),
            };
            let Some((period, count)) = next else { break; };
            after_period = Some(period);
            for _ in 0..count {
                match host.win16_media_time(Win16HostMediaTimeOperation::EndPeriod { period }) {
                    Ok(Win16HostMediaTimeResult::Period(0)) => self.record_period_end(period),
                    Ok(Win16HostMediaTimeResult::Period(code)) => keep_first(
                        &mut first_error,
                        RuntimeError::new(Kind::HostFailure, format!(
                            "native timer-period cleanup failed (0x{code:08X})",
                        )),
                    ),
                    Ok(_) => keep_first(&mut first_error, RuntimeError::new(Kind::InternalInvariant,
                        "timer-period teardown returned the wrong host result")),
                    Err(error) => keep_first(&mut first_error, error),
                }
            }
        }
        match first_error { Some(error) => Err(error), None => Ok(()) }
    }
}

fn keep_first(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    if slot.is_none() { *slot = Some(error); }
}
