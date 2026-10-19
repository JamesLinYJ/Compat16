//! Owned Win32 dialog-template encoding for the dialog worker.
//!
//! Win16 template strings and custom control creation data are copied into a
//! stable host allocation. Guest FAR values never become pointers in this
//! representation.
//! The SDK defines a distinct byte-oriented Win16 template, and Win32 exposes
//! no parser for it. This adapter expands its atoms/strings to a native W
//! template because the encoder emits UTF-16 fields and the worker calls the
//! matching `CreateDialogIndirectParamW`/`DialogBoxIndirectParamW` APIs.

use std::cell::RefCell;
use std::rc::Rc;

use super::super::win16_window_worker::WorkerState;
use super::copy_host_bytes;
use crate::windows::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostDialogAtom, Win16HostDialogTemplate};

const MAX_NATIVE_DIALOG_TEMPLATE_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct EncodedNativeTemplate {
    pub(super) words: Vec<u32>,
    pub(super) control_offsets: Vec<Option<(usize, usize)>>,
}

struct NativeTemplateWriter {
    bytes: Vec<u8>,
}

impl NativeTemplateWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn reserve(&mut self, extra: usize) -> Result<(), RuntimeError> {
        let length = self.bytes.len().checked_add(extra).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win32 dialog template size overflow",
            )
        })?;
        if length > MAX_NATIVE_DIALOG_TEMPLATE_BYTES {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "expanded Win32 dialog template exceeds the size limit",
            ));
        }
        self.bytes.try_reserve(extra).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate expanded Win32 dialog template",
                error,
            )
        })
    }

    fn word(&mut self, value: u16) -> Result<(), RuntimeError> {
        self.reserve(2)?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn dword(&mut self, value: u32) -> Result<(), RuntimeError> {
        self.reserve(4)?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn wide_string(&mut self, codec: GuestTextCodec, bytes: &[u8]) -> Result<bool, RuntimeError> {
        if bytes.contains(&0) {
            return Ok(false);
        }
        let wide = codec.to_wide(bytes)?;
        self.write_wide_string(wide)?;
        Ok(true)
    }

    fn wide_ascii_string(&mut self, bytes: &[u8]) -> Result<bool, RuntimeError> {
        if bytes.contains(&0) || !bytes.is_ascii() {
            return Ok(false);
        }
        self.write_wide_string(bytes.iter().copied().map(u16::from))?;
        Ok(true)
    }

    fn write_wide_string(
        &mut self,
        wide: impl IntoIterator<Item = u16>,
    ) -> Result<(), RuntimeError> {
        for unit in wide {
            self.word(unit)?;
        }
        self.word(0)?;
        Ok(())
    }

    fn atom(
        &mut self,
        atom: &Win16HostDialogAtom,
        state: &Rc<RefCell<WorkerState>>,
        codec: GuestTextCodec,
    ) -> Result<bool, RuntimeError> {
        match atom {
            Win16HostDialogAtom::None => {
                self.word(0)?;
                Ok(true)
            }
            Win16HostDialogAtom::Ordinal(ordinal) => {
                self.word(0xffff)?;
                self.word(*ordinal)?;
                Ok(true)
            }
            Win16HostDialogAtom::String(value) => self.wide_string(codec, value),
            Win16HostDialogAtom::GuestClass(class) => {
                let name = {
                    let state = state.borrow();
                    let Some(registered) = state.classes.get(class) else {
                        return Ok(false);
                    };
                    copy_host_bytes(
                        registered
                            .name
                            .strip_suffix(&[0])
                            .unwrap_or(&registered.name),
                        "registered native dialog class name",
                    )?
                };
                // GuestClass resolves to a generated host-private ASCII name
                // (or an ASCII predefined class), not the guest's class bytes.
                // Widen it directly so exotic guest code pages cannot alter it.
                self.wide_ascii_string(&name)
            }
        }
    }

    fn align_dword(&mut self) -> Result<(), RuntimeError> {
        let padding = (4 - (self.bytes.len() & 3)) & 3;
        self.reserve(padding)?;
        self.bytes.resize(self.bytes.len() + padding, 0);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u32>, RuntimeError> {
        let word_count = self.bytes.len().checked_add(3).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win32 dialog template size overflow",
            )
        })? / 4;
        let mut aligned = Vec::new();
        aligned.try_reserve_exact(word_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate aligned Win32 dialog template",
                error,
            )
        })?;
        aligned.resize(word_count, 0_u32);
        if !self.bytes.is_empty() {
            // Win32 requires DWORD-aligned DLGTEMPLATE storage. The owned
            // byte writer has already checked size and the destination is
            // the same number of bytes rounded up to DWORDs.
            // SAFETY: The source and destination are non-overlapping, and both spans were checked to cover the copied length.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.bytes.as_ptr(),
                    aligned.as_mut_ptr().cast::<u8>(),
                    self.bytes.len(),
                );
            }
        }
        Ok(aligned)
    }
}

pub(super) fn encode_native_template(
    state: &Rc<RefCell<WorkerState>>,
    template: &Win16HostDialogTemplate,
    creation: runtime::Win16CreationId,
) -> Result<Option<EncodedNativeTemplate>, RuntimeError> {
    if template.menu_template.is_none() && !matches!(&template.menu, Win16HostDialogAtom::None) {
        return Ok(None);
    }
    let Some(item_count) = u16::try_from(template.items.len()).ok() else {
        return Ok(None);
    };
    let codec = state.borrow().text_codec;
    let mut writer = NativeTemplateWriter::new();
    writer.dword(template.style)?;
    writer.dword(0)?;
    writer.word(item_count)?;
    writer.word(template.x as u16)?;
    writer.word(template.y as u16)?;
    writer.word(template.width as u16)?;
    writer.word(template.height as u16)?;
    let menu_encoded = if template.menu_template.is_some() {
        writer.atom(&Win16HostDialogAtom::None, state, codec)?
    } else {
        writer.atom(&template.menu, state, codec)?
    };
    if !menu_encoded
        || !writer.atom(&template.class, state, codec)?
        || !writer.atom(&template.title, state, codec)?
    {
        return Ok(None);
    }
    if let Some(font) = &template.font {
        writer.word(font.point_size as u16)?;
        if !writer.wide_string(codec, &font.face_name)? {
            return Ok(None);
        }
    }
    let mut control_offsets = Vec::new();
    control_offsets
        .try_reserve_exact(template.items.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve dialog-template control route offsets",
                error,
            )
        })?;
    for (index, item) in template.items.iter().enumerate() {
        writer.align_dword()?;
        writer.dword(item.style)?;
        writer.dword(0)?;
        writer.word(item.x as u16)?;
        writer.word(item.y as u16)?;
        writer.word(item.width as u16)?;
        writer.word(item.height as u16)?;
        writer.word(item.id)?;
        if !writer.atom(&item.class, state, codec)? || !writer.atom(&item.title, state, codec)? {
            return Ok(None);
        }
        let is_guest_class = matches!(&item.class, Win16HostDialogAtom::GuestClass(_));
        let has_cookie = is_guest_class || item.initial_icon.is_some();
        let cookie = has_cookie.then(|| dialog_control_cookie(creation, index, item.id));
        let cookie_length = cookie.as_ref().map_or(0, |_| 16);
        let payload_length = item
            .creation_data
            .len()
            .checked_add(cookie_length)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "dialog control creation data size overflow",
                )
            })?;
        let creation_size = if payload_length == 0 {
            0
        } else {
            let Some(size) = payload_length
                .checked_add(2)
                .and_then(|size| u16::try_from(size).ok())
            else {
                return Ok(None);
            };
            size
        };
        // Creation data begins with a WORD count. The template stays stable
        // until CreateDialogIndirectParam returns, making each control's
        // lpCreateParams address an exact route key, never a guest pointer.
        let size_offset = writer.bytes.len();
        writer.word(creation_size)?;
        let data_offset = writer.bytes.len();
        writer.reserve(payload_length)?;
        if let Some(cookie) = cookie {
            writer.bytes.extend_from_slice(&cookie);
        }
        writer.bytes.extend_from_slice(&item.creation_data);
        control_offsets.push(has_cookie.then_some((size_offset, data_offset)));
    }
    writer.align_dword()?;
    writer.finish().map(|words| {
        Some(EncodedNativeTemplate {
            words,
            control_offsets,
        })
    })
}

fn dialog_control_cookie(
    creation: runtime::Win16CreationId,
    index: usize,
    control_id: u16,
) -> [u8; 16] {
    let mut cookie = [0_u8; 16];
    cookie[..4].copy_from_slice(&0x5744_4C47_u32.to_le_bytes());
    cookie[4..12].copy_from_slice(&creation.0.to_le_bytes());
    cookie[12..14].copy_from_slice(&(index as u16).to_le_bytes());
    cookie[14..16].copy_from_slice(&control_id.to_le_bytes());
    cookie
}
