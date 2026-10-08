//! Scoped native buffers for USER control structures, arrays and text.

use std::{cell::RefCell, ops::Range, rc::Rc};
use runtime::{RuntimeError, DiagnosticKind as Kind, Win16HostControlCall,
    Win16HostControlMessage as Message, Win16HostControlOutput as Output,
    Win16HostEditMessage as Edit, Win16HostListBoxMessage as List,
    Win16HostComboBoxMessage as Combo, Win16HostControlFamily as Family,
    Win16HostMessageResult, Win16HostMessageOutput, Win16HostRect};
use windows_sys::Win32::{Foundation::{HWND,RECT}, UI::{Controls::*,WindowsAndMessaging::*}};
use super::win16_window_worker::WorkerState;
use super::win16_window_default::{MessageInvocation,invoke_message};

#[derive(Clone, Debug)]
struct TextRange {
    guest: Range<usize>,
    native: Range<usize>,
}

/// The Win16 ANSI edit messages count guest bytes, while the native control
/// counts UTF-16 code units. This map is built from one owned text snapshot;
/// only the retained built-in procedure may be queried for that snapshot.
pub(super) struct TextIndexMap {
    text: Vec<u16>,
    guest_len: usize,
    native_len: usize,
    ranges: Vec<TextRange>,
}

impl TextIndexMap {
    fn new(codec: super::super::guest_text::GuestTextCodec, native_text: Vec<u16>) -> Result<Self, RuntimeError> {
        let encoded = codec.from_wide(&native_text)?;
        let (decoded, spans) = codec.to_wide_with_ranges(&encoded.bytes)?;
        let source_scalars = scalar_ranges(&native_text)?;
        let decoded_scalars = scalar_ranges(&decoded)?;
        if source_scalars.len() != decoded_scalars.len() || spans.len() != source_scalars.len() {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "guest code page cannot map native control character positions exactly"));
        }
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(spans.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate control text position map", error))?;
        for ((native, decoded), span) in source_scalars.into_iter()
            .zip(decoded_scalars).zip(spans)
        {
            if decoded != span.utf16_units {
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "guest code-page spans do not match native control characters"));
            }
            ranges.push(TextRange { guest: span.guest_bytes, native });
        }
        Ok(Self { native_len: native_text.len(), text: native_text,
            guest_len: encoded.bytes.len(), ranges })
    }

    pub(super) fn guest_to_native(&self, offset: usize) -> Result<usize, RuntimeError> {
        let offset = offset.min(self.guest_len);
        if offset == 0 { return Ok(0); }
        if offset == self.guest_len { return Ok(self.native_len); }
        let index=self.ranges.partition_point(|range|range.guest.end<offset);
        if let Some(range)=self.ranges.get(index) {
            if offset == range.guest.start { return Ok(range.native.start); }
            if offset == range.guest.end { return Ok(range.native.end); }
        }
        Err(RuntimeError::new(Kind::CompatibilityGap,
            "guest control index splits an encoded character"))
    }

    pub(super) fn native_to_guest(&self, offset: usize) -> Result<usize, RuntimeError> {
        if offset > self.native_len {
            return Err(RuntimeError::new(Kind::HostFailure,
                "native control index exceeds its owned text snapshot"));
        }
        if offset == 0 { return Ok(0); }
        if offset == self.native_len { return Ok(self.guest_len); }
        let index=self.ranges.partition_point(|range|range.native.end<offset);
        if let Some(range)=self.ranges.get(index) {
            if offset == range.native.start { return Ok(range.guest.start); }
            if offset == range.native.end { return Ok(range.guest.end); }
        }
        Err(RuntimeError::new(Kind::CompatibilityGap,
            "native control index splits a UTF-16 character"))
    }

    pub(super) fn guest_len(&self) -> usize { self.guest_len }
    pub(super) fn native_len(&self) -> usize { self.native_len }
    pub(super) fn text(&self) -> &[u16] { &self.text }
}

pub(super) fn handles(message:&Message)->bool {
    matches!(message,
        Message::Edit(Edit::GetRect|Edit::SetRect{..}|Edit::SetRectNoPaint{..}|Edit::GetLine{..}|Edit::SetTabStops{..})
        | Message::ListBox(List::GetText{..}|List::GetTextLength{..}|List::GetSelectionItems{..}|List::SetTabStops{..}|List::GetItemRect{..})
        | Message::ComboBox(Combo::GetText{..}|Combo::GetTextLength{..}|Combo::GetDroppedControlRect))
}

fn result(value:u32,output:Output)->Win16HostMessageResult {
    Win16HostMessageResult {value,output:Win16HostMessageOutput::Control(output),dialog_result:None}
}
fn empty(value:u32)->Win16HostMessageResult {
    Win16HostMessageResult {value,output:Win16HostMessageOutput::None,dialog_result:None}
}
fn rect(r:RECT)->Win16HostRect {Win16HostRect{left:r.left,top:r.top,right:r.right,bottom:r.bottom}}

pub(super) fn invoke(state:&Rc<RefCell<WorkerState>>,call:&Win16HostControlCall,
    invocation:MessageInvocation,hwnd:HWND)->Result<Option<Win16HostMessageResult>,RuntimeError> {
    let output = match &call.message {
        Message::Edit(Edit::GetRect) | Message::ListBox(List::GetItemRect{..})
            | Message::ComboBox(Combo::GetDroppedControlRect) => {
            let (id,w) = match &call.message {
                Message::Edit(_) => (EM_GETRECT,0),
                Message::ListBox(List::GetItemRect{index}) => (LB_GETITEMRECT,usize::from(*index)),
                _ => (CB_GETDROPPEDCONTROLRECT,0),
            };
            let mut r = RECT::default();
            let value = invoke_message(invocation,hwnd,id,w,&mut r as *mut RECT as isize).value;
            if value==u32::MAX {empty(value)} else {result(value,Output::Rect(rect(r)))}
        }
        Message::Edit(Edit::SetRect{rect:r}|Edit::SetRectNoPaint{rect:r}) => {
            let mut r = RECT {left:r.left,top:r.top,right:r.right,bottom:r.bottom};
            let id = if matches!(&call.message,Message::Edit(Edit::SetRectNoPaint{..})){EM_SETRECTNP}else{EM_SETRECT};
            invoke_message(invocation,hwnd,id,0,&mut r as *mut RECT as isize)
        }
        Message::Edit(Edit::SetTabStops{positions}) => {
            let native = positions.iter().map(|value|u32::from(*value)).collect::<Vec<_>>();
            invoke_message(invocation,hwnd,EM_SETTABSTOPS,native.len(),
                if native.is_empty(){0}else{native.as_ptr() as isize})
        }
        Message::ListBox(List::SetTabStops{positions}) => {
            let native = positions.iter().map(|value|i32::from(*value)).collect::<Vec<_>>();
            invoke_message(invocation,hwnd,LB_SETTABSTOPS,native.len(),
                if native.is_empty(){0}else{native.as_ptr() as isize})
        }
        Message::Edit(Edit::GetLine{line,capacity}) => {
            if *capacity == 0 { return Ok(Some(empty(0))); }
            let Some(map) = text_index_map_for_builtin(state, call, hwnd,
                runtime::Win16HostSystemClass::Edit,invocation)? else { return Ok(None); };
            let (start,end)=if call.expected.style&(ES_MULTILINE as u32)==0 {
                // EM_GETLINE ignores wParam for single-line EDIT controls.
                (0,map.native_len())
            } else {
                let start = invoke_message(invocation,hwnd,EM_LINEINDEX,usize::from(*line),0).value as i32;
                if start < 0 { return Ok(Some(result(0,Output::Bytes(Vec::new())))); }
                let length = invoke_message(invocation,hwnd,EM_LINELENGTH,start as usize,0).value as i32;
                if length < 0 { return Ok(Some(empty(length as u32))); }
                let start = usize::try_from(start).map_err(|_|RuntimeError::new(Kind::HostFailure,
                    "native edit line start is outside the host range"))?;
                let end = start.checked_add(length as usize).filter(|end| *end <= map.native_len())
                    .ok_or_else(||RuntimeError::new(Kind::HostFailure,
                        "native edit line range exceeds its owned text snapshot"))?;
                (start,end)
            };
            let codec = state.borrow().text_codec;
            let bytes = codec.from_wide_bounded(&map.text()[start..end],usize::from(*capacity))?.bytes;
            let value = u32::try_from(bytes.len()).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
                "guest edit line byte count exceeds the Win16 result range"))?;
            result(value,Output::Bytes(bytes))
        }
        Message::ListBox(List::GetSelectionItems{capacity}) => {
            let mut native = vec![0_i32;usize::from(*capacity)];
            let value = invoke_message(invocation,hwnd,LB_GETSELITEMS,usize::from(*capacity),
                if native.is_empty(){0}else{native.as_mut_ptr() as isize}).value;
            if value==u32::MAX {empty(value)} else {
                let Some(items) = native.get(..value as usize) else {return Err(RuntimeError::new(
                    Kind::HostFailure,"LISTBOX returned more selection entries than its capacity"));};
                let items = items.iter().map(|value|i16::try_from(*value).map_err(|_|RuntimeError::new(
                    Kind::CompatibilityGap,"LISTBOX index exceeds the Win16 signed index range")))
                    .collect::<Result<Vec<_>,_>>()?;
                if *capacity==0 {empty(value)} else {result(value,Output::Int16s(items))}
            }
        }
        Message::ListBox(List::GetText{index,max_write_bytes})
            | Message::ComboBox(Combo::GetText{index,max_write_bytes}) => {
            return get_text(state,call,invocation,hwnd,*index,*max_write_bytes);
        }
        Message::ListBox(List::GetTextLength{index})
            | Message::ComboBox(Combo::GetTextLength{index}) => {
            return get_text_length(state,call,invocation,hwnd,*index);
        }
        _ => return Err(RuntimeError::new(Kind::InternalInvariant,"control output reached the wrong native adapter")),
    };
    Ok(Some(output))
}

fn get_text(state:&Rc<RefCell<WorkerState>>,call:&Win16HostControlCall,
    invocation:MessageInvocation,hwnd:HWND,index:u16,capacity:u32)
    ->Result<Option<Win16HostMessageResult>,RuntimeError> {
    let list = call.expected.family==Family::ListBox;
    let strings_flag = if list {LBS_HASSTRINGS}else{CBS_HASSTRINGS} as u32;
    let strings = call.expected.style & 0x30==0 || call.expected.style & strings_flag!=0;
    let kind = if list {runtime::Win16HostSystemClass::ListBox}else{runtime::Win16HostSystemClass::ComboBox};
    if !super::win16_native_procedures::is_builtin_control_target(state,call.window,call.dispatch,kind)? {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "unsized control GETTEXT requires the retained built-in procedure; returned LB/CB_ERR");
        return Ok(Some(empty(u32::MAX)));
    }
    if !strings {
        if capacity<4 {return Ok(Some(empty(u32::MAX)));}
        // Native no-strings GETTEXT writes ULONG_PTR (8 bytes on our hosts).
        // The guest wire value is DWORD; keep separate staging and narrow it.
        let mut data = 0_usize;
        let id=if list {LB_GETTEXT}else{CB_GETLBTEXT};
        let value = invoke_message(invocation,hwnd,id,usize::from(index),&mut data as *mut usize as isize).value;
        if value==u32::MAX {return Ok(Some(empty(value)));}
        let data = u32::try_from(data).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
            "control item data cannot be represented as a guest DWORD"))?;
        return Ok(Some(result(4,Output::ItemData(data))));
    }
    let text = match read_list_text(invocation,hwnd,list,index)? {
        NativeText::Error(value) => return Ok(Some(empty(value))),
        NativeText::Text(text) => text,
    };
    let codec = state.borrow().text_codec;
    let bytes = codec.from_wide(&text)?.bytes;
    let required = bytes.len().checked_add(1).ok_or_else(||RuntimeError::new(
        Kind::ResourceExhausted,"guest control text size overflowed"))?;
    if required>capacity as usize || required>runtime::WIN16_CONTROL_TEXT_CAPACITY {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "control GETTEXT output exceeds its checked guest capacity; returned LB/CB_ERR");
        return Ok(Some(empty(u32::MAX)));
    }
    if bytes.contains(&0) { return Err(RuntimeError::new(Kind::HostFailure,
        "guest control text conversion produced an embedded terminator")); }
    let value = u32::try_from(bytes.len()).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
        "guest control text byte count exceeds the Win16 result range"))?;
    let mut output = bytes;
    output.push(0);
    Ok(Some(result(value,Output::AnsiZ(output))))
}

fn get_text_length(state:&Rc<RefCell<WorkerState>>,call:&Win16HostControlCall,
    invocation:MessageInvocation,hwnd:HWND,index:u16)
    ->Result<Option<Win16HostMessageResult>,RuntimeError> {
    let list=call.expected.family==Family::ListBox;
    let kind=if list {runtime::Win16HostSystemClass::ListBox}else{runtime::Win16HostSystemClass::ComboBox};
    if !super::win16_native_procedures::is_builtin_control_target(state,call.window,call.dispatch,kind)? {
        return Ok(None);
    }
    let strings_flag=if list {LBS_HASSTRINGS}else{CBS_HASSTRINGS} as u32;
    let strings=call.expected.style&0x30==0 || call.expected.style&strings_flag!=0;
    if !strings {
        // Even owner-draw/no-strings controls report LB_ERR/CB_ERR from
        // GETTEXTLEN. The guest GETTEXT destination is an opaque DWORD, so
        // success always requires four bytes and must not query W text.
        let length_id=if list {LB_GETTEXTLEN}else{CB_GETLBTEXTLEN};
        let length=invoke_message(invocation,hwnd,length_id,usize::from(index),0).value;
        return Ok(Some(empty(if length>=u32::MAX-1 {length}else{4})));
    }
    let text=match read_list_text(invocation,hwnd,list,index)? {
        NativeText::Error(value)=>return Ok(Some(empty(value))),
        NativeText::Text(text)=>text,
    };
    let bytes=state.borrow().text_codec.from_wide(&text)?.bytes;
    let value=u32::try_from(bytes.len()).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
        "guest control text byte count exceeds the Win16 result range"))?;
    Ok(Some(empty(value)))
}

enum NativeText { Error(u32), Text(Vec<u16>) }

fn read_list_text(invocation:MessageInvocation,hwnd:HWND,list:bool,index:u16)
    ->Result<NativeText,RuntimeError> {
    let length_id=if list {LB_GETTEXTLEN}else{CB_GETLBTEXTLEN};
    let text_id=if list {LB_GETTEXT}else{CB_GETLBTEXT};
    let length=invoke_message(invocation,hwnd,length_id,usize::from(index),0).value;
    if length>=u32::MAX-1 {return Ok(NativeText::Error(length));}
    let length=usize::try_from(length).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
        "native control text length is outside the host range"))?;
    if length>runtime::WIN16_CONTROL_TEXT_CAPACITY {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native control text exceeds its checked UTF-16 staging bound"));
    }
    let allocation=length.checked_add(1).ok_or_else(||RuntimeError::new(Kind::ResourceExhausted,
        "native control text staging size overflowed"))?;
    let mut wide=vec![0xffff_u16;allocation];
    let copied=invoke_message(invocation,hwnd,text_id,usize::from(index),wide.as_mut_ptr() as isize).value;
    if copied>=u32::MAX-1 {return Ok(NativeText::Error(copied));}
    if copied as usize!=length || wide[length]!=0 || wide[..length].contains(&0) {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native control GETTEXTW violated its checked output contract"));
    }
    wide.truncate(length);
    Ok(NativeText::Text(wide))
}

pub(super) fn text_index_map_for_builtin(state:&Rc<RefCell<WorkerState>>,
    call:&Win16HostControlCall,hwnd:HWND,kind:runtime::Win16HostSystemClass,
    invocation:MessageInvocation)
    ->Result<Option<TextIndexMap>,RuntimeError> {
    if !super::win16_native_procedures::is_builtin_control_target(state,call.window,call.dispatch,kind)? {
        return Ok(None);
    }
    let text=read_window_text(invocation,hwnd)?;
    TextIndexMap::new(state.borrow().text_codec,text).map(Some)
}

fn read_window_text(invocation:MessageInvocation,hwnd:HWND)->Result<Vec<u16>,RuntimeError> {
    let length=invoke_message(invocation,hwnd,WM_GETTEXTLENGTH,0,0).value as i32;
    if length<0 {return Err(RuntimeError::new(Kind::HostFailure,
        "native control returned a negative WM_GETTEXTLENGTH result"));}
    let length=length as usize;
    if length>runtime::WIN16_CONTROL_TEXT_CAPACITY.saturating_mul(2) {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native edit text exceeds its checked UTF-16 staging bound"));
    }
    let allocation=length.checked_add(1).ok_or_else(||RuntimeError::new(Kind::ResourceExhausted,
        "native edit text staging size overflowed"))?;
    let mut wide=vec![0xffff_u16;allocation];
    let copied=invoke_message(invocation,hwnd,WM_GETTEXT,allocation,wide.as_mut_ptr() as isize).value as i32;
    if copied<0 || copied as usize!=length || wide[copied as usize]!=0
        || wide[..copied as usize].contains(&0) {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native GetWindowTextW violated its checked output contract"));
    }
    wide.truncate(copied as usize);
    Ok(wide)
}

fn scalar_ranges(text:&[u16])->Result<Vec<Range<usize>>,RuntimeError> {
    let mut ranges=Vec::new();
    ranges.try_reserve(text.len()).map_err(|error|RuntimeError::with_source(
        Kind::ResourceExhausted,"allocate UTF-16 scalar ranges",error))?;
    let mut at=0;
    while at<text.len() {
        let first=text[at];
        let end=if (0xd800..=0xdbff).contains(&first) {
            if !text.get(at+1).is_some_and(|unit|(0xdc00..=0xdfff).contains(unit)) {
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "native control text contains an unpaired UTF-16 surrogate"));
            }
            at+2
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "native control text contains an unpaired UTF-16 surrogate"));
        } else { at+1 };
        ranges.push(at..end);
        at=end;
    }
    Ok(ranges)
}
