//! Standard USER messages decoded by family, using owned native arguments.

use std::{cell::RefCell, rc::Rc};
use runtime::{RuntimeError, DiagnosticKind as Kind, Win16HostControlQuery,
    Win16HostControlQueryReply, Win16HostControlIdentity, Win16HostControlFamily as Family,
    Win16HostControlDispatch as Dispatch, Win16HostControlCall, Win16HostControlMessage as Message,
    Win16HostControlItem as Item, Win16HostButtonMessage as Button,
    Win16HostEditMessage as Edit, Win16HostListBoxMessage as List,
    Win16HostComboBoxMessage as Combo, Win16HostSystemClass as Class,
    Win16HostMessageResult};
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::Win32::UI::Controls::{EM_GETSEL, EM_SETSEL, EM_SCROLL, EM_GETTHUMB, EM_LINESCROLL,
    EM_GETMODIFY, EM_SETMODIFY, EM_GETLINECOUNT, EM_LINEINDEX, EM_LINELENGTH,
    EM_REPLACESEL, EM_LIMITTEXT, EM_CANUNDO, EM_UNDO, EM_FMTLINES, EM_LINEFROMCHAR,
    EM_SETPASSWORDCHAR, EM_EMPTYUNDOBUFFER, EM_GETFIRSTVISIBLELINE, EM_SETREADONLY,
    EM_GETPASSWORDCHAR, EM_SCROLLCARET};
use windows_sys::Win32::Globalization::{GetCPInfoExW, CPINFOEXW};
use super::win16_window_worker::WorkerState;
use super::win16_window_default::{MessageInvocation, invoke_message};

pub(super) fn query(state: &Rc<RefCell<WorkerState>>, query: Win16HostControlQuery)
    -> Result<Win16HostControlQueryReply, RuntimeError> {
    let mut reply = Win16HostControlQueryReply {
        window: query.window, dispatch: query.dispatch, identity: None,
    };
    let Some(hwnd) = super::win16_window_identity::resolve(state, query.window) else { return Ok(reply); };
    let kind = match query.dispatch {
        Dispatch::CallWindowProc { procedure } => {
            super::win16_native_procedures::control_procedure_family(state, query.window, procedure)?
        }
        Dispatch::Send => super::win16_native_procedures::bound_family(state, hwnd),
    };
    let kind = if let Some(kind) = kind { Some(kind) } else {
        let alias = {
            let state = state.borrow();
            state.windows_by_native.get(&(hwnd as usize)).is_some_and(|identity|
                identity.class.is_none() || identity.class.and_then(|class| state.classes.get(&class))
                    .is_some_and(|class| class.system_class))
        };
        if !alias { return Ok(reply); }
        let mut name = [0_u16; 64];
        // SAFETY: The cookie resolver verified the live worker-owned HWND.
        let count = unsafe { GetClassNameW(hwnd, name.as_mut_ptr(), name.len() as i32) };
        if count <= 0 || count as usize >= name.len() { return Ok(reply); }
        super::win16_system_classes::CLASSES.into_iter().find(|kind| {
            let expected = super::win16_system_classes::name(*kind);
            let expected=&expected[..expected.len()-1];
            name[..count as usize].len()==expected.len() && name[..count as usize].iter()
                .zip(expected).all(|(actual,expected)|u8::try_from(*actual).ok()
                    .is_some_and(|actual|actual.eq_ignore_ascii_case(expected)))
        })
    };
    let family = match kind {
        Some(Class::Button) => Family::Button, Some(Class::Edit) => Family::Edit,
        Some(Class::ListBox) => Family::ListBox, Some(Class::ComboBox) => Family::ComboBox,
        Some(Class::Static) => Family::Static, _ => return Ok(reply),
    };
    // SAFETY: This reads scalar style data from the same live native window.
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) as u32 };
    reply.identity = Some(Win16HostControlIdentity { family, style });
    Ok(reply)
}

pub(super) fn invoke(state: &Rc<RefCell<WorkerState>>, call: Win16HostControlCall,
    invocation: MessageInvocation) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    let matches = match (call.dispatch, invocation) {
        (Dispatch::Send, MessageInvocation::Send) => true,
        (Dispatch::CallWindowProc { procedure }, MessageInvocation::Procedure { token, .. })
            => procedure == token,
        _ => false,
    };
    if !matches { return Err(RuntimeError::new(Kind::InvalidInput,
        "control operation changed its checked dispatch target")); }
    let identity = query(state, Win16HostControlQuery { window: call.window, dispatch: call.dispatch })?;
    if identity.identity != Some(call.expected) { return Ok(None); }
    if !matches!((&call.message, call.expected.family),
        (Message::Button(_),Family::Button) | (Message::Edit(_),Family::Edit)
        | (Message::ListBox(_),Family::ListBox) | (Message::ComboBox(_),Family::ComboBox)
        | (Message::Static(_),Family::Static)) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "typed control request does not match its queried family"));
    }
    let Some(hwnd) = super::win16_window_identity::resolve(state, call.window) else { return Ok(None); };
    if matches!(&call.message, Message::ComboBox(Combo::LimitText { .. }))
        && call.expected.style & 0x3 == CBS_DROPDOWNLIST as u32 {
        // Win3.1 CB_LIMITTEXT reports CB_ERR for a combo without an EDIT.
        return Ok(Some(Win16HostMessageResult { value:u32::MAX,
            output:runtime::Win16HostMessageOutput::None, dialog_result:None }));
    }
    if let Message::ListBox(List::GetItemData { index })
        | Message::ComboBox(Combo::GetItemData { index }) = &call.message {
        let id = if call.expected.family == Family::ListBox { LB_GETITEMDATA } else { CB_GETITEMDATA };
        let native = super::win16_window_default::invoke_native_message(
            invocation, hwnd, id, usize::from(*index), 0);
        // Native item data is ULONG_PTR; the guest stores a DWORD. Retain
        // the native error sentinel and reject values that cannot round-trip.
        let value = if native == -1 { u32::MAX } else {
            u32::try_from(native).map_err(|_| RuntimeError::new(Kind::CompatibilityGap,
                "native control item data exceeds the guest DWORD range"))?
        };
        return Ok(Some(Win16HostMessageResult { value,
            output:runtime::Win16HostMessageOutput::None, dialog_result:None }));
    }
    if super::win16_control_outputs::handles(&call.message) {
        return super::win16_control_outputs::invoke(state, &call, invocation, hwnd);
    }
    if matches!(&call.message, Message::Edit(Edit::GetSelection) | Message::ComboBox(Combo::GetEditSelection)) {
        let id = if call.expected.family == Family::Edit { EM_GETSEL } else { CB_GETEDITSEL };
        let native_class=if call.expected.family==Family::Edit {runtime::Win16HostSystemClass::Edit}
            else {runtime::Win16HostSystemClass::ComboBox};
        let map=super::win16_control_outputs::text_index_map_for_builtin(state,&call,hwnd,native_class,invocation)?;
        let (mut start, mut end) = (u32::MAX, u32::MAX);
        // Native indices use DWORD output buffers; Win16 returns two packed
        // WORD positions. The buffers remain local across the native call.
        let native = invoke_message(invocation, hwnd, id, &mut start as *mut u32 as usize,
            &mut end as *mut u32 as isize);
        if call.expected.family == Family::ComboBox && native.value == u32::MAX {
            return Ok(Some(native));
        }
        if start==u32::MAX || end==u32::MAX {
            return Err(RuntimeError::new(Kind::HostFailure,
                "native control did not write its checked selection indices"));
        }
        let (start,end)=if let Some(map)=map {
            (u16::try_from(map.native_to_guest(start as usize)?).map_err(|_|RuntimeError::new(
                Kind::CompatibilityGap,"guest selection start exceeds the Win16 WORD range"))?,
             u16::try_from(map.native_to_guest(end as usize)?).map_err(|_|RuntimeError::new(
                Kind::CompatibilityGap,"guest selection end exceeds the Win16 WORD range"))?)
        } else {(start as u16,end as u16)};
        return Ok(Some(Win16HostMessageResult {
            value:u32::from(start)|(u32::from(end)<<16),
            output:runtime::Win16HostMessageOutput::None, dialog_result:None,
        }));
    }
    if let Message::Edit(Edit::LineIndex{line})=&call.message {
        if let Some(map)=super::win16_control_outputs::text_index_map_for_builtin(state,&call,hwnd,
            runtime::Win16HostSystemClass::Edit,invocation)? {
            let native=invoke_message(invocation,hwnd,EM_LINEINDEX,*line as isize as usize,0).value as i32;
            let value=if native<0 {native as u32} else {u32::try_from(
                map.native_to_guest(native as usize)?).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
                    "guest edit line index exceeds the Win32 result range"))?};
            return Ok(Some(Win16HostMessageResult {value,output:runtime::Win16HostMessageOutput::None,
                dialog_result:None}));
        }
    }
    if let Message::Edit(Edit::LineFromCharacter{character})=&call.message {
        if let Some(map)=super::win16_control_outputs::text_index_map_for_builtin(state,&call,hwnd,
            runtime::Win16HostSystemClass::Edit,invocation)? {
            let character=map_guest_offset(Some(&map),*character)?;
            return Ok(Some(invoke_message(invocation,hwnd,EM_LINEFROMCHAR,character as isize as usize,0)));
        }
    }
    if let Message::Edit(Edit::LineLength{character})=&call.message {
        if let Some(map)=super::win16_control_outputs::text_index_map_for_builtin(state,&call,hwnd,
            runtime::Win16HostSystemClass::Edit,invocation)? {
            let value=if *character==-1 {
                line_length_guest_bytes(invocation,hwnd,&map)?
            } else if *character>=0 {
                if *character as usize>map.guest_len() {
                    return Ok(Some(Win16HostMessageResult {value:0,
                        output:runtime::Win16HostMessageOutput::None,dialog_result:None}));
                }
                let position=map_guest_offset(Some(&map),*character)? as usize;
                let native_length=invoke_message(invocation,hwnd,EM_LINELENGTH,position,0).value as i32;
                if native_length<=0 {native_length as u32} else {
                    let line=invoke_message(invocation,hwnd,EM_LINEFROMCHAR,position,0).value as i32;
                    if line<0 {return Err(RuntimeError::new(Kind::HostFailure,
                        "native edit returned no line for a checked character index"));}
                    let start=invoke_message(invocation,hwnd,EM_LINEINDEX,line as usize,0).value as i32;
                    if start<0 {return Err(RuntimeError::new(Kind::HostFailure,
                        "native edit returned no start for a checked line"));}
                    let end=(start as usize).checked_add(native_length as usize)
                        .filter(|end|*end<=map.native_len()).ok_or_else(||RuntimeError::new(
                            Kind::HostFailure,"native edit line range exceeds its owned text snapshot"))?;
                    let guest_start=map.native_to_guest(start as usize)?;
                    let guest_end=map.native_to_guest(end)?;
                    u32::try_from(guest_end.checked_sub(guest_start).ok_or_else(||RuntimeError::new(
                        Kind::HostFailure,"native edit line position map is reversed"))?).map_err(|_|
                        RuntimeError::new(Kind::CompatibilityGap,"guest edit line length exceeds the Win32 result range"))?
                }
            } else {
                invoke_message(invocation,hwnd,EM_LINELENGTH,*character as isize as usize,0).value
            };
            return Ok(Some(Win16HostMessageResult {value,output:runtime::Win16HostMessageOutput::None,
                dialog_result:None}));
        }
    }
    if matches!(&call.message,Message::Edit(Edit::GetPasswordCharacter)) {
        let native=invoke_message(invocation,hwnd,EM_GETPASSWORDCHAR,0,0);
        if super::win16_native_procedures::is_builtin_control_target(state,call.window,call.dispatch,
            runtime::Win16HostSystemClass::Edit)? && native.value!=0 {
            let native_char=u16::try_from(native.value).map_err(|_|RuntimeError::new(Kind::HostFailure,
                "native EDIT returned a password character outside the WCHAR range"))?;
            let value=password_char_to_guest(state,native_char)?;
            return Ok(Some(Win16HostMessageResult {value:u32::from(value),
                output:runtime::Win16HostMessageOutput::None,dialog_result:None}));
        }
        return Ok(Some(native));
    }
    let set_selection = matches!(&call.message, Message::Edit(Edit::SetSelection {..}));
    let limit_combo_text = matches!(&call.message, Message::ComboBox(Combo::LimitText { .. }));
    let scroll_selection = matches!(&call.message, Message::Edit(Edit::SetSelection {no_scroll:false,..}));
    let mut text = Vec::new();
    // Only owned text converted to native UTF-16 or opaque guest DWORD data becomes LPARAM.
    // No guest FAR pointer is representable in this native adapter.
    let mut item_param = |item: Item| -> Result<isize, RuntimeError> {
        let strings_bit = if call.expected.family == Family::ListBox { LBS_HASSTRINGS }
            else { CBS_HASSTRINGS } as u32;
        let strings = call.expected.style & 0x30 == 0 || call.expected.style & strings_bit != 0;
        if matches!(&item, Item::Text(_)) != strings {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "control item representation differs from its checked string style"));
        }
        match item {
            Item::ItemData(data) => Ok(data as usize as isize),
            Item::Text(bytes) => {
                if bytes.contains(&0) { return Err(RuntimeError::new(Kind::InvalidInput,
                    "control input text contains an embedded terminator")); }
                text = state.borrow().text_codec.to_wide_z(&bytes)?;
                Ok(text.as_ptr() as isize)
            }
        }
    };
    let edit_set_map=if matches!(&call.message,Message::Edit(Edit::SetSelection{..})) {
        super::win16_control_outputs::text_index_map_for_builtin(state,&call,hwnd,
            runtime::Win16HostSystemClass::Edit,invocation)?
    } else {None};
    let combo_set_map=if matches!(&call.message,Message::ComboBox(Combo::SetEditSelection{..})) {
        super::win16_control_outputs::text_index_map_for_builtin(state,&call,hwnd,
            runtime::Win16HostSystemClass::ComboBox,invocation)?
    } else {None};
    let (message, w, l) = match call.message {
        Message::Button(message) if call.expected.family == Family::Button => match message {
            Button::GetCheck => (BM_GETCHECK,0,0), Button::SetCheck{state} => (BM_SETCHECK,usize::from(state),0),
            Button::GetState => (BM_GETSTATE,0,0), Button::SetState{state} => (BM_SETSTATE,usize::from(state),0),
            Button::SetStyle{style,redraw} => (BM_SETSTYLE,usize::from(style),isize::from(redraw)),
        },
        Message::ListBox(message) if call.expected.family == Family::ListBox => match message {
            List::AddString{item} => (LB_ADDSTRING,0,item_param(item)?),
            List::InsertString{index,item} => (LB_INSERTSTRING,index as isize as usize,item_param(item)?),
            List::DeleteString{index} => (LB_DELETESTRING,usize::from(index),0),
            List::ResetContent => (LB_RESETCONTENT,0,0),
            List::SetSelection{select,index} => (LB_SETSEL,usize::from(select),isize::from(index)),
            List::SetCurrentSelection{index} => (LB_SETCURSEL,index as isize as usize,0),
            List::GetSelection{index} => (LB_GETSEL,usize::from(index),0),
            List::GetCurrentSelection => (LB_GETCURSEL,0,0),
            List::GetTextLength{index} => (LB_GETTEXTLEN,usize::from(index),0),
            List::GetCount => (LB_GETCOUNT,0,0),
            List::SelectString{start,item} => (LB_SELECTSTRING,start as isize as usize,item_param(item)?),
            List::GetTopIndex => (LB_GETTOPINDEX,0,0),
            List::FindString{start,item} => (LB_FINDSTRING,start as isize as usize,item_param(item)?),
            List::GetSelectionCount => (LB_GETSELCOUNT,0,0),
            List::GetHorizontalExtent => (LB_GETHORIZONTALEXTENT,0,0),
            List::SetHorizontalExtent{extent} => (LB_SETHORIZONTALEXTENT,usize::from(extent),0),
            List::SetColumnWidth{width} => (LB_SETCOLUMNWIDTH,usize::from(width),0),
            List::SetTopIndex{index} => (LB_SETTOPINDEX,usize::from(index),0),
            List::GetItemData{index} => (LB_GETITEMDATA,usize::from(index),0),
            List::SetItemData{index,data} => (LB_SETITEMDATA,usize::from(index),data as usize as isize),
            List::SelectItemRange{select,first,last} => (LB_SELITEMRANGE,usize::from(select),
                (u32::from(first)|(u32::from(last)<<16)) as usize as isize),
            List::SetCaretIndex{index,scroll} => (LB_SETCARETINDEX,usize::from(index),isize::from(scroll)),
            List::SetAnchorIndex{index} => (LB_SETANCHORINDEX,index as isize as usize,0),
            List::GetAnchorIndex => (LB_GETANCHORINDEX,0,0),
            List::GetCaretIndex => (LB_GETCARETINDEX,0,0),
            List::SetItemHeight{index,height} => (LB_SETITEMHEIGHT,usize::from(index),height as isize),
            List::GetItemHeight{index} => (LB_GETITEMHEIGHT,usize::from(index),0),
            List::FindStringExact{start,item} => (LB_FINDSTRINGEXACT,start as isize as usize,item_param(item)?),
            _ => return Ok(None),
        },
        Message::Edit(message) if call.expected.family == Family::Edit => match message {
            Edit::GetSelection => (EM_GETSEL,0,0),
            Edit::SetSelection{start,end,no_scroll:_} => {
                let start=map_guest_offset(edit_set_map.as_ref(),start)?;
                let end=map_guest_offset(edit_set_map.as_ref(),end)?;
                (EM_SETSEL,start as usize,end)
            },
            Edit::Scroll{command} => (EM_SCROLL,usize::from(command),0),
            Edit::LineScroll{vertical,horizontal} => (EM_LINESCROLL,horizontal as isize as usize,isize::from(vertical)),
            Edit::GetThumb => (EM_GETTHUMB,0,0),
            Edit::GetModify => (EM_GETMODIFY,0,0), Edit::SetModify{modified} => (EM_SETMODIFY,usize::from(modified),0),
            Edit::GetLineCount => (EM_GETLINECOUNT,0,0), Edit::LineIndex{line} => (EM_LINEINDEX,line as isize as usize,0),
            Edit::LineLength{character} => (EM_LINELENGTH,character as isize as usize,0),
            Edit::ReplaceSelection{text:bytes} => {
                if bytes.contains(&0) { return Err(RuntimeError::new(Kind::InvalidInput,
                    "edit replacement text contains an embedded terminator")); }
                drop(item_param);
                let text=state.borrow().text_codec.to_wide_z(&bytes)?;
                let ptr = text.as_ptr() as isize;
                // This owned buffer stays live throughout synchronous USER
                // dispatch, including nested callbacks.
                return Ok(Some(invoke_message(invocation, hwnd, EM_REPLACESEL, 0, ptr)));
            },
            Edit::LimitText{maximum} => {
                let preserve_zero=maximum==0;
                let maximum=if preserve_zero {u16::MAX} else {maximum};
                let codec=state.borrow().text_codec;
                let mut info=CPINFOEXW::default();
                // The code page is an explicit guest setting, never CP_ACP.
                let sbcs=unsafe {GetCPInfoExW(codec.code_page(),0,&mut info)}!=0 && info.MaxCharSize==1;
                if !preserve_zero && !sbcs {
                    super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
                        "multibyte EM_LIMITTEXT is applied as a Unicode character cap; future guest-byte enforcement needs input and IME interception");
                }
                (EM_LIMITTEXT,usize::from(maximum),0)
            },
            Edit::CanUndo => (EM_CANUNDO,0,0), Edit::Undo => (EM_UNDO,0,0),
            Edit::FormatLines{add_eol} => (EM_FMTLINES,usize::from(add_eol),0),
            Edit::LineFromCharacter{character} => (EM_LINEFROMCHAR,character as isize as usize,0),
            Edit::SetPasswordCharacter{character} => {
                let native_char=if character==0 {0} else if
                    super::win16_native_procedures::is_builtin_control_target(state,call.window,
                        call.dispatch,runtime::Win16HostSystemClass::Edit)? {
                    usize::from(password_char_to_wide(state,character)?)
                } else {usize::from(character)};
                (EM_SETPASSWORDCHAR,native_char,0)
            },
            Edit::EmptyUndoBuffer => (EM_EMPTYUNDOBUFFER,0,0),
            Edit::GetFirstVisibleLine => (EM_GETFIRSTVISIBLELINE,0,0),
            Edit::SetReadOnly{read_only} => (EM_SETREADONLY,usize::from(read_only),0),
            Edit::GetPasswordCharacter => (EM_GETPASSWORDCHAR,0,0), _ => return Ok(None),
        },
        Message::ComboBox(message) if call.expected.family == Family::ComboBox => match message {
            Combo::GetEditSelection => (CB_GETEDITSEL,0,0),
            // Win3.1 specifies 65,535 for zero; modern USER uses a larger limit.
            Combo::LimitText{maximum} => (CB_LIMITTEXT,usize::from(if maximum==0 {u16::MAX}else{maximum}),0),
            Combo::SetEditSelection{start,end} => {
                let start=i16::try_from(map_guest_offset(combo_set_map.as_ref(),start)?).map_err(|_|RuntimeError::new(
                    Kind::CompatibilityGap,"native combo selection start exceeds the packed Win16 range"))?;
                let end=i16::try_from(map_guest_offset(combo_set_map.as_ref(),end)?).map_err(|_|RuntimeError::new(
                    Kind::CompatibilityGap,"native combo selection end exceeds the packed Win16 range"))?;
                (CB_SETEDITSEL,0,(u32::from(start as u16)|(u32::from(end as u16)<<16)) as usize as isize)
            },
            Combo::AddString{item} => (CB_ADDSTRING,0,item_param(item)?),
            Combo::DeleteString{index} => (CB_DELETESTRING,usize::from(index),0),
            Combo::GetCount => (CB_GETCOUNT,0,0), Combo::GetCurrentSelection => (CB_GETCURSEL,0,0),
            Combo::GetTextLength{index} => (CB_GETLBTEXTLEN,usize::from(index),0),
            Combo::InsertString{index,item} => (CB_INSERTSTRING,index as isize as usize,item_param(item)?),
            Combo::ResetContent => (CB_RESETCONTENT,0,0),
            Combo::FindString{start,item} => (CB_FINDSTRING,start as isize as usize,item_param(item)?),
            Combo::SelectString{start,item} => (CB_SELECTSTRING,start as isize as usize,item_param(item)?),
            Combo::SetCurrentSelection{index} => (CB_SETCURSEL,index as isize as usize,0),
            Combo::ShowDropdown{show} => (CB_SHOWDROPDOWN,usize::from(show),0),
            Combo::GetItemData{index} => (CB_GETITEMDATA,usize::from(index),0),
            Combo::SetItemData{index,data} => (CB_SETITEMDATA,usize::from(index),data as usize as isize),
            Combo::SetItemHeight{index,height} => (CB_SETITEMHEIGHT,index as isize as usize,height as isize),
            Combo::GetItemHeight{index} => (CB_GETITEMHEIGHT,index as isize as usize,0),
            Combo::SetExtendedUi{extended} => (CB_SETEXTENDEDUI,usize::from(extended),0),
            Combo::GetExtendedUi => (CB_GETEXTENDEDUI,0,0), Combo::GetDroppedState => (CB_GETDROPPEDSTATE,0,0),
            Combo::FindStringExact{start,item} => (CB_FINDSTRINGEXACT,start as isize as usize,item_param(item)?),
            _ => return Ok(None),
        },
        _ => return Err(RuntimeError::new(Kind::InvalidInput,
            "typed control request does not match its queried family")),
    };
    let mut result = invoke_message(invocation,hwnd,message,w,l);
    // Win3.1 EM_SETSEL returns nonzero when sent to an EDIT. Win32 has
    // no return contract, so project success from the checked EDIT dispatch.
    if set_selection { result.value = 1; }
    if limit_combo_text { result.value = 1; }
    if scroll_selection && query(state, Win16HostControlQuery {window:call.window,dispatch:call.dispatch})?
        .identity == Some(call.expected) {
        invoke_message(invocation,hwnd,EM_SCROLLCARET,0,0);
    }
    Ok(Some(result))
}

fn map_guest_offset(map:Option<&super::win16_control_outputs::TextIndexMap>,offset:i16)
    ->Result<isize,RuntimeError> {
    if offset<0 {return Ok(isize::from(offset));}
    match map {
        Some(map)=>isize::try_from(map.guest_to_native(offset as usize)?).map_err(|_|
            RuntimeError::new(Kind::CompatibilityGap,"native control position exceeds host LPARAM range")),
        None=>Ok(isize::from(offset)),
    }
}

fn password_char_to_wide(state:&Rc<RefCell<WorkerState>>,character:u16)->Result<u16,RuntimeError> {
    let compatibility=||RuntimeError::new(Kind::CompatibilityGap,
        "guest password character is not representable as one native WCHAR");
    let byte=u8::try_from(character).map_err(|_| {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "guest password character exceeds one ANSI byte and cannot be mapped to WCHAR");
        compatibility()
    })?;
    let codec=state.borrow().text_codec;
    let converted=codec.to_wide(&[byte]).map_err(|error| {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "guest password character cannot be decoded from its selected code page");
        RuntimeError::with_source(Kind::CompatibilityGap,
            "guest password character cannot be decoded from its selected code page",error)
    })?;
    if converted.len()!=1 {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "guest password character does not map to one native WCHAR");
        return Err(compatibility());
    }
    Ok(converted[0])
}

fn password_char_to_guest(state:&Rc<RefCell<WorkerState>>,character:u16)->Result<u16,RuntimeError> {
    let codec=state.borrow().text_codec;
    let converted=codec.from_wide(&[character]).map_err(|error| {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "native password character cannot be encoded in the guest code page");
        RuntimeError::with_source(Kind::CompatibilityGap,
            "native password character cannot be encoded in the guest code page",error)
    })?;
    if converted.bytes.len()!=1 || converted.used_default_char==Some(true) {
        super::win16_window_position::report_diagnostic(state,Kind::CompatibilityGap,
            "native password character cannot be represented as one guest ANSI byte");
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            "native password character cannot be represented as one guest ANSI byte"));
    }
    Ok(u16::from(converted.bytes[0]))
}

fn line_length_guest_bytes(invocation:MessageInvocation,hwnd:windows_sys::Win32::Foundation::HWND,
    map:&super::win16_control_outputs::TextIndexMap)->Result<u32,RuntimeError> {
    let (mut selection_start,mut selection_end)=(u32::MAX,u32::MAX);
    let native=invoke_message(invocation,hwnd,EM_GETSEL,&mut selection_start as *mut u32 as usize,
        &mut selection_end as *mut u32 as isize);
    if native.value==u32::MAX || selection_start==u32::MAX || selection_end==u32::MAX
        || selection_start>selection_end || selection_end as usize>map.native_len() {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native EDIT returned invalid selection positions for EM_LINELENGTH(-1)"));
    }
    let (first_position,last_position)=if selection_start==selection_end {
        (selection_start,selection_start)
    } else {(selection_start,selection_end-1)};
    let first_line=invoke_message(invocation,hwnd,EM_LINEFROMCHAR,first_position as usize,0).value as i32;
    let last_line=invoke_message(invocation,hwnd,EM_LINEFROMCHAR,last_position as usize,0).value as i32;
    if first_line<0 || last_line<first_line
        || (last_line-first_line) as usize>runtime::WIN16_CONTROL_TEXT_CAPACITY.saturating_mul(2) {
        return Err(RuntimeError::new(Kind::HostFailure,
            "native EDIT returned an invalid line range for EM_LINELENGTH(-1)"));
    }
    let mut byte_count=0_usize;
    for line in first_line..=last_line {
        let line_start=invoke_message(invocation,hwnd,EM_LINEINDEX,line as usize,0).value as i32;
        if line_start<0 {return Err(RuntimeError::new(Kind::HostFailure,
            "native EDIT returned no start for a selected line"));}
        let line_start=line_start as usize;
        let line_length=invoke_message(invocation,hwnd,EM_LINELENGTH,line_start,0).value as i32;
        if line_length<0 {return Err(RuntimeError::new(Kind::HostFailure,
            "native EDIT returned a negative line length"));}
        let line_end=line_start.checked_add(line_length as usize).filter(|end|*end<=map.native_len())
            .ok_or_else(||RuntimeError::new(Kind::HostFailure,
                "native EDIT line range exceeds its owned text snapshot"))?;
        let mut add_range=|start:usize,end:usize|->Result<(),RuntimeError> {
            if end<=start {return Ok(());}
            let guest_start=map.native_to_guest(start)?;
            let guest_end=map.native_to_guest(end)?;
            byte_count=byte_count.checked_add(guest_end.checked_sub(guest_start).ok_or_else(||
                RuntimeError::new(Kind::HostFailure,"native EDIT text map is reversed"))?)
                .ok_or_else(||RuntimeError::new(Kind::CompatibilityGap,
                    "guest edit line byte count overflowed"))?;
            Ok(())
        };
        if selection_start==selection_end {
            add_range(line_start,line_end)?;
        } else {
            let before_end=(selection_start as usize).clamp(line_start,line_end);
            let after_start=(selection_end as usize).clamp(line_start,line_end);
            add_range(line_start,before_end)?;
            add_range(after_start,line_end)?;
        }
    }
    u32::try_from(byte_count).map_err(|_|RuntimeError::new(Kind::CompatibilityGap,
        "guest EM_LINELENGTH result exceeds the Win32 result range"))
}
