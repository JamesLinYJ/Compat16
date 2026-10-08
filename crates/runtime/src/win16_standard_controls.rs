//! Windows 3.1 control messages: family first, then guest argument decoding.

use guest_core::memory::Memory;
use win16_abi::{MAX_WIN16_STRING_BYTES, strings::read_ansi_z};
use super::Win16State;
use super::messages::MessageOutput;
use super::guest_ranges::GuestOutputRange;
use crate::{RuntimeError, RuntimeHost, Diagnostic, DiagnosticKind as Kind,
    Win16HostControlQuery, Win16HostControlDispatch as Dispatch,
    Win16HostControlFamily as Family, Win16HostControlIdentity, Win16HostControlItem as Item,
    Win16HostControlMessage as Message, Win16HostControlCall,
    Win16HostButtonMessage as Button, Win16HostEditMessage as Edit,
    Win16HostListBoxMessage as List, Win16HostComboBoxMessage as Combo,
    Win16HostProcedure, Win16HostMessage};

impl Win16State {
    pub(super) fn control_identity(&self, window: u16, procedure: Option<Win16HostProcedure>,
        host: &mut impl RuntimeHost) -> Result<Option<Win16HostControlIdentity>, RuntimeError> {
        let Some(&window) = self.window_handles.get(&window) else { return Ok(None); };
        let dispatch = procedure.map_or(Dispatch::Send, |procedure| Dispatch::CallWindowProc{procedure});
        let reply = host.win16_control_identity(Win16HostControlQuery {window,dispatch})?;
        if reply.window != window || reply.dispatch != dispatch {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "control identity reply changed its queried target"));
        }
        Ok(reply.identity)
    }

    pub(super) fn prepare_control_message(&self, window: u16, message: u16, w: u16, l: u32,
        procedure: Option<Win16HostProcedure>, identity: Win16HostControlIdentity,
        memory: &Memory, host: &mut impl RuntimeHost) -> Result<Option<(Win16HostMessage, MessageOutput)>, RuntimeError> {
        let Some(&native) = self.window_handles.get(&window) else { return Ok(None); };
        let text = |address| read_ansi_z(&self.selectors, memory, address, MAX_WIN16_STRING_BYTES)
            .map_err(crate::runtime_error);
        // WINDOWS.H 3.1: owner-draw 0x10/0x20; HASSTRINGS is 0x40 for
        // LISTBOX and 0x200 for COMBOBOX. Without strings LPARAM is opaque
        // application DWORD data, including zero and values resembling FARs.
        let item = || -> Result<Item, RuntimeError> {
            let strings = match identity.family {
                Family::ListBox => 0x40, Family::ComboBox => 0x200,
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "non-item control requested item conversion")),
            };
            if identity.style & 0x30 != 0 && identity.style & strings == 0 {
                Ok(Item::ItemData(l))
            } else { text(l).map(Item::Text) }
        };
        // Guest IDs come from Windows 3.1 WINDOWS.H, not Win32 constants.
        // Reserved IDs and unresolved pointer/handle contracts have no DTO.
        let mut output = MessageOutput::None;
        let mut capture = |size, shape| -> Result<u32, RuntimeError> {
            let pointer = self.selectors.pointer_from_far(l).map_err(crate::runtime_error)?;
            let size = if let Some(size) = size { size } else {
                let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
                descriptor.limit.checked_sub(u32::from(pointer.offset()))
                    .and_then(|n| n.checked_add(1)).ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                        "control output pointer exceeds its selector"))?
                    .min(MAX_WIN16_STRING_BYTES as u32) as usize
            };
            if size == 0 || l == 0 { return Err(RuntimeError::new(Kind::GuestFault,
                "control output requires a nonempty guest write range")); }
            let range = GuestOutputRange::capture(self, memory, pointer, size)?;
            output = MessageOutput::Control(ControlOutputPlan {range,shape});
            Ok(size as u32)
        };
        let read_ints = || -> Result<Vec<i16>, RuntimeError> {
            if w == 0 { return Ok(Vec::new()); }
            let pointer = self.selectors.pointer_from_far(l).map_err(crate::runtime_error)?;
            let mut bytes = vec![0;usize::from(w)*2];
            self.selectors.read(memory,pointer,&mut bytes).map_err(crate::runtime_error)?;
            // These are WORD element arrays, not a packed native structure.
            Ok(bytes.chunks_exact(2).map(|pair| i16::from_le_bytes([pair[0],pair[1]])).collect())
        };
        let rect = || -> Result<crate::Win16HostRect, RuntimeError> {
            let pointer = self.selectors.pointer_from_far(l).map_err(crate::runtime_error)?;
            let r = self.read_rect16(memory,pointer)?;
            Ok(crate::Win16HostRect {left:i32::from(r.left),top:i32::from(r.top),
                right:i32::from(r.right),bottom:i32::from(r.bottom)})
        };
        let decoded = match identity.family {
            Family::Button => Message::Button(match message {
                0x0400 => Button::GetCheck, 0x0401 => Button::SetCheck{state:w},
                0x0402 => Button::GetState, 0x0403 => Button::SetState{state:w},
                0x0404 => Button::SetStyle{style:w,redraw:l as u16 != 0},
                _ => return control_gap(host, identity.family, message),
            }),
            Family::ListBox => Message::ListBox(match message {
                0x0401 => List::AddString{item:item()?},
                0x0402 => List::InsertString{index:w as i16,item:item()?},
                0x0403 => List::DeleteString{index:w}, 0x0405 => List::ResetContent,
                0x0406 => List::SetSelection{select:w,index:l as i16},
                0x0407 => List::SetCurrentSelection{index:w as i16},
                0x0408 => List::GetSelection{index:w}, 0x0409 => List::GetCurrentSelection,
                0x040A => {
                    let strings = identity.style & 0x30 == 0 || identity.style & 0x40 != 0;
                    let capacity = capture(if strings {None} else {Some(4)},
                        if strings {ControlOutputShape::Text} else {ControlOutputShape::ItemData})?;
                    List::GetText{index:w,max_write_bytes:capacity}
                }
                0x040B if identity.style & 0x30 == 0 || identity.style & 0x40 != 0
                    => List::GetTextLength{index:w},
                0x040C => List::GetCount, 0x040D => List::SelectString{start:w as i16,item:item()?},
                0x040F => List::GetTopIndex, 0x0410 => List::FindString{start:w as i16,item:item()?},
                0x0411 => List::GetSelectionCount, 0x0414 => List::GetHorizontalExtent,
                0x0412 => {
                    if w == 0 { return Ok(Some((Win16HostMessage::Control(Win16HostControlCall {
                        window:native,expected:identity,
                        dispatch:procedure.map_or(Dispatch::Send,|procedure| Dispatch::CallWindowProc{procedure}),
                        message:Message::ListBox(List::GetSelectionItems{capacity:0}),
                    }),MessageOutput::None))); }
                    capture(Some(usize::from(w)*2),ControlOutputShape::Int16s)?;
                    List::GetSelectionItems{capacity:w}
                }
                0x0413 => List::SetTabStops{positions:read_ints()?},
                0x0415 => List::SetHorizontalExtent{extent:w}, 0x0416 => List::SetColumnWidth{width:w},
                0x0418 => List::SetTopIndex{index:w}, 0x041A => List::GetItemData{index:w},
                0x0419 => { capture(Some(win16_abi::window_geometry::Rect16::SIZE),ControlOutputShape::Rect)?;
                    List::GetItemRect{index:w} }
                0x041B => List::SetItemData{index:w,data:l},
                0x041C => List::SelectItemRange{select:w,first:l as u16,last:(l>>16) as u16},
                // The WOW16 internal WINDOWS.H exposes WM_USER+29/+30;
                // WINDOWSX.H passes the selection anchor as a signed int.
                // Windows owns the index validation and multi-select state.
                0x041D => List::SetAnchorIndex{index:w as i16},
                0x041E => List::GetAnchorIndex,
                0x041F => List::SetCaretIndex{index:w,scroll:l as u16 != 0},
                0x0420 => List::GetCaretIndex, 0x0421 => List::SetItemHeight{index:w,height:l as u16},
                0x0422 => List::GetItemHeight{index:w},
                0x0423 => List::FindStringExact{start:w as i16,item:item()?},
                _ => return control_gap(host, identity.family, message),
            }),
            Family::Edit => Message::Edit(match message {
                0x0400 => Edit::GetSelection,
                0x0401 => Edit::SetSelection{start:l as i16,end:(l>>16) as i16,no_scroll:w!=0},
                0x0402 => {capture(Some(win16_abi::window_geometry::Rect16::SIZE),ControlOutputShape::Rect)?; Edit::GetRect}
                0x0403 => Edit::SetRect{rect:rect()?}, 0x0404 => Edit::SetRectNoPaint{rect:rect()?},
                0x0406 => Edit::LineScroll{vertical:l as i16,horizontal:(l>>16) as i16},
                0x0408 => Edit::GetModify, 0x0409 => Edit::SetModify{modified:w!=0},
                0x040A => Edit::GetLineCount, 0x040B => Edit::LineIndex{line:w as i16},
                0x0411 => Edit::LineLength{character:w as i16},
                0x0412 => Edit::ReplaceSelection{text:text(l)?},
                0x0414 => {
                    let pointer = self.selectors.pointer_from_far(l).map_err(crate::runtime_error)?;
                    let mut word = [0;2]; self.selectors.read(memory,pointer,&mut word).map_err(crate::runtime_error)?;
                    let capacity = u16::from_le_bytes(word);
                    if capacity != 0 { capture(Some(usize::from(capacity)),ControlOutputShape::Bytes)?; }
                    Edit::GetLine{line:w,capacity}
                }
                0x0415 => Edit::LimitText{maximum:w}, 0x0416 => Edit::CanUndo, 0x0417 => Edit::Undo,
                0x0418 => Edit::FormatLines{add_eol:w!=0}, 0x0419 => Edit::LineFromCharacter{character:w as i16},
                0x041C => Edit::SetPasswordCharacter{character:w}, 0x041D => Edit::EmptyUndoBuffer,
                // Win3.1 EDIT tab positions are unsigned WORDs; LISTBOX
                // positions retain their separate signed-int contract.
                0x041B => Edit::SetTabStops{positions:read_ints()?.into_iter().map(|n| n as u16).collect()},
                0x041E => Edit::GetFirstVisibleLine, 0x041F => Edit::SetReadOnly{read_only:w!=0},
                0x0422 => Edit::GetPasswordCharacter,
                _ => return control_gap(host, identity.family, message),
            }),
            Family::ComboBox => Message::ComboBox(match message {
                0x0400 => Combo::GetEditSelection, 0x0401 => Combo::LimitText{maximum:w},
                0x0402 => Combo::SetEditSelection{start:l as i16,end:(l>>16) as i16},
                0x0403 => Combo::AddString{item:item()?}, 0x0404 => Combo::DeleteString{index:w},
                0x0406 => Combo::GetCount, 0x0407 => Combo::GetCurrentSelection,
                0x0408 => {
                    let strings = identity.style & 0x30 == 0 || identity.style & 0x200 != 0;
                    let capacity = capture(if strings {None} else {Some(4)},
                        if strings {ControlOutputShape::Text} else {ControlOutputShape::ItemData})?;
                    Combo::GetText{index:w,max_write_bytes:capacity}
                }
                0x0409 if identity.style & 0x30 == 0 || identity.style & 0x200 != 0 => Combo::GetTextLength{index:w},
                0x040A => Combo::InsertString{index:w as i16,item:item()?}, 0x040B => Combo::ResetContent,
                0x040C => Combo::FindString{start:w as i16,item:item()?},
                0x040D => Combo::SelectString{start:w as i16,item:item()?},
                0x040E => Combo::SetCurrentSelection{index:w as i16}, 0x040F => Combo::ShowDropdown{show:w!=0},
                0x0410 => Combo::GetItemData{index:w}, 0x0411 => Combo::SetItemData{index:w,data:l},
                0x0412 => {capture(Some(win16_abi::window_geometry::Rect16::SIZE),ControlOutputShape::Rect)?;
                    Combo::GetDroppedControlRect}
                0x0413 => Combo::SetItemHeight{index:w as i16,height:l as u16},
                0x0414 => Combo::GetItemHeight{index:w as i16}, 0x0415 => Combo::SetExtendedUi{extended:w!=0},
                0x0416 => Combo::GetExtendedUi, 0x0417 => Combo::GetDroppedState,
                0x0418 => Combo::FindStringExact{start:w as i16,item:item()?},
                _ => return control_gap(host, identity.family, message),
            }),
            Family::Static => return control_gap(host, identity.family, message),
        };
        Ok(Some((Win16HostMessage::Control(Win16HostControlCall {
            window:native, expected:identity,
            dispatch:procedure.map_or(Dispatch::Send, |procedure| Dispatch::CallWindowProc{procedure}),
            message:decoded,
        }), output)))
    }
}

fn control_gap(host: &mut impl RuntimeHost, family: Family, message: u16)
    -> Result<Option<(Win16HostMessage, MessageOutput)>, RuntimeError> {
    let name = match family { Family::Button=>"BUTTON",Family::Edit=>"EDIT",Family::ListBox=>"LISTBOX",
        Family::ComboBox=>"COMBOBOX",Family::Static=>"STATIC" };
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        format!("Win16 {name} message 0x{message:04X} has no parameter conversion; returned zero")));
    Ok(None)
}

pub(super) struct ControlOutputPlan {pub(super) range:GuestOutputRange, shape:ControlOutputShape}
#[derive(Clone,Copy)]
enum ControlOutputShape {Text,Bytes,Rect,Int16s,ItemData}

impl ControlOutputPlan {
    pub(super) fn encode(&self, output:&crate::Win16HostControlOutput, value:u32)
        -> Result<Vec<u8>,RuntimeError> {
        use crate::Win16HostControlOutput as Output;
        let invalid = || RuntimeError::new(Kind::InternalInvariant,
            "native control output differs from its captured guest contract");
        let bytes = match (self.shape,output) {
            (ControlOutputShape::Text,Output::AnsiZ(bytes)) if bytes.last()==Some(&0)
                && bytes.len()==value as usize+1 && !bytes[..bytes.len()-1].contains(&0) => bytes.clone(),
            (ControlOutputShape::Bytes,Output::Bytes(bytes)) if bytes.len()==value as usize => bytes.clone(),
            (ControlOutputShape::Rect,Output::Rect(r)) => win16_abi::window_geometry::Rect16 {
                left:i16::try_from(r.left).map_err(|_|invalid())?, top:i16::try_from(r.top).map_err(|_|invalid())?,
                right:i16::try_from(r.right).map_err(|_|invalid())?, bottom:i16::try_from(r.bottom).map_err(|_|invalid())?,
            }.encode().to_vec(),
            (ControlOutputShape::Int16s,Output::Int16s(items)) if items.len()==value as usize
                => items.iter().flat_map(|item|item.to_le_bytes()).collect(),
            (ControlOutputShape::ItemData,Output::ItemData(data)) if value==4 => data.to_le_bytes().to_vec(),
            _ => return Err(invalid()),
        };
        if bytes.len()>self.range.length() {return Err(invalid());}
        Ok(bytes)
    }
}
