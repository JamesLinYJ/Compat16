//! Native WM_DDE endpoint operations on the existing USER worker.

use std::cell::RefCell;
use std::os::windows::io::AsRawHandle;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16ClassicDdeAtom,
    Win16ClassicDdeCallbackSource,
    Win16ClassicDdeConversationId, Win16ClassicDdeDeliveryKind,
    Win16ClassicDdeAckStatus, Win16ClassicDdeAckValue, Win16ClassicDdeTransactionId,
    Win16ClassicDdeEventId, Win16ClassicDdeMessage,
    Win16ClassicDdeOperationIdentity, Win16ClassicDdeOperationId,
    Win16ClassicDdeTransferId, Win16HostClassicDdeCall, Win16HostClassicDdeNativeWindow,
    Win16HostClassicDdeCallbackFrame, Win16HostClassicDdeCallbackReply,
    Win16HostClassicDdeCallbackResult, Win16HostClassicDdeCallbackStep,
    Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent,
    Win16HostClassicDdePeer, Win16HostClassicDdeResult,
    Win16HostClassicDdeSourceRetiredProof, Win16HostClassicDdeStep,
    Win16HostCallback,
    Win16HostWindowOperationId, Win16WindowStep,
};
use windows_sys::Win32::Foundation::{
    GetLastError, GlobalFree, HGLOBAL, HWND, LPARAM, LRESULT, WPARAM,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::SetEvent;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetWindowThreadProcessId,
    InSendMessage, IsWindow, PeekMessageW, PostMessageW, RegisterClassExW, SendMessageW, UnregisterClassW,
    WNDCLASSEXW, HWND_BROADCAST, WM_APP, WM_NCDESTROY, WS_CHILD, WS_POPUP,
};

use super::{ActiveClassicDdeOperation, WorkerCommand, WorkerState};
use super::super::classic_dde::{callback_retirement, validate_callback_reply};
use crate::windows::win16_classic_dde_wire as wire;

const AFTER_CALLBACK_MESSAGE: u32 = WM_APP + 0x3e9;


#[path = "win16_classic_dde_worker_types.rs"]
mod worker_types;
#[path = "win16_classic_dde_worker_ingress.rs"]
mod ingress;
#[path = "win16_classic_dde_worker_receive.rs"]
mod receive;
#[path = "win16_classic_dde_worker_transactions.rs"]
mod transactions;
#[path = "win16_classic_dde_worker_outbound.rs"]
mod outbound;
#[path = "win16_classic_dde_worker_endpoints.rs"]
mod endpoints;
#[path = "win16_classic_dde_worker_callbacks.rs"]
mod callbacks;
#[path = "win16_classic_dde_worker_callback_retirement.rs"]
mod callback_retirement;
#[path = "win16_classic_dde_worker_quiescence.rs"]
mod quiescence;

pub(in crate::windows::win16_windows) use worker_types::*;
pub(super) use ingress::{begin_operation, resume_operation};
use ingress::window_proc;
pub(in crate::windows::win16_windows) use ingress::pump_internal_messages;
use receive::*;
use transactions::*;
use outbound::*;
use endpoints::*;
use callbacks::*;
use callback_retirement::*;
use quiescence::*;
