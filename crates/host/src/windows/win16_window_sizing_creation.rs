//! Restore bounds for windows created with WS_MINIMIZE.

use super::*;
use runtime::{Win16CreationId, Win16HostCreationData};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowPlacement, IsIconic, IsWindowVisible, SW_HIDE, SW_SHOWMINNOACTIVE, SetWindowPlacement,
    WINDOWPLACEMENT, WS_MINIMIZE,
};

pub(super) struct CreationFrame {
    id: u64,
    operation: u64,
    creation: Win16CreationId,
    window: Win16HostWindow,
    callback_depth: usize,
    constraints: Option<(SizingKey, Win16HostMinMaxInfo)>,
}

pub(in crate::windows::win16_windows) struct MinimizedCreation {
    state: Rc<RefCell<WorkerState>>,
    id: u64,
    window: Win16HostWindow,
    requested: Win16HostPoint,
}

impl MinimizedCreation {
    pub(in crate::windows::win16_windows) fn enter(
        state: &Rc<RefCell<WorkerState>>,
        creation: Win16CreationId,
        window: Win16HostWindow,
        data: &Win16HostCreationData,
    ) -> Result<Option<Self>, RuntimeError> {
        if data.style & (WS_MINIMIZE | WS_MINIMIZEBOX) != WS_MINIMIZE | WS_MINIMIZEBOX {
            return Ok(None);
        }
        let shared = Rc::clone(state);
        let mut state = state.borrow_mut();
        let Some(operation) = state.active_operations.last().map(|active| active.id) else {
            return Ok(None);
        };
        let callback_depth = state.live_callbacks.len();
        let contexts = &mut state.window_sizing_contexts;
        let id = contexts.next_id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "minimized creation sizing identity exhausted",
            )
        })?;
        contexts.creations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve minimized creation sizing context",
                error,
            )
        })?;
        contexts.next_id = id;
        contexts.creations.push(CreationFrame {
            id,
            operation,
            creation,
            window,
            callback_depth,
            constraints: None,
        });
        Ok(Some(Self {
            state: shared,
            id,
            window,
            requested: Win16HostPoint {
                x: i32::from(data.width),
                y: i32::from(data.height),
            },
        }))
    }

    pub(in crate::windows::win16_windows) fn finish(&self, hwnd: HWND) -> Result<(), RuntimeError> {
        let constraints = self
            .state
            .borrow()
            .window_sizing_contexts
            .creations
            .last()
            .filter(|frame| frame.id == self.id)
            .and_then(|frame| frame.constraints);
        let Some((key, info)) = constraints else {
            return Ok(());
        };
        if win16_window_identity::resolve(&self.state, self.window) != Some(hwnd)
            || key.hwnd != hwnd as usize
            || !self
                .state
                .borrow()
                .window_identity_cookies
                .get(&self.window)
                .is_some_and(|cookie| cookie.value == key.cookie)
        {
            return Ok(());
        }
        repair_restore_size(&self.state, self.window, hwnd, self.requested, info)
    }
}

pub(super) fn record(
    state: &mut WorkerState,
    key: SizingKey,
    creation: Option<runtime::Win16CreationId>,
    info: Win16HostMinMaxInfo,
) {
    if let Some(frame) = state.window_sizing_contexts.creations.last_mut()
        && frame.operation == key.operation
        && frame.window == key.window
        && Some(frame.creation) == creation
        && frame.callback_depth.checked_add(1) == Some(key.callback_depth)
        && frame.constraints.is_none()
    {
        // The initial checked reply belongs to this exact creation call.
        // Later defaults, nested creations and unrelated HWNDs cannot replace it.
        frame.constraints = Some((key, info));
    }
}

pub(in crate::windows::win16_windows) fn repair_restore_size(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    requested: Win16HostPoint,
    info: Win16HostMinMaxInfo,
) -> Result<(), RuntimeError> {
    if win16_window_identity::resolve(state, window) != Some(hwnd) || unsafe { IsIconic(hwnd) } == 0
    {
        return Ok(());
    }
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as u32;
    if style & WS_MINIMIZEBOX == 0 {
        return Ok(());
    }
    let Some(legacy) = legacy_minimized_size() else {
        return Ok(());
    };
    let mut placement: WINDOWPLACEMENT = unsafe { std::mem::zeroed() };
    placement.length = std::mem::size_of::<WINDOWPLACEMENT>() as u32;
    if unsafe { GetWindowPlacement(hwnd, &mut placement) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "query minimized creation restore bounds",
        ));
    }
    let before = placement.rcNormalPosition;
    let Some(actual_width) = before.right.checked_sub(before.left) else {
        return Ok(());
    };
    let Some(actual_height) = before.bottom.checked_sub(before.top) else {
        return Ok(());
    };
    let width = restore_axis(
        requested.x,
        actual_width,
        unsafe { GetSystemMetrics(SM_CXMINIMIZED) },
        legacy.x,
        info.max_size.x,
    );
    let height = restore_axis(
        requested.y,
        actual_height,
        unsafe { GetSystemMetrics(SM_CYMINIMIZED) },
        legacy.y,
        info.max_size.y,
    );
    let Some(right) = before.left.checked_add(width) else {
        return Ok(());
    };
    let Some(bottom) = before.top.checked_add(height) else {
        return Ok(());
    };
    if right == before.right && bottom == before.bottom {
        return Ok(());
    }
    placement.rcNormalPosition.right = right;
    placement.rcNormalPosition.bottom = bottom;
    // SetWindowPlacement otherwise shows an initially hidden minimized window
    // or activates a visible one. Keep visibility and avoid activation.
    placement.showCmd = if unsafe { IsWindowVisible(hwnd) } == 0 {
        SW_HIDE as u32
    } else {
        SW_SHOWMINNOACTIVE as u32
    };
    // Keep native flags and minimized position. Only the untouched
    // restore axes enlarged by the modern minimized default are projected.
    if win16_window_identity::resolve(state, window) == Some(hwnd)
        && unsafe { SetWindowPlacement(hwnd, &placement) } == 0
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "set legacy minimized creation restore bounds",
        ));
    }
    Ok(())
}

pub(super) fn restore_axis(
    requested: i32,
    actual: i32,
    native_minimum: i32,
    legacy_minimum: i32,
    maximum: i32,
) -> i32 {
    // CW_USEDEFAULT, zero/negative extents and bounds changed by creation-time
    // application work keep native placement. Never invent a missing extent.
    if requested <= 0 || actual != clamp(requested, native_minimum, maximum) {
        actual
    } else {
        clamp(requested, legacy_minimum, maximum)
    }
}

impl Drop for MinimizedCreation {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        if state
            .window_sizing_contexts
            .creations
            .last()
            .is_some_and(|frame| frame.id == self.id)
        {
            state.window_sizing_contexts.creations.pop();
        } else {
            drop(state);
            super::super::win16_window_callbacks::fail_worker(
                &self.state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "minimized creation sizing contexts did not unwind in LIFO order",
                ),
            );
        }
    }
}
