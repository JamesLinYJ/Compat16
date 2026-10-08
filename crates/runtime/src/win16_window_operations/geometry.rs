//! USER geometry request marshalling.

use super::*;

impl Win16State {
    pub(super) fn begin_geometry_api(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16ApiRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16ApiRequest as Request;

        match request {
            Request::User(win16_abi::Win16UserRequest::Geometry(
                request @ (win16_abi::Win16UserGeometryRequest::GetWindowPlacement { .. }
                    | win16_abi::Win16UserGeometryRequest::SetWindowPlacement { .. }),
            )) => {
                use win16_abi::user_abi::WindowPlacement16;
                let (window, far, get) = match request {
                    win16_abi::Win16UserGeometryRequest::GetWindowPlacement { window, placement } =>
                        (window, placement, true),
                    win16_abi::Win16UserGeometryRequest::SetWindowPlacement { window, placement } =>
                        (window, placement, false),
                    _ => unreachable!(),
                };
                let pointer = self.checked_guest_range(far, WindowPlacement16::SIZE, Access::Read, memory)?;
                let mut bytes = [0; WindowPlacement16::SIZE];
                self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
                let placement = WindowPlacement16::decode(&bytes);
                // Both SDK 3.1 APIs require length = sizeof(WINDOWPLACEMENT).
                // Reject a guest version mismatch as ordinary API failure.
                if usize::from(placement.length) != WindowPlacement16::SIZE {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, return_kind);
                }
                let (call, output) = if get {
                    self.selectors.translate(pointer, Access::Write, WindowPlacement16::SIZE, memory)
                        .map_err(crate::runtime_error)?;
                    let output = super::super::guest_ranges::GuestOutputRange::capture(
                        self, memory, pointer, WindowPlacement16::SIZE,
                    )?;
                    (Win16WindowCall::GetWindowPlacement { window: self.native_window(window) },
                        Win16WindowCallOutput::Placement(output))
                } else {
                    let point = |p: Point16| Win16HostPoint { x: i32::from(p.x), y: i32::from(p.y) };
                    (Win16WindowCall::SetWindowPlacement {
                        window: self.native_window(window),
                        placement: crate::Win16WindowPlacement {
                            flags: u32::from(placement.flags),
                            show_command: u32::from(placement.show_command),
                            minimum: point(placement.minimum), maximum: point(placement.maximum),
                            normal: crate::Win16HostRect {
                                left: i32::from(placement.normal.left), top: i32::from(placement.normal.top),
                                right: i32::from(placement.normal.right), bottom: i32::from(placement.normal.bottom),
                            },
                        },
                    }, Win16WindowCallOutput::None)
                };
                self.submit_call(registers, memory, host, call, output, return_to, return_kind, None)
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::GetCursorPos { point },
            )) => {
                // SDK 3.1 WINDOWS.H declares void GetCursorPos(POINT FAR*).
                // Host POINT uses 32-bit coordinates; the shared POINT16 codec
                // and continuation writeback own guest narrowing and lifetime.
                let pointer = self.checked_guest_range(point, POINT16_SIZE, Access::Write, memory)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, POINT16_SIZE,
                )?;
                self.submit_call(
                    registers, memory, host, Win16WindowCall::GetCursorPos,
                    Win16WindowCallOutput::Point(output), return_to, return_kind, None,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::SetRect {
                    rect,
                    left,
                    top,
                    right,
                    bottom,
                },
            )) => {
                let pointer =
                    self.checked_guest_range(rect, Rect16::SIZE, Access::Write, memory)?;
                self.write_rect(
                    memory,
                    pointer,
                    Rect16 {
                        left,
                        top,
                        right,
                        bottom,
                    },
                )?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::SetRectEmpty { rect },
            )) => {
                let pointer =
                    self.checked_guest_range(rect, Rect16::SIZE, Access::Write, memory)?;
                self.write_rect(memory, pointer, Rect16::default())?;
                // USER.73 is declared void in the SDK; the export's -ret16
                // marker does not promise a meaningful guest return value.
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::CopyRect {
                    destination,
                    source,
                },
            )) => {
                let destination =
                    self.checked_guest_range(destination, Rect16::SIZE, Access::Write, memory)?;
                let source =
                    self.checked_guest_range(source, Rect16::SIZE, Access::Read, memory)?;
                // Read before writing so exact and partial aliases preserve the
                // source rectangle value.
                let rect = self.read_rect(memory, source)?;
                self.write_rect(memory, destination, rect)?;
                // USER.74 is declared void in the SDK; the export's -ret16
                // marker does not promise a meaningful guest return value.
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::IsRectEmpty { rect },
            )) => {
                let pointer = self.checked_guest_range(rect, Rect16::SIZE, Access::Read, memory)?;
                let rect = self.read_rect(memory, pointer)?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(is_rect_empty(rect)),
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::PtInRect { rect, x, y },
            )) => {
                let pointer = self.checked_guest_range(rect, Rect16::SIZE, Access::Read, memory)?;
                let rect = self.read_rect(memory, pointer)?;
                let contains = !is_rect_empty(rect)
                    && x >= rect.left
                    && x < rect.right
                    && y >= rect.top
                    && y < rect.bottom;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(contains),
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::OffsetRect { rect, x, y },
            )) => {
                let pointer =
                    self.checked_guest_range(rect, Rect16::SIZE, Access::Write, memory)?;
                let mut rect = self.read_rect(memory, pointer)?;
                rect.left = rect.left.wrapping_add(x);
                rect.right = rect.right.wrapping_add(x);
                rect.top = rect.top.wrapping_add(y);
                rect.bottom = rect.bottom.wrapping_add(y);
                self.write_rect(memory, pointer, rect)?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::InflateRect { rect, x, y },
            )) => {
                let pointer =
                    self.checked_guest_range(rect, Rect16::SIZE, Access::Write, memory)?;
                let mut rect = self.read_rect(memory, pointer)?;
                rect.left = rect.left.wrapping_sub(x);
                rect.right = rect.right.wrapping_add(x);
                rect.top = rect.top.wrapping_sub(y);
                rect.bottom = rect.bottom.wrapping_add(y);
                self.write_rect(memory, pointer, rect)?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::IntersectRect {
                    destination,
                    source1,
                    source2,
                },
            )) => {
                let destination =
                    self.checked_guest_range(destination, Rect16::SIZE, Access::Write, memory)?;
                let source1 =
                    self.checked_guest_range(source1, Rect16::SIZE, Access::Read, memory)?;
                let source2 =
                    self.checked_guest_range(source2, Rect16::SIZE, Access::Read, memory)?;
                // Read both sources before writing so aliasing the destination
                // with either input has the same value semantics.
                let first = self.read_rect(memory, source1)?;
                let second = self.read_rect(memory, source2)?;
                let left = first.left.max(second.left);
                let top = first.top.max(second.top);
                let right = first.right.min(second.right);
                let bottom = first.bottom.min(second.bottom);
                let intersects = left < right && top < bottom;
                let result = if intersects {
                    Rect16 {
                        left,
                        top,
                        right,
                        bottom,
                    }
                } else {
                    Rect16::default()
                };
                self.write_rect(memory, destination, result)?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(intersects),
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::UnionRect {
                    destination,
                    source1,
                    source2,
                },
            )) => {
                let destination =
                    self.checked_guest_range(destination, Rect16::SIZE, Access::Write, memory)?;
                let source1 =
                    self.checked_guest_range(source1, Rect16::SIZE, Access::Read, memory)?;
                let source2 =
                    self.checked_guest_range(source2, Rect16::SIZE, Access::Read, memory)?;
                // Snapshot both inputs before writeback: Win16 far pointers may
                // alias the output, including through distinct selectors.
                let first = self.read_rect(memory, source1)?;
                let second = self.read_rect(memory, source2)?;
                let first_empty = is_rect_empty(first);
                let second_empty = is_rect_empty(second);
                let (result, nonempty) = match (first_empty, second_empty) {
                    (true, true) => (Rect16::default(), false),
                    (false, true) => (first, true),
                    (true, false) => (second, true),
                    (false, false) => (
                        Rect16 {
                            left: first.left.min(second.left),
                            top: first.top.min(second.top),
                            right: first.right.max(second.right),
                            bottom: first.bottom.max(second.bottom),
                        },
                        true,
                    ),
                };
                self.write_rect(memory, destination, result)?;
                self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(nonempty),
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::GetWindowRect { window, rect },
            )) => {
                let pointer =
                    self.checked_guest_range(rect, Rect16::SIZE, Access::Write, memory)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, Rect16::SIZE,
                )?;
                let call = Win16WindowCall::GetWindowRect {
                    window: self.native_window(window),
                };
                self.submit_call(
                    registers,
                    memory,
                    host,
                    call,
                    Win16WindowCallOutput::WindowRect {
                        range: output,
                        api: "GetWindowRect",
                        guest_window: window,
                    },
                    return_to,
                    return_kind,
                    None,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::GetClientRect { window, rect },
            )) => {
                let pointer =
                    self.checked_guest_range(rect, Rect16::SIZE, Access::Write, memory)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, Rect16::SIZE,
                )?;
                let call = Win16WindowCall::GetClientRect {
                    window: self.native_window(window),
                };
                self.submit_call(
                    registers,
                    memory,
                    host,
                    call,
                    Win16WindowCallOutput::WindowRect {
                        range: output,
                        api: "GetClientRect",
                        guest_window: window,
                    },
                    return_to,
                    return_kind,
                    None,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::ClientToScreen { window, point },
            )) => {
                let pointer =
                    self.checked_guest_range(point, POINT16_SIZE, Access::Read, memory)?;
                self.selectors
                    .translate(pointer, Access::Write, POINT16_SIZE, memory)
                    .map_err(crate::runtime_error)?;
                let point = self.read_point(memory, pointer)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, POINT16_SIZE,
                )?;
                let host_point = Win16HostPoint {
                    x: i32::from(point.x),
                    y: i32::from(point.y),
                };
                let call = Win16WindowCall::ClientToScreen {
                    window: self.native_window(window),
                    point: host_point,
                };
                self.submit_call(
                    registers,
                    memory,
                    host,
                    call,
                    Win16WindowCallOutput::Point(output),
                    return_to,
                    return_kind,
                    None,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::ScreenToClient { window, point },
            )) => {
                let pointer =
                    self.checked_guest_range(point, POINT16_SIZE, Access::Read, memory)?;
                self.selectors
                    .translate(pointer, Access::Write, POINT16_SIZE, memory)
                    .map_err(crate::runtime_error)?;
                let point = self.read_point(memory, pointer)?;
                let output = super::super::guest_ranges::GuestOutputRange::capture(
                    self, memory, pointer, POINT16_SIZE,
                )?;
                let host_point = Win16HostPoint {
                    x: i32::from(point.x),
                    y: i32::from(point.y),
                };
                let call = Win16WindowCall::ScreenToClient {
                    window: self.native_window(window),
                    point: host_point,
                };
                self.submit_call(
                    registers,
                    memory,
                    host,
                    call,
                    Win16WindowCallOutput::Point(output),
                    return_to,
                    return_kind,
                    None,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::WindowFromPoint { x, y },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::WindowFromPoint {
                    point: Win16HostPoint {
                        x: i32::from(x),
                        y: i32::from(y),
                    },
                },
                return_to,
                return_kind,
            ),
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::SetWindowPos {
                    window,
                    insert_after,
                    x,
                    y,
                    width,
                    height,
                    flags,
                },
            )) => {
                host.observe_win16_io(&crate::Win16IoEvent::WindowPositionRequest {
                    window, insert_after, x, y, width, height, flags,
                });
                let Some(insert_after) = self.window_insert_after(insert_after) else {
                    return self.complete_return(
                        registers,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        0,
                        return_kind,
                    );
                };
                self.submit_value_call(
                    registers,
                    memory,
                    host,
                    Win16WindowCall::SetWindowPos {
                        window: self.native_window(window),
                        insert_after,
                        x,
                        y,
                        width,
                        height,
                        flags,
                    },
                    return_to,
                    return_kind,
                )
            }
            Request::User(win16_abi::Win16UserRequest::Geometry(
                win16_abi::Win16UserGeometryRequest::MoveWindow {
                    window,
                    x,
                    y,
                    width,
                    height,
                    repaint,
                },
            )) => self.submit_value_call(
                registers,
                memory,
                host,
                Win16WindowCall::MoveWindow {
                    window: self.native_window(window),
                    x,
                    y,
                    width,
                    height,
                    repaint: repaint != 0,
                },
                return_to,
                return_kind,
            ),
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-window request reached the Win16 window-operation bridge",
            )),
        }
    }
}
