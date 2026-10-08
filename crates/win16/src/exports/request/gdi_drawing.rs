//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiDrawingRequest {
    GetMapMode {
        dc: u16,
    },

    GetPolyFillMode {
        dc: u16,
    },

    SetPolyFillMode {
        dc: u16,
        mode: i16,
    },

    GetRop2 {
        dc: u16,
    },

    SetArcDirection {
        dc: u16,
        direction: i16,
    },

    GetArcDirection {
        dc: u16,
    },

    SetBrushOrg {
        dc: u16,
        x: i16,
        y: i16,
    },

    GetBrushOrg {
        dc: u16,
    },

    GetBrushOrgEx {
        dc: u16,
        output: u32,
    },

    GetDcOrg {
        dc: u16,
    },

    /// Drawing points/rectangles are checked, owned Win16 values. `output`
    /// fields below retain raw FAR values for runtime preflight/writeback.
    SetStretchBltMode {
        dc: u16,
        mode: i16,
    },

    GetStretchBltMode {
        dc: u16,
    },

    SetWindowExt {
        dc: u16,
        x: i16,
        y: i16,
    },

    SetWindowOrg {
        dc: u16,
        x: i16,
        y: i16,
    },

    SetViewportOrg {
        dc: u16,
        x: i16,
        y: i16,
    },

    SetViewportExt {
        dc: u16,
        x: i16,
        y: i16,
    },

    OffsetWindowOrg {
        dc: u16,
        x: i16,
        y: i16,
    },

    OffsetViewportOrg {
        dc: u16,
        x: i16,
        y: i16,
    },

    ScaleWindowExt {
        dc: u16,
        x_numerator: i16,
        x_denominator: i16,
        y_numerator: i16,
        y_denominator: i16,
    },

    ScaleViewportExt {
        dc: u16,
        x_numerator: i16,
        x_denominator: i16,
        y_numerator: i16,
        y_denominator: i16,
    },

    GetCurrentPosition {
        dc: u16,
    },

    GetViewportExt {
        dc: u16,
    },

    GetViewportOrg {
        dc: u16,
    },

    GetWindowExt {
        dc: u16,
    },

    GetWindowOrg {
        dc: u16,
    },

    Arc {
        dc: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
        start_x: i16,
        start_y: i16,
        end_x: i16,
        end_y: i16,
    },

    Pie {
        dc: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
        start_x: i16,
        start_y: i16,
        end_x: i16,
        end_y: i16,
    },

    Chord {
        dc: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
        start_x: i16,
        start_y: i16,
        end_x: i16,
        end_y: i16,
    },

    Ellipse {
        dc: u16,
        rect: Rect16,
    },

    RoundRect {
        dc: u16,
        rect: Rect16,
        ellipse_width: i16,
        ellipse_height: i16,
    },

    FloodFill {
        dc: u16,
        x: i16,
        y: i16,
        color: u32,
    },

    ExtFloodFill {
        dc: u16,
        x: i16,
        y: i16,
        color: u32,
        fill_type: u16,
    },

    OffsetClipRgn {
        dc: u16,
        x: i16,
        y: i16,
    },

    Polygon {
        dc: u16,
        count: i16,
        points: Vec<Point16>,
    },

    FillRgn {
        dc: u16,
        region: u16,
        brush: u16,
    },

    FrameRgn {
        dc: u16,
        region: u16,
        brush: u16,
        width: i16,
        height: i16,
    },

    InvertRgn {
        dc: u16,
        region: u16,
    },

    PaintRgn {
        dc: u16,
        region: u16,
    },

    SelectClipRgn {
        dc: u16,
        region: u16,
    },

    CombineRgn {
        destination: u16,
        source1: u16,
        source2: u16,
        mode: i16,
    },

    EqualRgn {
        first: u16,
        second: u16,
    },

    OffsetRgn {
        region: u16,
        x: i16,
        y: i16,
    },

    PtVisible {
        dc: u16,
        x: i16,
        y: i16,
    },

    GetRgnBox {
        region: u16,
        output: u32,
    },

    PtInRegion {
        region: u16,
        x: i16,
        y: i16,
    },

    SetRectRgn {
        region: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    GetClipRgn {
        dc: u16,
    },

    RectInRegion {
        region: u16,
        rect: Option<Rect16>,
    },

    PolyPolygon {
        dc: u16,
        polygon_count: u16,
        point_counts: Vec<i16>,
        points: Vec<Point16>,
        valid: bool,
    },

    PolyBezier {
        dc: u16,
        count: i16,
        points: Vec<Point16>,
        valid: bool,
    },

    PolyBezierTo {
        dc: u16,
        count: i16,
        points: Vec<Point16>,
        valid: bool,
    },

    AbortPath {
        dc: u16,
    },

    BeginPath {
        dc: u16,
    },

    CloseFigure {
        dc: u16,
    },

    EndPath {
        dc: u16,
    },

    FillPath {
        dc: u16,
    },

    FlattenPath {
        dc: u16,
    },

    PathToRegion {
        dc: u16,
    },

    StrokeAndFillPath {
        dc: u16,
    },

    StrokePath {
        dc: u16,
    },

    WidenPath {
        dc: u16,
    },

    GetPath {
        dc: u16,
        count: i16,
        output_points: u32,
        output_types: u32,
    },

    SelectClipPath {
        dc: u16,
        mode: u16,
    },

    ExtSelectClipRgn {
        dc: u16,
        region: u16,
        mode: i16,
    },

    ExcludeClipRect {
        dc: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    IntersectClipRect {
        dc: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    PatBlt {
        dc: u16,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        rop: u32,
    },

    SaveDC {
        dc: u16,
    },

    SetPixel {
        dc: u16,
        x: i16,
        y: i16,
        color: u32,
    },

    StretchBlt {
        destination: u16,
        destination_x: i16,
        destination_y: i16,
        width: i16,
        height: i16,
        source: u16,
        source_x: i16,
        source_y: i16,
        source_width: i16,
        source_height: i16,
        rop: u32,
    },

    Polyline {
        dc: u16,
        count: i16,
        points: Vec<Point16>,
    },

    RestoreDC {
        dc: u16,
        saved: i16,
    },

    DPtoLP {
        dc: u16,
        count: i16,
        points: Vec<Point16>,
        output: u32,
    },

    GetClipBox {
        dc: u16,
        output: u32,
    },

    GetPixel {
        dc: u16,
        x: i16,
        y: i16,
    },

    LPtoDP {
        dc: u16,
        count: i16,
        points: Vec<Point16>,
        output: u32,
    },

    RectVisible {
        dc: u16,
        rect: Option<Rect16>,
    },

    GetCurrentPositionEx {
        dc: u16,
        output: u32,
    },

    GetViewportOrgEx {
        dc: u16,
        output: u32,
    },

    GetViewportExtEx {
        dc: u16,
        output: u32,
    },

    GetWindowExtEx {
        dc: u16,
        output: u32,
    },

    GetWindowOrgEx {
        dc: u16,
        output: u32,
    },

    SetViewportExtEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    SetViewportOrgEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    SetWindowExtEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    SetWindowOrgEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    OffsetViewportOrgEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    OffsetWindowOrgEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    ScaleViewportExtEx {
        dc: u16,
        x_numerator: i16,
        x_denominator: i16,
        y_numerator: i16,
        y_denominator: i16,
        output: u32,
    },

    ScaleWindowExtEx {
        dc: u16,
        x_numerator: i16,
        x_denominator: i16,
        y_numerator: i16,
        y_denominator: i16,
        output: u32,
    },

    MoveToEx {
        dc: u16,
        x: i16,
        y: i16,
        output: u32,
    },

    /// Enumerate signed-coordinate line points through a checked guest FAR callback.
    LineDda {
        x_start: i16,
        y_start: i16,
        x_end: i16,
        y_end: i16,
        callback: u32,
        data: u32,
    },

    /// Perform the Win16 GDI signed 16-bit multiply/divide operation.
    MulDiv {
        multiplicand: i16,
        multiplier: i16,
        divisor: i16,
    },

    /// Set the guest DC mapping mode; the previous signed INT16 is returned in AX.
    SetMapMode {
        dc: u16,
        mode: i16,
    },

    /// Set the guest DC raster operation mode; the previous signed INT16 is returned in AX.
    SetRop2 {
        dc: u16,
        mode: i16,
    },

    /// Draw a line to the supplied signed Win16 coordinates.
    LineTo {
        dc: u16,
        x: i16,
        y: i16,
    },

    /// Move the current point, returning the prior packed POINT in DX:AX.
    MoveTo {
        dc: u16,
        x: i16,
        y: i16,
    },

    /// Draw a rectangle using signed Win16 coordinates.
    Rectangle {
        dc: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    /// Copy a raster operation between guest DCs. A zero source handle is
    /// preserved for source-free ROPs; runtime maps it to host None.
    BitBlt {
        destination: u16,
        destination_x: i16,
        destination_y: i16,
        width: i16,
        height: i16,
        source: u16,
        source_x: i16,
        source_y: i16,
        rop: u32,
    },
}
