// Extend the USER scroll-bar records with the verified rectangle/icon APIs.
macro_rules! export_catalog_with_user_drawing_objects {
    ($($existing:tt)*) => {
        export_catalog_with_scroll_bars! {
            $($existing)*
            #[doc = "Windows SDK 3.1 declares InvertRect as void; the spec -ret16 modifier is metadata only."]
            UserInvertRect => USER_INVERT_RECT:
                ("USER", 82u16, Stack, user_drawing_objects::RECT_PARAMETERS, Void);
            UserFrameRect => USER_FRAME_RECT:
                ("USER", 83u16, Stack, user_drawing_objects::FRAME_RECT_PARAMETERS, Word);
            UserDrawIcon => USER_DRAW_ICON:
                ("USER", 84u16, Stack, user_drawing_objects::DRAW_ICON_PARAMETERS, Word);
            #[doc = "Windows SDK 3.1 declares DrawFocusRect as void; the spec -ret16 modifier is metadata only."]
            UserDrawFocusRect => USER_DRAW_FOCUS_RECT:
                ("USER", 466u16, Stack, user_drawing_objects::RECT_PARAMETERS, Void);
        }
    };
}
