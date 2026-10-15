//! Default host ports for native GDI resources and USER images.

macro_rules! graphics_runtime_host_ports {
    () => {
    fn win16_metafile(&mut self, _operation: crate::Win16HostMetafileOperation)
        -> Result<crate::Win16HostMetafileResult, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 metafile service is unavailable"))
    }
    fn win16_create_icon_masks(&mut self, _masks: &crate::Win16HostImageMasks)
        -> Result<Option<Win16HostIcon>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap, "host icon mask creation is unavailable"))
    }
    fn win16_create_cursor_masks(&mut self, _masks: &crate::Win16HostImageMasks, _x: i16, _y: i16)
        -> Result<Option<Win16HostCursor>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap, "host cursor mask creation is unavailable"))
    }
    fn win16_create_compatible_dc(&mut self, _source: Option<Win16HostDc>)
        -> Result<Option<Win16HostDc>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 compatible device context creation is unavailable"))
    }
    fn win16_acquire_screen_dc(&mut self, _whole_window: bool)
        -> Result<Option<Win16HostDc>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 screen DC acquisition is unavailable"))
    }
    fn win16_acquire_screen_dc_ex(&mut self, _region: Option<Win16HostGdiObject>, _flags: u32)
        -> Result<Option<Win16HostDc>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 extended screen DC acquisition is unavailable"))
    }
    fn win16_release_screen_dc(&mut self, _dc: Win16HostDc) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 screen DC release is unavailable"))
    }
    fn win16_cleanup_dc(&mut self, _dc: Win16HostDc) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 DC cleanup is unavailable"))
    }
    fn win16_cleanup_dc_state(&mut self, dc: Win16HostDc)
        -> Result<Win16HostGdiCleanup, RuntimeError> {
        self.win16_cleanup_dc(dc).map(|released| if released {
            Win16HostGdiCleanup::Released
        } else { Win16HostGdiCleanup::Failed })
    }
    fn win16_delete_dc(&mut self, _dc: Win16HostDc) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 device context deletion is unavailable"))
    }
    fn win16_get_device_caps(&mut self, _dc: Win16HostDc, _index: i16)
        -> Result<Option<i16>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 device capability query is unavailable"))
    }
    fn win16_enum_objects(&mut self, _dc: Win16HostDc, _object_type: i16)
        -> Result<Vec<crate::Win16HostGdiObjectRecord>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 GDI object enumeration is unavailable"))
    }
    fn win16_enum_fonts(&mut self, _dc: Win16HostDc, _face: Option<&[u8]>)
        -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 font enumeration is unavailable"))
    }
    fn win16_enum_font_families(&mut self, _dc: Win16HostDc, _face: Option<&[u8]>)
        -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 font family enumeration is unavailable"))
    }
    fn win16_get_stock_object(&mut self, _index: i16)
        -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 stock object lookup is unavailable"))
    }
    fn win16_select_object(&mut self, _dc: Win16HostDc, _object: Win16HostGdiObject)
        -> Result<Option<Win16SelectObjectResult>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 GDI object selection is unavailable"))
    }
    fn win16_delete_object(&mut self, _object: Win16HostGdiObject) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 GDI object deletion is unavailable"))
    }
    fn win16_cleanup_gdi_object(&mut self, object: Win16HostGdiObject)
        -> Result<Win16HostGdiCleanup, RuntimeError> {
        self.win16_delete_object(object).map(|released| if released {
            Win16HostGdiCleanup::Released
        } else { Win16HostGdiCleanup::Failed })
    }
    fn win16_load_system_icon(&mut self, _id: u16) -> Result<Option<Win16HostIcon>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 system icon lookup is unavailable"))
    }
    fn win16_select_icon_image(&mut self, _group: &[u8]) -> Result<Option<u16>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 icon image selection is unavailable"))
    }
    fn win16_select_icon_image_sized(
        &mut self,
        group: &[u8],
        _size: crate::Win16HostIconSize,
    ) -> Result<Option<u16>, RuntimeError> {
        self.win16_select_icon_image(group)
    }
    fn win16_create_icon(&mut self, _image: &[u8]) -> Result<Option<Win16HostIcon>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 icon creation is unavailable"))
    }
    fn win16_create_icon_sized(
        &mut self,
        image: &[u8],
        _size: crate::Win16HostIconSize,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.win16_create_icon(image)
    }
    fn win16_release_icon(&mut self, _icon: Win16HostIcon) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 icon release is unavailable"))
    }
    fn win16_load_system_cursor(&mut self, _id: u16) -> Result<Option<Win16HostCursor>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 system cursor lookup is unavailable"))
    }
    fn win16_select_cursor_image(&mut self, _group: &[u8]) -> Result<Option<u16>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 cursor image selection is unavailable"))
    }
    fn win16_create_cursor(&mut self, _image: &[u8]) -> Result<Option<Win16HostCursor>, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 cursor creation is unavailable"))
    }
    fn win16_release_cursor(&mut self, _cursor: Win16HostCursor) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 cursor release is unavailable"))
    }
    };
}
pub(super) use graphics_runtime_host_ports;
