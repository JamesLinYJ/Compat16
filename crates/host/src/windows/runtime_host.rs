//! Runtime services forwarded by the native Windows adapter.

use super::runtime_host_lz::lz_runtime_host_methods;
use super::runtime_host_ver::ver_runtime_host_methods;
use super::runtime_host_wave::wave_runtime_host_methods;
use super::win16_kernel_file_system;
use super::*;

#[path = "runtime_host_callbacks.rs"]
mod callbacks;
#[path = "runtime_host_mci.rs"]
mod mci;
#[path = "runtime_host_midi.rs"]
mod midi;
#[path = "runtime_host_netbios.rs"]
mod netbios;
#[path = "runtime_host_profile.rs"]
mod profile;

fn windows_error_code_description(native_error: Option<u32>) -> String {
    match native_error {
        Some(code) => format!("Windows error code {code}"),
        None => "Windows error code unavailable".to_owned(),
    }
}

impl RuntimeHost for WindowsHost {
    fn win16_program_load_result(&mut self, result: Result<(), u16>) -> Result<(), RuntimeError> {
        if let Some(reporter) = &self.program_load_reporter {
            reporter.report(result)?;
        }
        Ok(())
    }
    fn win16_yield_thread(&mut self) -> Result<(), RuntimeError> {
        if let Some(reporter) = &self.program_load_reporter { reporter.ready()?; }
        std::thread::yield_now();
        Ok(())
    }

    fn win16_com_owner(&mut self) -> Result<runtime::Win16ComHostOwnerIdentity, RuntimeError> {
        self.win16_windows.com_owner()
    }

    fn win16_com_shutdown(
        &mut self,
        owner: runtime::Win16ComHostOwnerIdentity,
        operation: runtime::Win16ComHostShutdownOperation,
    ) -> Result<runtime::Win16ComHostShutdownStep, RuntimeError> {
        self.win16_windows.shutdown_com(owner, operation)
    }

    fn win16_com_begin(
        &mut self,
        owner: runtime::Win16ComHostOwnerIdentity,
        start: runtime::Win16ComHostStart,
    ) -> Result<runtime::Win16ComHostStep, RuntimeError> {
        self.win16_windows.begin_com(&mut self.filesystem, owner, start)
    }

    fn win16_com_continue(
        &mut self,
        owner: runtime::Win16ComHostOwnerIdentity,
        continuation: runtime::Win16ComHostContinue,
    ) -> Result<runtime::Win16ComHostStep, RuntimeError> {
        self.win16_windows.continue_com_callback(owner, continuation)
    }

    fn win16_com_poll_callback(
        &mut self,
        owner: runtime::Win16ComHostOwnerIdentity,
    ) -> Result<Option<runtime::Win16ComHostStep>, RuntimeError> {
        self.win16_windows.poll_com_callback(owner)
    }

    fn win16_com_poll_terminal(
        &mut self,
        owner: runtime::Win16ComHostOwnerIdentity,
        operation: runtime::Win16ComHostOperationIdentity,
    ) -> Result<Option<runtime::Win16ComHostStep>, RuntimeError> {
        self.win16_windows.poll_com_terminal(owner, operation)
    }

    fn win16_com_acknowledge_terminal(
        &mut self,
        owner: runtime::Win16ComHostOwnerIdentity,
        operation: runtime::Win16ComHostOperationIdentity,
    ) -> Result<(), RuntimeError> {
        self.win16_windows.acknowledge_com_terminal(owner, operation)
    }

    fn win32_import(
        &mut self,
        call: runtime::Win32HostImportCall,
    ) -> Result<runtime::Win32HostImportResult, RuntimeError> {
        self.win32_imports.execute(call)
    }
    fn win16_output_debug_string(&mut self, message: &[u8]) -> Result<(), RuntimeError> {
        win16_kernel_diagnostics::output_debug_string(self.win16_dcs.text_codec(), message)
    }
    fn win16_ole2disp_conversion(
        &mut self,
        operation: runtime::Win16Ole2DispConversionOperation,
    ) -> Result<runtime::Win16Ole2DispConversionResult, RuntimeError> {
        win16_ole2disp::execute_conversion(operation, self.win16_dcs.text_codec())
    }
    fn win16_media_time(
        &mut self,
        operation: runtime::Win16HostMediaTimeOperation,
    ) -> Result<runtime::Win16HostMediaTimeResult, RuntimeError> {
        runtime_host_multimedia::media_time(self, operation)
    }
    fn win16_media_io(
        &mut self,
        operation: runtime::Win16HostMediaIoOperation,
    ) -> Result<runtime::Win16HostMediaIoResult, RuntimeError> {
        runtime_host_multimedia::media_io(self, operation)
    }
    fn win16_acm(
        &mut self,
        operation: runtime::Win16HostAcmOperation,
    ) -> Result<runtime::Win16HostAcmResult, RuntimeError> {
        self.win16_acm_direct
            .execute(operation, &self.win16_images, self.win16_dcs.text_codec())
    }
    wave_runtime_host_methods!();
    fn win16_network(
        &mut self,
        call: runtime::Win16HostNetworkCall,
    ) -> Result<runtime::Win16HostNetworkResult, RuntimeError> {
        Ok(self.win16_network.execute(call))
    }
    fn win16_peek_network_event(
        &mut self,
    ) -> Result<Option<runtime::Win16HostNetworkEvent>, RuntimeError> {
        self.win16_network.peek_network_event()
    }
    fn win16_ack_network_event(
        &mut self,
        source: runtime::Win16GuestNotificationSource,
    ) -> Result<(), RuntimeError> {
        self.win16_network.ack_network_event(source)
    }
    fn win16_ole2nls(
        &mut self,
        operation: runtime::Win16NlsOperation,
    ) -> Result<runtime::Win16NlsHostResult, RuntimeError> {
        win16_ole2nls::execute(operation, self.win16_dcs.text_codec())
    }
    fn win16_ime_profile(
        &mut self,
        call: runtime::Win16HostImeProfileCall,
    ) -> Result<runtime::Win16HostImeProfileResult, RuntimeError> {
        self.win16_windows.ime_profile(call)
    }
    fn win16_path_info(
        &mut self,
        operation: runtime::Win16HostPathInfoOperation,
    ) -> Result<runtime::Win16HostPathInfoResult, RuntimeError> {
        win16_path_info::execute(operation, self.code_page)
    }
    fn win16_file_system(
        &mut self,
        call: runtime::Win16HostFileSystemCall,
    ) -> Result<runtime::Win16HostFileSystemResult, RuntimeError> {
        win16_kernel_file_system::execute(&mut self.filesystem, &mut self.win16_file_system, call)
    }
    fn win16_ansi_code_page(&self) -> u32 {
        self.win16_dcs.text_codec().code_page()
    }
    fn decode_win16_ansi(&self, bytes: &[u8]) -> Result<String, RuntimeError> {
        let wide = self.win16_dcs.text_codec().to_wide(bytes)?;
        String::from_utf16(&wide).map_err(|error| {
            RuntimeError::with_source(Kind::InvalidInput, "decode Win16 task ANSI text", error)
        })
    }
    fn encode_win16_ansi(&self, text: &str) -> Result<Vec<u8>, RuntimeError> {
        let wide: Vec<u16> = text.encode_utf16().collect();
        let encoded = self.win16_dcs.text_codec().from_wide(&wide)?;
        if encoded.used_default_char == Some(true) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 task ANSI text is not representable without substitution",
            ));
        }
        Ok(encoded.bytes)
    }
    fn win16_dos_current_directory(
        &mut self,
        _owner: guest_core::OwnerId,
        path: &runtime::Win16CanonicalPath,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        let mut output = [0_u8; 64];
        let Ok(length) = self
            .filesystem
            .directory_get_current_canonical(path, &mut output)
        else {
            return Ok(None);
        };
        Ok(Some(output[..length].to_vec()))
    }
    fn win16_dos_path_bytes(
        &mut self,
        _owner: guest_core::OwnerId,
        path: &runtime::Win16CanonicalPath,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        Ok(self.filesystem.dos_path_bytes_for_canonical(path))
    }
    fn activate_win16_dos_directory(
        &mut self,
        _owner: guest_core::OwnerId,
        path: &runtime::Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        self.filesystem
            .directory_set_current_canonical(path, false)
            .map_err(|error| RuntimeError::from(dos_kernel::DosError::HostOperation(error)))
    }
    fn win16_shell_icons(
        &mut self,
        call: runtime::Win16HostShellIconCall,
    ) -> Result<runtime::Win16HostShellIconResult, RuntimeError> {
        self.win16_images.shell_icon_call(call)
    }
    fn win16_service_trace_enabled(&self) -> bool {
        self.win16_io_trace.is_some()
    }
    fn observe_win16_io(&mut self, event: &runtime::Win16IoEvent<'_>) {
        runtime_host_diagnostics::observe_win16_io(self, event)
    }
    fn win16_registry(
        &mut self,
        operation: runtime::Win16HostRegistryOperation,
    ) -> Result<runtime::Win16HostRegistryResult, RuntimeError> {
        self.win16_registry
            .execute(self.win16_dcs.text_codec(), operation)
    }
    fn win16_keyboard(
        &mut self,
        call: runtime::Win16HostKeyboardCall,
    ) -> Result<runtime::Win16HostKeyboardResult, RuntimeError> {
        self.win16_windows.keyboard(call)
    }
    fn win16_take_guest_callback(
        &mut self,
    ) -> Result<Option<runtime::Win16GuestCallbackEvent>, RuntimeError> {
        callbacks::take_guest_callback(self)
    }
    fn win16_scheduler_readiness(&self) -> Option<runtime::Win16SchedulerReadiness> {
        Some(runtime::Win16SchedulerReadiness {
            generation: self.win16_work_generation.load(std::sync::atomic::Ordering::Acquire),
            callback_pending: self.win16_callback_receiver.has_pending(),
        })
    }
    fn win16_guest_callback_sender(&self) -> Option<runtime::Win16GuestCallbackSender> {
        Some(self.win16_callback_sender.clone())
    }
    fn win16_register_window_message(&mut self, name: Option<&[u8]>) -> Result<u16, RuntimeError> {
        win16_registered_names::register_message(self.win16_dcs.text_codec(), name)
    }
    fn win16_register_clipboard_format(
        &mut self,
        name: Option<&[u8]>,
    ) -> Result<u16, RuntimeError> {
        win16_registered_names::register_clipboard_format(self.win16_dcs.text_codec(), name)
    }
    fn win16_clipboard_format_name(
        &mut self,
        format: u16,
        buffer: Vec<u8>,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        win16_registered_names::clipboard_format_name(self.win16_dcs.text_codec(), format, buffer)
    }
    fn win16_create_dc(
        &mut self,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&runtime::Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        runtime_host_gdi::create_dc(self, driver, device, output, devmode)
    }
    fn win16_create_ic(
        &mut self,
        driver: Option<&[u8]>,
        device: Option<&[u8]>,
        output: Option<&[u8]>,
        devmode: Option<&runtime::Win16HostDevMode>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        runtime_host_gdi::create_ic(self, driver, device, output, devmode)
    }
    fn win16_get_outline_text_metrics(
        &mut self,
        dc: Win16HostDc,
    ) -> Result<Option<runtime::Win16HostOutlineTextMetrics>, RuntimeError> {
        self.win16_dcs.get_outline_text_metrics(dc)
    }
    fn win16_get_text_metrics(
        &mut self,
        dc: Win16HostDc,
    ) -> Result<Option<runtime::Win16HostTextMetrics>, RuntimeError> {
        runtime_host_gdi::get_text_metrics(self, dc)
    }
    fn win16_get_text_face(
        &mut self,
        dc: Win16HostDc,
        count: i16,
        output: Option<Vec<u8>>,
    ) -> Result<Option<runtime::Win16HostTextFace>, RuntimeError> {
        runtime_host_gdi::get_text_face(self, dc, count, output)
    }
    fn win16_gdi(
        &mut self,
        operation: runtime::Win16DrawingOperation,
    ) -> Result<runtime::Win16DrawingResult, RuntimeError> {
        runtime_host_gdi::execute_drawing(self, operation)
    }
    fn win16_create_gdi_object(
        &mut self,
        operation: runtime::Win16GdiObjectOperation,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        runtime_host_gdi::create_object(self, operation)
    }
    fn win16_gdi_bitmap(
        &mut self,
        operation: runtime::Win16GdiBitmapOperation,
    ) -> Result<runtime::Win16GdiBitmapResult, RuntimeError> {
        runtime_host_gdi::execute_bitmap_transfer(self, operation)
    }
    fn win16_gdi_device(
        &mut self,
        operation: runtime::Win16GdiDeviceOperation,
    ) -> Result<runtime::Win16GdiDeviceResult, RuntimeError> {
        runtime_host_gdi::execute_device(self, operation)
    }
    fn win16_gdi_services(
        &mut self,
        operation: runtime::Win16GdiServicesOperation,
    ) -> Result<runtime::Win16GdiServicesResult, RuntimeError> {
        win16_gdi_services::execute(
            &self.win16_dcs,
            &mut self.win16_objects,
            &mut self.filesystem,
            operation,
        )
    }
    fn win16_metafile(
        &mut self,
        operation: runtime::Win16HostMetafileOperation,
    ) -> Result<runtime::Win16HostMetafileResult, RuntimeError> {
        match runtime_host_gdi::execute_metafile(self, operation) {
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                self.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "WMF playback requires an unsupported Escape payload translation")
                    .with_cause(error));
                Ok(runtime::Win16HostMetafileResult::Played(false))
            }
            result => result,
        }
    }
    fn win16_printer_capabilities(
        &mut self,
        request: runtime::Win16PrinterCapabilities,
    ) -> Result<runtime::Win16PrinterCapabilitiesResult, RuntimeError> {
        win16_printer::capabilities(request, self.win16_dcs.text_codec().code_page())
    }
    lz_runtime_host_methods!();
    ver_runtime_host_methods!();
    fn win16_read_module(
        &mut self,
        name: &[u8],
        application_path: &[u8],
    ) -> Result<Result<runtime::Win16ModuleImage, u16>, RuntimeError> {
        runtime_host_diagnostics::read_win16_module(self, name, application_path)
    }
    fn win16_read_program_image(
        &mut self, input: &runtime::Win16HostProgramLoadInput,
    ) -> Result<Result<runtime::Win16ModuleImage, u16>, RuntimeError> {
        win16_program_launch::read_image(self, input)
    }
    fn win16_read_task_module(
        &mut self,
        name: &[u8],
        application_path: &[u8],
        path: &runtime::Win16GuestPath,
    ) -> Result<Result<runtime::Win16ModuleImage, u16>, RuntimeError> {
        runtime_host_diagnostics::read_win16_task_module(self, name, application_path, path)
    }
    fn win16_classify_character(
        &mut self,
        value: u8,
        classification: runtime::Win16CharacterClassification,
    ) -> Result<bool, RuntimeError> {
        win16_text::classify_character(self.win16_dcs.text_codec(), value, classification)
    }
    fn win16_ansi_lower_char(&mut self, value: u16) -> Result<u16, RuntimeError> {
        win16_text::ansi_lower_char(self.win16_dcs.text_codec(), value)
    }
    fn win16_ansi_lower_string(&mut self, source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        win16_text::ansi_lower_string(self.win16_dcs.text_codec(), source)
    }
    fn win16_ansi_case_string_in_place(
        &mut self,
        source: &[u8],
        upper: bool,
    ) -> Result<Vec<u8>, RuntimeError> {
        win16_text::ansi_case_string_in_place(self.win16_dcs.text_codec(), source, upper)
    }
    fn win16_ansi_upper_char(&mut self, value: u16) -> Result<u16, RuntimeError> {
        win16_text::ansi_upper_char(self.win16_dcs.text_codec(), value)
    }
    fn win16_ansi_upper_string(&mut self, source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        win16_text::ansi_upper_string(self.win16_dcs.text_codec(), source)
    }
    fn win16_ansi_case_buffer(
        &mut self,
        source: &[u8],
        upper: bool,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        win16_text::ansi_case_buffer(self.win16_dcs.text_codec(), source, upper)
    }
    fn win16_ansi_compare(
        &mut self,
        left: &[u8],
        right: &[u8],
        ignore_case: bool,
    ) -> Result<i16, RuntimeError> {
        win16_text::ansi_compare(self.win16_dcs.text_codec(), left, right, ignore_case)
    }
    fn win16_ansi_next_probe(
        &mut self, source: &[u8],
    ) -> Result<runtime::Win16AnsiNextProbe, RuntimeError> {
        self.win16_dcs.text_codec().next_character_probe(source)
    }
    fn win16_ansi_prev_offset(
        &mut self,
        source: &[u8],
        current: usize,
    ) -> Result<usize, RuntimeError> {
        win16_text::ansi_prev_offset(self.win16_dcs.text_codec(), source, current)
    }
    fn win16_oem_to_ansi(&mut self, source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        win16_keyboard::oem_to_ansi(self.win16_dcs.text_codec(), source, self.code_page)
    }
    fn win16_initialize_user_queue(&mut self) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_initialize_user_queue(self)
    }

    fn win16_bind_task_queue(
        &mut self,
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
    ) -> Result<Option<runtime::Win16HostTaskQueue>, RuntimeError> {
        runtime_host_windows::win16_bind_task_queue(
            self,
            owner,
            guest_htask,
            task_selector_generation,
        )
    }

    fn win16_retire_task_queue(
        &mut self,
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
        queue: runtime::Win16HostTaskQueue,
    ) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_retire_task_queue(
            self,
            owner,
            guest_htask,
            task_selector_generation,
            queue,
        )
    }
    fn win16_register_window_class(
        &mut self,
        spec: Win16HostClassSpec,
    ) -> Result<Option<Win16RegisteredClass>, RuntimeError> {
        runtime_host_windows::win16_register_window_class(self, spec)
    }
    fn win16_system_class_info(
        &mut self,
        kind: runtime::Win16HostSystemClass,
    ) -> Result<Option<runtime::Win16HostSystemClassInfo>, RuntimeError> {
        self.win16_windows
            .system_class_info(kind, &self.win16_images, &mut self.win16_objects)
    }
    fn win16_control_identity(
        &mut self,
        query: runtime::Win16HostControlQuery,
    ) -> Result<runtime::Win16HostControlQueryReply, RuntimeError> {
        self.win16_windows.control_identity(query)
    }
    fn win16_window_enumeration(
        &mut self,
        query: runtime::Win16WindowEnumerationQuery,
    ) -> Result<runtime::Win16WindowEnumerationReply, RuntimeError> {
        self.win16_windows.window_enumeration(query)
    }
    fn win16_unregister_window_class(
        &mut self,
        class: Win16HostClass,
    ) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_unregister_window_class(self, class)
    }
    fn win16_replace_class_resource(
        &mut self,
        class: Win16HostClass,
        window: runtime::Win16HostWindow,
        resource: runtime::Win16HostClassResource,
    ) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_replace_class_resource(self, class, window, resource)
    }
    fn win16_window_begin(
        &mut self,
        operation: Win16WindowOperation,
    ) -> Result<Win16WindowStep, RuntimeError> {
        runtime_host_windows::win16_window_begin(self, operation)
    }
    fn win16_window_resume(
        &mut self,
        reply: Option<Win16WindowReply>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        runtime_host_windows::win16_window_resume(self, reply)
    }
    fn win16_classic_dde_begin(
        &mut self,
        call: runtime::Win16HostClassicDdeCall,
    ) -> Result<runtime::Win16HostClassicDdeStep, RuntimeError> {
        self.win16_windows.classic_dde_begin(call)
    }
    fn win16_classic_dde_resume(
        &mut self,
        resume: runtime::Win16HostClassicDdeResume,
    ) -> Result<runtime::Win16HostClassicDdeStep, RuntimeError> {
        self.win16_windows.classic_dde_resume(resume)
    }
    fn win16_classic_dde_source_retirement_consumed(
        &mut self,
        proof: &runtime::Win16HostClassicDdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        self.win16_windows
            .classic_dde_source_retirement_consumed(proof)
    }
    fn win16_take_native_drop_retirement(
        &mut self,
    ) -> Result<Option<runtime::Win16HostDropRetirementReceipt>, RuntimeError> {
        runtime_host_windows::win16_take_native_drop_retirement(self)
    }
    fn win16_ack_native_drop_retirement(
        &mut self,
        receipt: runtime::Win16HostDropRetirementReceipt,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_ack_native_drop_retirement(self, receipt)
    }
    fn win16_window_receive_pending(&mut self) -> Result<Win16WindowStep, RuntimeError> {
        runtime_host_windows::win16_window_receive_pending(self)
    }
    fn win16_window_resume_modal_guest_work(
        &mut self,
        operation_id: runtime::Win16HostWindowOperationId,
        scope_id: u64,
        generation: u64,
        marker_id: Option<u64>,
        wake_generation: Option<u64>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        runtime_host_windows::win16_window_resume_modal_guest_work(
            self,
            operation_id,
            scope_id,
            generation,
            marker_id,
            wake_generation,
        )
    }
    fn win16_window_terminal_ack(
        &mut self,
        ack: runtime::Win16WindowTerminalAck,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_window_terminal_ack(self, ack)
    }
    fn win16_window_terminal_acknowledged(
        &mut self,
        receipt: &runtime::Win16WindowAbortReceipt,
        ack: &runtime::Win16WindowTerminalAck,
    ) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_window_terminal_acknowledged(self, receipt, ack)
    }
    fn win16_window_terminal_source_top(
        &mut self,
        receipt: &runtime::Win16WindowAbortReceipt,
    ) -> Result<Option<runtime::Win16WindowTerminalSourceTop>, RuntimeError> {
        runtime_host_windows::win16_window_terminal_source_top(self, receipt)
    }
    fn win16_window_source_retirement(
        &mut self,
        operation: runtime::Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Option<std::sync::Arc<runtime::Win16WindowSourceRetiredProof>>, RuntimeError> {
        runtime_host_windows::win16_window_source_retirement(self, operation, worker_generation)
    }
    fn win16_window_retry_cached_completion(
        &mut self,
        operation: runtime::Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Win16WindowStep, RuntimeError> {
        runtime_host_windows::win16_window_retry_cached_completion(
            self,
            operation,
            worker_generation,
        )
    }
    fn win16_window_source_retirement_consumed(
        &mut self,
        proof: &runtime::Win16WindowSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_window_source_retirement_consumed(self, proof)
    }
    fn win16_window_abort(&mut self) -> Result<runtime::Win16WindowAbortReceipt, RuntimeError> {
        runtime_host_windows::win16_window_abort(self)
    }
    fn win16_ctl3d_frame(
        &mut self,
        window: runtime::Win16HostWindow,
    ) -> Result<Option<runtime::Win16HostCtl3dFrameFacts>, RuntimeError> {
        self.win16_windows.ctl3d_frame(window)
    }
    fn win16_destroy_window(&mut self, window: Win16HostWindow) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_destroy_window(self, window)
    }
    fn win16_host_window_liveness(
        &mut self,
        window: Win16HostWindow,
    ) -> Result<runtime::Win16HostWindowLiveness, RuntimeError> {
        runtime_host_windows::win16_host_window_liveness(self, window)
    }
    fn win16_host_window_parent(
        &mut self,
        window: Win16HostWindow,
    ) -> Result<runtime::Win16HostWindowParentObservation, RuntimeError> {
        runtime_host_windows::win16_host_window_parent(self, window)
    }
    fn win16_file_create(
        &mut self,
        path: &runtime::Win16GuestPath,
        attributes: u16,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        super::win16_file_paths::open(&mut self.filesystem, &mut self.win16_files,
            path, attributes, true)
    }
    fn win16_file_open(
        &mut self,
        path: &runtime::Win16GuestPath,
        mode: u16,
    ) -> Result<Option<Win16HostFile>, RuntimeError> {
        super::win16_file_paths::open(&mut self.filesystem, &mut self.win16_files,
            path, mode, false)
    }
    fn win16_open_file(
        &mut self, path: &runtime::Win16GuestPath, search_name: Option<&str>,
        style: u16, previous_ofstruct: Vec<u8>,
    ) -> Result<runtime::Win16HostOpenFile, RuntimeError> {
        super::win16_open_file::open(
            &mut self.filesystem, &mut self.win16_files, self.win16_dcs.text_codec(),
            path, search_name, style, previous_ofstruct,
        )
    }
    fn win16_file_read(
        &mut self,
        file: Win16HostFile,
        count: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.win16_files.read(file, count)
    }
    fn win16_file_seek(
        &mut self,
        file: Win16HostFile,
        offset: i32,
        origin: u16,
    ) -> Result<Option<i32>, RuntimeError> {
        self.win16_files.seek(file, offset, origin)
    }
    fn win16_file_write(
        &mut self,
        file: Win16HostFile,
        data: &[u8],
    ) -> Result<Option<u32>, RuntimeError> {
        self.win16_files.write(file, data)
    }
    fn win16_file_close(
        &mut self,
        file: Win16HostFile,
    ) -> Result<runtime::Win16HostFileClose, RuntimeError> {
        self.win16_files.close(file)
    }
    fn win16_file_commit(&mut self, file: Win16HostFile) -> Result<(), DosHostError> {
        self.win16_files.commit(file)
    }
    fn win16_file_write_time(&mut self, file: Win16HostFile) -> Result<(u16, u16), DosHostError> {
        self.win16_files.write_time(file)
    }
    fn win16_file_set_write_time(
        &mut self,
        file: Win16HostFile,
        time: u16,
        date: u16,
    ) -> Result<(), DosHostError> {
        self.win16_files.set_write_time(file, time, date)
    }
    fn win16_file_dos_access(&mut self, file: Win16HostFile) -> Result<DosFileAccess, DosHostError> {
        self.win16_files.dos_access(file)
    }
    fn win16_dos_file_read(
        &mut self, file: Win16HostFile, output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        self.win16_files.dos_read(file, output)
    }
    fn win16_dos_file_write(
        &mut self, file: Win16HostFile, input: &[u8],
    ) -> Result<usize, DosHostError> {
        self.win16_files.dos_write(file, input)
    }
    fn win16_dos_file_seek(
        &mut self, file: Win16HostFile, offset: i32, origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        self.win16_files.dos_seek(file, offset, origin)
    }
    fn win16_dos_file_close(
        &mut self, file: Win16HostFile,
    ) -> Result<runtime::Win16HostFileClose, DosHostError> {
        self.win16_files.close_checked(file)
    }
    fn win16_drive_kind(
        &mut self,
        drive: u16,
    ) -> Result<runtime::Win16HostDriveKind, RuntimeError> {
        Ok(win16_storage::drive_kind(drive))
    }
    fn win16_set_handle_count(&mut self, requested_count: u16) -> Result<u16, RuntimeError> {
        // Windows NT owns its native process handle table. This historical
        // API reports the available count; it does not resize the guest HFILE
        // token map or a DOS PSP's job-file table.
        let actual = unsafe {
            windows_sys::Win32::System::WindowsProgramming::SetHandleCount(u32::from(
                requested_count,
            ))
        };
        Ok(actual.min(u32::from(u16::MAX)) as u16)
    }
    fn win16_set_error_mode(&mut self, mode: u16) -> Result<u16, RuntimeError> {
        // Return the previous process flags truncated to the Win16 WORD.
        let previous = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(u32::from(mode))
        };
        Ok(previous as u16)
    }
    fn win16_create_compatible_dc(
        &mut self,
        source: Option<Win16HostDc>,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        runtime_host_gdi::create_compatible_dc(self, source)
    }
    fn win16_acquire_screen_dc(
        &mut self,
        whole_window: bool,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        runtime_host_gdi::acquire_screen_dc(self, whole_window)
    }
    fn win16_release_screen_dc(&mut self, dc: Win16HostDc) -> Result<bool, RuntimeError> {
        runtime_host_gdi::release_screen_dc(self, dc)
    }
    fn win16_acquire_screen_dc_ex(
        &mut self,
        region: Option<runtime::Win16HostGdiObject>,
        flags: u32,
    ) -> Result<Option<Win16HostDc>, RuntimeError> {
        super::win16_get_dc_ex::acquire_screen(
            &self.win16_dcs, &mut self.win16_objects, region, flags,
        )
    }
    fn win16_cleanup_dc(&mut self, dc: Win16HostDc) -> Result<bool, RuntimeError> {
        runtime_host_gdi::cleanup_dc(self, dc)
    }
    fn win16_cleanup_dc_state(
        &mut self,
        dc: Win16HostDc,
    ) -> Result<runtime::Win16HostGdiCleanup, RuntimeError> {
        runtime_host_gdi::cleanup_dc_state(self, dc)
    }
    fn win16_delete_dc(&mut self, dc: Win16HostDc) -> Result<bool, RuntimeError> {
        runtime_host_gdi::delete_dc(self, dc)
    }
    fn win16_get_device_caps(
        &mut self,
        dc: Win16HostDc,
        index: i16,
    ) -> Result<Option<i16>, RuntimeError> {
        runtime_host_gdi::device_caps(self, dc, index)
    }
    fn win16_enum_objects(
        &mut self,
        dc: Win16HostDc,
        object_type: i16,
    ) -> Result<Vec<runtime::Win16HostGdiObjectRecord>, RuntimeError> {
        runtime_host_gdi::enum_objects(self, dc, object_type)
    }
    fn win16_enum_fonts(
        &mut self,
        dc: Win16HostDc,
        face: Option<&[u8]>,
    ) -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        runtime_host_gdi::enum_fonts(self, dc, face)
    }

    fn win16_enum_font_families(
        &mut self,
        dc: Win16HostDc,
        face: Option<&[u8]>,
    ) -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        runtime_host_gdi::enum_font_families(self, dc, face)
    }
    fn win16_get_stock_object(
        &mut self,
        index: i16,
    ) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
        runtime_host_gdi::stock_object(self, index)
    }
    fn win16_select_object(
        &mut self,
        dc: Win16HostDc,
        object: Win16HostGdiObject,
    ) -> Result<Option<Win16SelectObjectResult>, RuntimeError> {
        runtime_host_gdi::select_object(self, dc, object)
    }
    fn win16_delete_object(&mut self, object: Win16HostGdiObject) -> Result<bool, RuntimeError> {
        runtime_host_gdi::delete_object(self, object)
    }
    fn win16_cleanup_gdi_object(
        &mut self,
        object: Win16HostGdiObject,
    ) -> Result<runtime::Win16HostGdiCleanup, RuntimeError> {
        runtime_host_gdi::cleanup_gdi_object(self, object)
    }
    fn win16_load_system_icon(&mut self, id: u16) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.win16_images.system_icon(id)
    }
    fn win16_select_icon_image(&mut self, group: &[u8]) -> Result<Option<u16>, RuntimeError> {
        Ok(win16_images::Win16Images::select_icon_image(group))
    }
    fn win16_select_icon_image_sized(
        &mut self,
        group: &[u8],
        size: runtime::Win16HostIconSize,
    ) -> Result<Option<u16>, RuntimeError> {
        Ok(win16_images::Win16Images::select_icon_image_sized(
            group, size,
        ))
    }
    fn win16_create_icon(&mut self, image: &[u8]) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.win16_images.create_icon(image)
    }
    fn win16_create_icon_sized(
        &mut self,
        image: &[u8],
        size: runtime::Win16HostIconSize,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.win16_images.create_icon_sized(image, size)
    }
    fn win16_create_icon_masks(
        &mut self,
        masks: &runtime::Win16HostImageMasks,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.win16_images.create_icon_masks(masks)
    }
    fn win16_create_cursor_masks(
        &mut self,
        masks: &runtime::Win16HostImageMasks,
        x: i16,
        y: i16,
    ) -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.win16_images.create_cursor_masks(masks, x, y)
    }
    fn win16_release_icon(&mut self, icon: Win16HostIcon) -> Result<(), RuntimeError> {
        self.win16_images.release_icon(icon)
    }
    fn win16_copy_icon(&mut self, icon: Win16HostIcon)
        -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.win16_images.copy_icon(icon)
    }
    fn win16_load_system_cursor(
        &mut self,
        id: u16,
    ) -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.win16_images.system_cursor(id)
    }
    fn win16_select_cursor_image(&mut self, group: &[u8]) -> Result<Option<u16>, RuntimeError> {
        Ok(win16_images::Win16Images::select_cursor_image(group))
    }
    fn win16_create_cursor(
        &mut self,
        image: &[u8],
    ) -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.win16_images.create_cursor(image)
    }
    fn win16_release_cursor(&mut self, cursor: Win16HostCursor) -> Result<(), RuntimeError> {
        self.win16_images.release_cursor(cursor)
    }
    fn win16_copy_cursor(&mut self, cursor: Win16HostCursor)
        -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.win16_images.copy_cursor(cursor)
    }
    fn win16_global_add_atom(&mut self, name: Win16HostAtomName<'_>) -> Result<u16, RuntimeError> {
        self.win16_atoms.add(self.win16_dcs.text_codec(), name)
    }
    fn win16_global_find_atom(&mut self, name: Win16HostAtomName<'_>) -> Result<u16, RuntimeError> {
        self.win16_atoms.find(self.win16_dcs.text_codec(), name)
    }
    fn win16_global_delete_atom(&mut self, atom: u16) -> Result<(), RuntimeError> {
        self.win16_atoms.delete(atom)
    }
    fn win16_global_get_atom_name(
        &mut self,
        atom: u16,
        capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        self.win16_atoms
            .get_name(self.win16_dcs.text_codec(), atom, capacity)
    }
    fn win16_message_box(
        &mut self,
        text: &[u8],
        caption: &[u8],
        style: u16,
    ) -> Result<u16, RuntimeError> {
        win16::message_box(self.win16_dcs.text_codec(), text, caption, style)
    }
    fn win16_wnet_get_caps(&mut self, index: u16) -> Result<u16, RuntimeError> {
        super::win16_wnet_caps::get_caps(self, index)
    }
    fn win16_network_redirector(
        &mut self,
        call: runtime::Win16HostNetworkRedirectorCall,
    ) -> Result<runtime::Win16HostNetworkRedirectorResult, RuntimeError> {
        win16_network_redirector::execute(call, &self.win16_dcs.text_codec())
    }
    fn win16_spool(
        &mut self,
        operation: runtime::Win16HostSpoolOperation,
    ) -> Result<runtime::Win16HostSpoolResult, RuntimeError> {
        let release_owner = match &operation {
            runtime::Win16HostSpoolOperation::ReleaseNetworkOwner { owner } => Some(*owner),
            _ => None,
        };
        let spool_result = self
            .win16_spool_jobs
            .execute(self.win16_dcs.text_codec(), operation);
        let Some(owner) = release_owner else {
            return spool_result;
        };
        // Snapshot/watch setup can retain a temporary printer handle after a
        // failed ClosePrinter. Retry those exact task-owned handles even when
        // spool-job cleanup itself reports an error.
        let queue_result = self.win16_network_print_queues.release_owner_orphans(owner);
        self.win16_network
            .set_printer_watch_poll_demand(self.win16_network_print_queues.active_watch_count());
        match (spool_result, queue_result) {
            (
                Ok(runtime::Win16HostSpoolResult::Status {
                    succeeded: spool_ok,
                    native_error: spool_error,
                }),
                Ok(runtime::Win16HostNetworkQueueResult::Status {
                    succeeded: queues_ok,
                    native_error: queues_error,
                }),
            ) => Ok(runtime::Win16HostSpoolResult::Status {
                succeeded: spool_ok && queues_ok,
                native_error: if !spool_ok {
                    spool_error
                } else if !queues_ok {
                    queues_error
                } else {
                    None
                },
            }),
            (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(
                "retrying task-owned WNet temporary printer handles",
                cleanup,
            )),
            (
                Err(primary),
                Ok(runtime::Win16HostNetworkQueueResult::Status {
                    succeeded: false,
                    native_error,
                }),
            ) => Err(primary.with_cleanup(
                "closing task-owned WNet temporary printer handle",
                RuntimeError::new(
                    runtime::DiagnosticKind::HostFailure,
                    format!(
                        "ClosePrinter retry failed; {}",
                        windows_error_code_description(native_error),
                    ),
                ),
            )),
            (
                Ok(runtime::Win16HostSpoolResult::Status {
                    succeeded: false,
                    native_error,
                }),
                Err(cleanup),
            ) => Err(RuntimeError::new(
                runtime::DiagnosticKind::HostFailure,
                format!(
                    "task-owned spool job cleanup failed; {}",
                    windows_error_code_description(native_error),
                ),
            )
            .with_cleanup("closing task-owned WNet temporary printer handles", cleanup)),
            (Ok(_), Ok(_)) => Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "ReleaseNetworkOwner returned a non-status result",
            )),
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        }
    }
    fn win16_network_print_queues(
        &mut self,
        operation: runtime::Win16HostNetworkQueueOperation,
    ) -> Result<runtime::Win16HostNetworkQueueResult, RuntimeError> {
        let notification_source_id = if matches!(
            &operation,
            runtime::Win16HostNetworkQueueOperation::Watch { .. },
        ) {
            self.win16_network.ensure_printer_watch_polling()?;
            Some(self.win16_network.reserve_notification_source_id()?)
        } else {
            None
        };
        let result = self.win16_network_print_queues.execute(
            self.win16_dcs.text_codec(),
            operation,
            &mut self.win16_spool_jobs,
            notification_source_id,
        );
        self.win16_network
            .set_printer_watch_poll_demand(self.win16_network_print_queues.active_watch_count());
        result
    }

    fn win16_get_tick_count(&mut self) -> Result<u32, RuntimeError> {
        Ok(win16_common::get_tick_count())
    }
    fn win16_message_beep(&mut self, kind: u32) -> Result<bool, RuntimeError> {
        Ok(win16_common::message_beep(kind) != 0)
    }
    fn win16_get_key_state(&mut self, key: i32, asynchronous: bool) -> Result<i16, RuntimeError> {
        if asynchronous {
            Ok(win16_common::get_async_key_state(key))
        } else {
            self.win16_windows.get_key_state(key)
        }
    }
    fn win16_get_system_metrics(&mut self, index: i32) -> Result<i32, RuntimeError> {
        Ok(win16_common::get_system_metrics(index))
    }
    fn win16_get_double_click_time(&mut self) -> Result<u32, RuntimeError> {
        Ok(win16_user_services_system::get_double_click_time())
    }
    fn win16_set_double_click_time(&mut self, milliseconds: u32) -> Result<bool, RuntimeError> {
        Ok(win16_user_services_system::set_double_click_time(
            milliseconds,
        ))
    }
    fn win16_get_caret_blink_time(&mut self) -> Result<u32, RuntimeError> {
        Ok(win16_user_services_system::get_caret_blink_time())
    }
    fn win16_set_caret_blink_time(&mut self, milliseconds: u32) -> Result<bool, RuntimeError> {
        Ok(win16_user_services_system::set_caret_blink_time(
            milliseconds,
        ))
    }
    fn win16_get_sys_color(&mut self, index: i32) -> Result<u32, RuntimeError> {
        Ok(win16_user_services_system::get_sys_color(index))
    }
    fn win16_swap_mouse_button(&mut self, swap: bool) -> Result<bool, RuntimeError> {
        Ok(win16_user_services_system::swap_mouse_button(swap))
    }
    fn win16_any_popup(&mut self) -> Result<bool, RuntimeError> {
        Ok(win16_user_services_system::any_popup())
    }
    fn win16_get_dialog_base_units(&mut self) -> Result<u32, RuntimeError> {
        Ok(win16_user_services_system::get_dialog_base_units())
    }
    fn win16_profile_int(
        &mut self, section: Option<&[u8]>, key: Option<&[u8]>, default: i32,
        filename: &runtime::Win16ProfilePath,
    ) -> Result<u32, RuntimeError> {
        let codec = self.win16_dcs.text_codec();
        if matches!(filename, runtime::Win16ProfilePath::System) {
            return win16_common::get_private_profile_int(codec, section, key, default, None);
        }
        super::win16_private_profile::read(&mut self.filesystem, codec, filename,
            |path| win16_common::private_int_wide(codec, section, key, default, path))
    }
    fn win16_system_profile_int(
        &mut self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        default: i32,
    ) -> Result<u32, RuntimeError> {
        win16_common::get_profile_int(self.win16_dcs.text_codec(), section, key, default)
    }
    fn win16_profile_string(
        &mut self, section: Option<&[u8]>, key: Option<&[u8]>, default: Option<&[u8]>,
        filename: &runtime::Win16ProfilePath, capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        let codec = self.win16_dcs.text_codec();
        if matches!(filename, runtime::Win16ProfilePath::System) {
            return profile::private_string(codec, section, key, default, None, capacity);
        }
        let output = super::win16_private_profile::read(&mut self.filesystem, codec, filename,
            |path| win16_common::private_string_wide(codec, section, key, default, path,
                u32::from(capacity)))?;
        Ok((output.buffer, output.copied as u16))
    }
    fn win16_system_profile_string(
        &mut self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        default: Option<&[u8]>,
        capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        profile::system_string(self.win16_dcs.text_codec(), section, key, default, capacity)
    }
    fn win16_profile_write(
        &mut self, section: Option<&[u8]>, key: Option<&[u8]>, value: Option<&[u8]>,
        filename: &runtime::Win16ProfilePath,
    ) -> Result<bool, RuntimeError> {
        let codec = self.win16_dcs.text_codec();
        if matches!(filename, runtime::Win16ProfilePath::System) {
            return Ok(win16_common::write_private_profile_string(codec, section, key, value, None)? != 0);
        }
        super::win16_private_profile::write(&mut self.filesystem, codec, filename,
            section.is_none() && key.is_none() && value.is_none(),
            |path| win16_common::private_write_wide(codec, section, key, value, path))
    }
    fn win16_profile_section(
        &mut self, section: Option<&[u8]>, filename: &runtime::Win16ProfilePath, capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        let codec = self.win16_dcs.text_codec();
        let output = if matches!(filename, runtime::Win16ProfilePath::System) {
            win16_profile_sections::get_private_profile_section(codec, section, None, capacity)?
        } else {
            super::win16_private_profile::read(&mut self.filesystem, codec, filename,
                |path| win16_profile_sections::private_section_wide(codec, section, path, capacity))?
        };
        Ok((output.buffer, output.copied))
    }
    fn win16_system_profile_section(
        &mut self,
        section: Option<&[u8]>,
        capacity: u16,
    ) -> Result<(Vec<u8>, u16), RuntimeError> {
        let output = win16_profile_sections::get_profile_section(
            self.win16_dcs.text_codec(),
            section,
            capacity,
        )?;
        Ok((output.buffer, output.copied))
    }
    fn win16_profile_section_write(
        &mut self, section: Option<&[u8]>, entries: Option<&[u8]>,
        filename: &runtime::Win16ProfilePath,
    ) -> Result<bool, RuntimeError> {
        let codec = self.win16_dcs.text_codec();
        if matches!(filename, runtime::Win16ProfilePath::System) {
            return win16_profile_sections::write_private_profile_section(codec, section, entries, None);
        }
        super::win16_private_profile::write(&mut self.filesystem, codec, filename,
            section.is_none() && entries.is_none(),
            |path| win16_profile_sections::private_write_wide(codec, section, entries, path))
    }
    fn win16_system_profile_section_write(
        &mut self,
        section: Option<&[u8]>,
        entries: Option<&[u8]>,
    ) -> Result<bool, RuntimeError> {
        win16_profile_sections::write_profile_section(self.win16_dcs.text_codec(), section, entries)
    }
    fn report_diagnostic(&mut self, diagnostic: &Diagnostic) {
        eprintln!("runtime: {diagnostic}");
    }
    fn observe_dos_service(
        &mut self,
        instruction_count: u64,
        before: &runtime::GuestRegisters,
        after: &runtime::GuestRegisters,
    ) {
        runtime_host_diagnostics::observe_dos_service(self, instruction_count, before, after)
    }
    fn epoch_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        runtime_host_input::read_bios_key(self)
    }
    fn try_read_bios_key(&mut self) -> Result<Option<KeyStroke>, RuntimeError> {
        runtime_host_input::try_read_bios_key(self)
    }
    fn pump_events(&mut self) -> Result<(), RuntimeError> {
        runtime_host_input::pump_events(self)
    }
    fn mouse_available(&self) -> bool {
        runtime_host_mouse::mouse_available(self)
    }
    fn take_mouse_input(&mut self) -> Result<Option<MouseInput>, RuntimeError> {
        runtime_host_mouse::take_mouse_input(self)
    }
    fn set_mouse_position(&mut self, x: u16, y: u16) -> Result<(), RuntimeError> {
        runtime_host_mouse::set_mouse_position(self, x, y)
    }
    fn render_graphics(&mut self, frame: &devices::vga::VgaFrame) -> Result<(), RuntimeError> {
        runtime_host_windows::render_graphics(self, frame)
    }
    fn render_text(&mut self, screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        runtime_host_windows::render_text(self, screen)
    }
}
