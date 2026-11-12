//! Input snapshots and guest-output identities for common-dialog calls.

use guest_core::memory::Memory;
use win16_abi::{
    commdlg_abi::{ChooseColor16, ChooseFont16, FindReplace16, OpenFileName16, PrintDlg16},
    gdi_abi::{decode_devmode16, LogFont16},
    Win16CommdlgRequest, Win16ResourceName, Win16ReturnKind,
};

use super::{
    report_common_dialog_gap, ranges::GuestOutputRange,
    support::{checked_capacity, host_log_font, validate_dev_names,
        MAX_COMMON_DIALOG_BYTES},
    Win16CommonDialogCall, Win16CommonDialogContinuation, Win16CommonDialogOutput,
    Win16CommonDialogPreparation, Win16State,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostChooseColorDialog,
    Win16HostChooseFontDialog, Win16HostCommonDialogOperation as Operation,
    Win16HostOpenFileDialog, Win16HostPrintDialog,
};

const OFN_ENABLEHOOK: u32 = 0x0000_0020;
const OFN_ENABLETEMPLATE: u32 = 0x0000_0040;
const OFN_ENABLETEMPLATEHANDLE: u32 = 0x0000_0080;
const OFN_VERIFIED_FLAGS: u32 = 0x0001_FFFF;
// Windows 3.1 SDK COMMDLG error words. These are the published CDERR values
// for a missing hook, instance, template, or named dialog resource.
const CDERR_STRUCTSIZE: u32 = 0x0000_0001;
const CDERR_INITIALIZATION: u32 = 0x0000_0002;
const CDERR_NOTEMPLATE: u32 = 0x0000_0003;
const CDERR_NOHINSTANCE: u32 = 0x0000_0004;
const CDERR_FINDRESFAILURE: u32 = 0x0000_0006;
const CDERR_NOHOOK: u32 = 0x0000_000B;
const CDERR_DIALOGFAILURE: u32 = 0x0000_FFFF;
const PDERR_RETDEFFAILURE: u32 = 0x0000_1003;
const CFERR_MAXLESSTHANMIN: u32 = 0x0000_2002;
const FRERR_BUFFERLENGTHZERO: u32 = 0x0000_4001;
const RT_DIALOG: u16 = 5;

/// Hook and template inputs shared by the common-dialog families.
/// The hook value stays a guest procedure address. A decoded template is an
/// owned byte layout, not a host window procedure.
pub(super) struct CommonDialogHookTemplate {
    pub(super) enable_hook: bool,
    pub(super) enable_template: bool,
    pub(super) enable_template_handle: bool,
    /// Guest FAR procedure. Never a host window procedure.
    pub(super) hook: u32,
    pub(super) instance: u16,
    /// Guest FAR of the template name, or a MAKEINTRESOURCE id in the low word.
    pub(super) template_name: u32,
}

pub(super) enum CommonDialogHookTemplateResolution {
    Rejected { extended_error: u32 },
    Ready {
        /// `None` is a template with no hook procedure.
        hook: Option<u32>,
        /// Owned Win16 dialog template. It is not a host window procedure.
        template: Option<crate::Win16HostDialogTemplate>,
    },
}
const CC_ENABLEHOOK: u32 = 0x0000_0010;
const CC_ENABLETEMPLATE: u32 = 0x0000_0020;
const CC_ENABLETEMPLATEHANDLE: u32 = 0x0000_0040;
const CF_ENABLEHOOK: u32 = 0x0000_0008;
const CF_ENABLETEMPLATE: u32 = 0x0000_0010;
const CF_ENABLETEMPLATEHANDLE: u32 = 0x0000_0020;
const CF_USESTYLE: u32 = 0x0000_0080;
const CF_LIMITSIZE: u32 = 0x0000_2000;
// Windows 3.1 COMMDLG.H requires lpszStyle to hold at least LF_FACESIZE bytes.
const CF_STYLE_BYTES: usize = 32;
const PD_RETURNDEFAULT: u32 = 0x0000_0400;
const FR_ENABLEHOOK: u32 = 0x0000_0100;
const FR_ENABLETEMPLATE: u32 = 0x0000_0200;
const FR_ENABLETEMPLATEHANDLE: u32 = 0x0000_2000;
const PD_ENABLEPRINHOOK: u32 = 0x0000_1000;
const PD_ENABLESETUPHOOK: u32 = 0x0000_2000;
const PD_ENABLEPRINTTEMPLATE: u32 = 0x0000_4000;
const PD_ENABLESETUPTEMPLATE: u32 = 0x0000_8000;
const PD_ENABLEPRINTTEMPLATEHANDLE: u32 = 0x0001_0000;
const PD_ENABLESETUPTEMPLATEHANDLE: u32 = 0x0002_0000;

enum DialogGate {
    Continue,
    /// The hook or template is present, but no live dialog window exists to
    /// enter the guest procedure.
    HookUnavailable,
    Stop(Win16CommonDialogPreparation),
}

impl Win16State {
    /// `None` is a null structure pointer. Microsoft documents that case as
    /// `CDERR_INITIALIZATION`, and a readable size other than the packed Win16
    /// record as `CDERR_STRUCTSIZE`. Neither case writes guest memory.
    fn dialog_structure_size(
        &self,
        memory: &Memory,
        structure_far: u32,
    ) -> Result<Option<u32>, RuntimeError> {
        if structure_far == 0 {
            return Ok(None);
        }
        let pointer = self.selectors.pointer_from_far(structure_far)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, 4)?;
        let raw: [u8; 4] = bytes.try_into().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 common-dialog size read returned an unexpected length"))?;
        Ok(Some(u32::from_le_bytes(raw)))
    }

    fn reject_common_dialog(&mut self, extended_error: u32) -> Win16CommonDialogPreparation {
        self.common_dialog_state.last_extended_error = extended_error;
        Win16CommonDialogPreparation::Immediate(0)
    }

    fn gate_structure_size(
        &mut self,
        memory: &Memory,
        structure_far: u32,
        expected: u32,
    ) -> Result<DialogGate, RuntimeError> {
        match self.dialog_structure_size(memory, structure_far)? {
            None => Ok(DialogGate::Stop(self.reject_common_dialog(CDERR_INITIALIZATION))),
            Some(size) if size != expected => {
                Ok(DialogGate::Stop(self.reject_common_dialog(CDERR_STRUCTSIZE)))
            }
            Some(_) => Ok(DialogGate::Continue),
        }
    }

    fn gate_one_hook_template(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        request: CommonDialogHookTemplate,
    ) -> Result<DialogGate, RuntimeError> {
        if !request.enable_hook && !request.enable_template && !request.enable_template_handle {
            return Ok(DialogGate::Continue);
        }
        match self.resolve_common_dialog_hook_template(memory, host, request)? {
            CommonDialogHookTemplateResolution::Rejected { extended_error } => {
                Ok(DialogGate::Stop(self.reject_common_dialog(extended_error)))
            }
            CommonDialogHookTemplateResolution::Ready { .. } => Ok(DialogGate::HookUnavailable),
        }
    }

    pub(super) fn prepare_common_dialog(
        &mut self,
        memory: &Memory,
        request: Win16CommdlgRequest,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonDialogPreparation, RuntimeError> {
        let result = match request {
            request @ (Win16CommdlgRequest::GetOpenFileName { structure }
                | Win16CommdlgRequest::GetSaveFileName { structure }) => {
                self.prepare_open_file(memory, request, structure, return_kind, host)?
            }
            Win16CommdlgRequest::ChooseColor { structure } => {
                self.prepare_choose_color(memory, structure, return_kind, host)?
            }
            Win16CommdlgRequest::GetFileTitle { file_name, title, capacity } => {
                if title == 0 && capacity != 0 {
                    return Ok(Win16CommonDialogPreparation::Immediate(u16::MAX as u32));
                }
                let output = if title == 0 { None }
                    else { self.optional_output_range(memory, title, u32::from(capacity))? };
                return Ok(window_call(
                    Operation::GetFileTitle {
                        file_name, capacity, title_is_null: title == 0,
                    },
                    return_kind,
                    Win16CommonDialogOutput::FileTitle { output },
                ));
            }
            Win16CommdlgRequest::ExtendedError => {
                return Ok(Win16CommonDialogPreparation::Immediate(
                    self.common_dialog_state.last_extended_error,
                ));
            }
            request @ (Win16CommdlgRequest::FindText { structure }
                | Win16CommdlgRequest::ReplaceText { structure }) => {
                self.prepare_find_replace(memory, request, structure, return_kind, host)?
            }
            Win16CommdlgRequest::ChooseFont { structure } => {
                self.prepare_choose_font(memory, structure, return_kind, host)?
            }
            Win16CommdlgRequest::PrintDlg { structure } => {
                self.prepare_print(memory, structure, return_kind, host)?
            }
            Win16CommdlgRequest::DialogProcedure { ordinal, .. } => {
                report_common_dialog_gap(host, &format!(
                    "COMMDLG dialog procedure ordinal {ordinal} has no guest callback conversion"));
                Win16CommonDialogPreparation::Immediate(0)
            }
            Win16CommdlgRequest::FontEnumerationProcedure { ordinal, .. } => {
                report_common_dialog_gap(host, &format!(
                    "COMMDLG font enumeration procedure ordinal {ordinal} has no typed GDI callback conversion"));
                Win16CommonDialogPreparation::Immediate(0)
            }
        };
        Ok(result)
    }

    fn prepare_open_file(
        &mut self,
        memory: &Memory,
        request: Win16CommdlgRequest,
        structure_far: u32,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonDialogPreparation, RuntimeError> {
        if let DialogGate::Stop(stopped) = self.gate_structure_size(
            memory, structure_far, OpenFileName16::SIZE as u32,
        )? {
            return Ok(stopped);
        }
        let structure_pointer = self.selectors.pointer_from_far(structure_far)
            .map_err(crate::runtime_error)?;
        let structure = GuestOutputRange::capture(
            self, memory, structure_pointer, OpenFileName16::SIZE,
        )?;
        let raw: [u8; OpenFileName16::SIZE] = structure.read(self, memory)?.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "Win16 OPENFILENAME read returned an unexpected length"))?;
        let value = OpenFileName16::decode(&raw);
        if value.flags & !OFN_VERIFIED_FLAGS != 0 {
            report_common_dialog_gap(host,
                "Win16 OPENFILENAME uses flags outside the verified Windows 3.x set; returning FALSE");
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let hook_template = value.flags
            & (OFN_ENABLEHOOK | OFN_ENABLETEMPLATE | OFN_ENABLETEMPLATEHANDLE);
        let resolved = if hook_template == 0 {
            None
        } else {
            Some(self.resolve_common_dialog_hook_template(memory, host,
                CommonDialogHookTemplate {
                    enable_hook: value.flags & OFN_ENABLEHOOK != 0,
                    enable_template: value.flags & OFN_ENABLETEMPLATE != 0,
                    enable_template_handle: value.flags & OFN_ENABLETEMPLATEHANDLE != 0,
                    hook: value.hook,
                    instance: value.instance,
                    template_name: value.template,
                })?)
        };
        if let Some(CommonDialogHookTemplateResolution::Rejected { extended_error }) = resolved {
            self.common_dialog_state.last_extended_error = extended_error;
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let owner = self.common_dialog_owner(value.owner)?;
        let file_capacity = checked_capacity(value.max_file)?;
        if value.file == 0 || file_capacity == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 OPENFILENAME requires a writable file buffer"));
        }
        let file_pointer = self.selectors.pointer_from_far(value.file)
            .map_err(crate::runtime_error)?;
        let file_range = GuestOutputRange::capture(self, memory, file_pointer, file_capacity)?;
        let file = file_range.read(self, memory)?;
        if !file.contains(&0) {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 OPENFILENAME input file buffer has no terminator within nMaxFile"));
        }
        if let Some(CommonDialogHookTemplateResolution::Ready { .. }) = resolved {
            // A Common Dialog hook is a dialog procedure for a live HWND.
            // No file-dialog window exists, so the guest procedure is not
            // entered. Template bytes were already decoded above; a bad
            // template returned its SDK CDERR before this gap.
            report_common_dialog_gap(host,
                "Win16 OPENFILENAME hook is not called: no file-dialog window exists, so the call returns FALSE");
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let file_title = self.optional_output_range(memory, value.file_title,
            value.max_file_title)?;
        let title_bytes = file_title.as_ref().map(|range| range.read(self, memory)).transpose()?;
        let custom_filter = self.optional_output_range(memory, value.custom_filter,
            value.max_custom_filter)?;
        let custom_bytes = custom_filter.as_ref().map(|range| range.read(self, memory)).transpose()?;
        let filter = self.read_multisz(memory, value.filter)?;
        let initial_dir = self.read_z_string(memory, value.initial_dir, MAX_COMMON_DIALOG_BYTES)?;
        let title = self.read_z_string(memory, value.title, MAX_COMMON_DIALOG_BYTES)?;
        let default_extension = self.read_z_string(memory, value.default_extension,
            MAX_COMMON_DIALOG_BYTES)?;

        let dialog = Win16HostOpenFileDialog {
            owner,
            flags: value.flags,
            filter,
            custom_filter: custom_bytes,
            filter_index: value.filter_index,
            file,
            file_title: title_bytes,
            initial_dir,
            title,
            default_extension,
            file_offset: value.file_offset,
            file_extension: value.file_extension,
        };
        let output = Win16CommonDialogOutput::File {
            structure,
            file: file_range,
            file_far: value.file,
            file_capacity,
            file_title,
            file_title_far: value.file_title,
            file_title_capacity: value.max_file_title,
            custom_filter,
            custom_filter_far: value.custom_filter,
            custom_filter_capacity: value.max_custom_filter,
        };
        let operation = if matches!(request, Win16CommdlgRequest::GetSaveFileName { .. }) {
            Operation::SaveFile(dialog)
        } else { Operation::OpenFile(dialog) };
        Ok(window_call(operation, return_kind, output))
    }

    /// Validate an OPENFILENAME-style hook and dialog template.
    ///
    /// The hook value stays the guest procedure address. `OFN_ENABLETEMPLATE`
    /// reads `RT_DIALOG` from the guest NE module. `OFN_ENABLETEMPLATEHANDLE`
    /// reads a preloaded template from the guest global named by `hInstance`
    /// and ignores the template name, which is the Windows 3.1 SDK rule.
    /// A decoded template is an owned byte layout, not a host procedure pointer.
    pub(super) fn resolve_common_dialog_hook_template(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        request: CommonDialogHookTemplate,
    ) -> Result<CommonDialogHookTemplateResolution, RuntimeError> {
        let template = if request.enable_template_handle {
            if request.instance == 0 {
                return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_NOHINSTANCE,
                });
            }
            match self.dialog_template_from_global(request.instance, memory)? {
                Some(template) => Some(template),
                None => return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_NOTEMPLATE,
                }),
            }
        } else if request.enable_template {
            if request.instance == 0 {
                return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_NOHINSTANCE,
                });
            }
            if request.template_name == 0 {
                return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_NOTEMPLATE,
                });
            }
            let name = if request.template_name >> 16 == 0 {
                Win16ResourceName::Id(request.template_name as u16)
            } else {
                let bytes = self.read_z_string(memory, request.template_name,
                    MAX_COMMON_DIALOG_BYTES)?.ok_or_else(|| RuntimeError::new(
                    Kind::GuestFault, "Win16 common-dialog template name is null"))?;
                Win16ResourceName::Name(bytes)
            };
            let info = self.find_resource(
                request.instance, &name, &Win16ResourceName::Id(RT_DIALOG), host,
            )?;
            if info == 0 {
                return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_FINDRESFAILURE,
                });
            }
            match self.dialog_template_from_resource(request.instance, &name, host)? {
                Some(template) => Some(template),
                None => return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_NOTEMPLATE,
                }),
            }
        } else {
            None
        };
        let hook = if request.enable_hook {
            if request.hook == 0 {
                return Ok(CommonDialogHookTemplateResolution::Rejected {
                    extended_error: CDERR_NOHOOK,
                });
            }
            self.validate_dialog_procedure(request.hook, memory)?;
            Some(request.hook)
        } else {
            None
        };
        Ok(CommonDialogHookTemplateResolution::Ready { hook, template })
    }

    fn prepare_choose_color(
        &mut self,
        memory: &Memory,
        structure_far: u32,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonDialogPreparation, RuntimeError> {
        if let DialogGate::Stop(stopped) = self.gate_structure_size(
            memory, structure_far, ChooseColor16::SIZE as u32,
        )? {
            return Ok(stopped);
        }
        let pointer = self.selectors.pointer_from_far(structure_far).map_err(crate::runtime_error)?;
        let structure = GuestOutputRange::capture(self, memory, pointer, ChooseColor16::SIZE)?;
        let raw: [u8; ChooseColor16::SIZE] = structure.read(self, memory)?.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "Win16 CHOOSECOLOR read returned an unexpected length"))?;
        let value = ChooseColor16::decode(&raw);
        let hook_gate = self.gate_one_hook_template(memory, host, CommonDialogHookTemplate {
            enable_hook: value.flags & CC_ENABLEHOOK != 0,
            enable_template: value.flags & CC_ENABLETEMPLATE != 0,
            enable_template_handle: value.flags & CC_ENABLETEMPLATEHANDLE != 0,
            hook: value.hook,
            instance: value.instance,
            template_name: value.template,
        })?;
        if let DialogGate::Stop(stopped) = hook_gate {
            return Ok(stopped);
        }
        if matches!(hook_gate, DialogGate::HookUnavailable) {
            report_common_dialog_gap(host,
                "Win16 CHOOSECOLOR hook is not called: no color-dialog window exists, so the call returns FALSE");
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let owner = self.common_dialog_owner(value.owner)?;
        if value.custom_colors == 0 {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 CHOOSECOLOR requires a writable sixteen-entry custom color array"));
        }
        let colors_pointer = self.selectors.pointer_from_far(value.custom_colors)
            .map_err(crate::runtime_error)?;
        let custom_colors = GuestOutputRange::capture(self, memory, colors_pointer, 16 * 4)?;
        let bytes = custom_colors.read(self, memory)?;
        let mut palette = [0u32; 16];
        for (index, color) in palette.iter_mut().enumerate() {
            let at = index * 4;
            *color = u32::from_le_bytes(bytes[at..at + 4].try_into().map_err(|_|
                RuntimeError::new(Kind::InternalInvariant,
                    "Win16 custom-color entry has an invalid byte count"))?);
        }
        let operation = Operation::ChooseColor(Win16HostChooseColorDialog {
            owner,
            initial_color: value.initial_color,
            custom_colors: palette,
            flags: value.flags,
        });
        Ok(window_call(operation, return_kind, Win16CommonDialogOutput::Color {
            structure, custom_colors, custom_colors_far: value.custom_colors,
        }))
    }

    fn prepare_find_replace(
        &mut self,
        memory: &Memory,
        request: Win16CommdlgRequest,
        structure_far: u32,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonDialogPreparation, RuntimeError> {
        if let DialogGate::Stop(stopped) = self.gate_structure_size(
            memory, structure_far, FindReplace16::SIZE as u32,
        )? {
            return Ok(stopped);
        }
        let pointer = self.selectors.pointer_from_far(structure_far).map_err(crate::runtime_error)?;
        let structure = GuestOutputRange::capture(self, memory, pointer, FindReplace16::SIZE)?;
        let raw: [u8; FindReplace16::SIZE] = structure.read(self, memory)?.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "Win16 FINDREPLACE read returned an unexpected length"))?;
        let value = FindReplace16::decode(&raw);
        // FindText/ReplaceText require a real owner window. A null or unmapped
        // HWND is CDERR_DIALOGFAILURE, which Microsoft gives as the example of
        // an invalid common-dialog window handle. Zero find length, a null find
        // buffer, or a null ReplaceText replacement buffer is
        // FRERR_BUFFERLENGTHZERO. Guest memory is left unchanged.
        let owner = match self.common_dialog_owner(value.owner) {
            Ok(Some(owner)) => owner,
            Ok(None) => return Ok(self.reject_common_dialog(CDERR_DIALOGFAILURE)),
            Err(error) if super::is_guest_api_failure(&error) => {
                return Ok(self.reject_common_dialog(CDERR_DIALOGFAILURE));
            }
            Err(error) => return Err(error),
        };
        let replace = matches!(request, Win16CommdlgRequest::ReplaceText { .. });
        if value.find_text_capacity == 0 || value.find_text == 0
            || (replace && value.replace_text == 0)
        {
            return Ok(self.reject_common_dialog(FRERR_BUFFERLENGTHZERO));
        }
        let hook_gate = self.gate_one_hook_template(memory, host, CommonDialogHookTemplate {
            enable_hook: value.flags & FR_ENABLEHOOK != 0,
            enable_template: value.flags & FR_ENABLETEMPLATE != 0,
            enable_template_handle: value.flags & FR_ENABLETEMPLATEHANDLE != 0,
            hook: value.hook,
            instance: value.instance,
            template_name: value.template,
        })?;
        if let DialogGate::Stop(stopped) = hook_gate {
            return Ok(stopped);
        }
        if matches!(hook_gate, DialogGate::HookUnavailable) {
            report_common_dialog_gap(host,
                "Win16 FINDREPLACE hook is not called: no find-dialog window exists, so the call returns NULL");
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let find_capacity = checked_capacity(u32::from(value.find_text_capacity))?;
        let find_pointer = self.selectors.pointer_from_far(value.find_text)
            .map_err(crate::runtime_error)?;
        let find = GuestOutputRange::capture(self, memory, find_pointer, find_capacity)?;
        let find_text = find.read(self, memory)?;
        if !find_text.contains(&0) {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 FINDREPLACE find-text buffer has no terminator within its capacity"));
        }
        let (replace_far, replace_pointer, replace_capacity, replace_text) = if replace {
            let capacity = checked_capacity(u32::from(value.replace_text_capacity))?;
            if capacity == 0 {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 ReplaceText requires a nonempty writable replacement buffer"));
            }
            let pointer = self.selectors.pointer_from_far(value.replace_text)
                .map_err(crate::runtime_error)?;
            let range = GuestOutputRange::capture(self, memory, pointer, capacity)?;
            let bytes = range.read(self, memory)?;
            if !bytes.contains(&0) {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 FINDREPLACE replacement buffer has no terminator within its capacity"));
            }
            (Some(value.replace_text), Some(pointer), capacity, Some(bytes))
        } else { (None, None, 0, None) };
        let (request_id, operation) = self.reserve_find_replace(
            memory, structure_far, pointer, owner, replace,
            value.find_text, find_pointer, find_capacity, find_text,
            replace_far, replace_pointer, replace_capacity, replace_text, value.flags,
        )?;
        Ok(window_call(Operation::FindReplace(operation), return_kind,
            Win16CommonDialogOutput::FindReplace { request_id }))
    }

    fn prepare_choose_font(
        &mut self,
        memory: &Memory,
        structure_far: u32,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonDialogPreparation, RuntimeError> {
        if let DialogGate::Stop(stopped) = self.gate_structure_size(
            memory, structure_far, ChooseFont16::SIZE as u32,
        )? {
            return Ok(stopped);
        }
        let pointer = self.selectors.pointer_from_far(structure_far).map_err(crate::runtime_error)?;
        let structure = GuestOutputRange::capture(self, memory, pointer, ChooseFont16::SIZE)?;
        let raw: [u8; ChooseFont16::SIZE] = structure.read(self, memory)?.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "Win16 CHOOSEFONT read returned an unexpected length"))?;
        let value = ChooseFont16::decode(&raw);
        let hook_gate = self.gate_one_hook_template(memory, host, CommonDialogHookTemplate {
            enable_hook: value.flags & CF_ENABLEHOOK != 0,
            enable_template: value.flags & CF_ENABLETEMPLATE != 0,
            enable_template_handle: value.flags & CF_ENABLETEMPLATEHANDLE != 0,
            hook: value.hook,
            instance: value.instance,
            template_name: value.template,
        })?;
        if let DialogGate::Stop(stopped) = hook_gate {
            return Ok(stopped);
        }
        // CHOOSEFONT nSizeMin and nSizeMax are signed 16-bit fields. Microsoft
        // returns CFERR_MAXLESSTHANMIN when CF_LIMITSIZE is set and nSizeMax
        // is less than nSizeMin. The comparison is signed, and the structure
        // is left unchanged.
        if value.flags & CF_LIMITSIZE != 0 && value.min_size > value.max_size {
            return Ok(self.reject_common_dialog(CFERR_MAXLESSTHANMIN));
        }
        if value.log_font == 0 || (value.flags & CF_USESTYLE != 0 && value.style == 0) {
            return Ok(self.reject_common_dialog(CDERR_INITIALIZATION));
        }
        if matches!(hook_gate, DialogGate::HookUnavailable) {
            report_common_dialog_gap(host,
                "Win16 CHOOSEFONT hook is not called: no font-dialog window exists, so the call returns FALSE");
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let font_pointer = self.selectors.pointer_from_far(value.log_font)
            .map_err(crate::runtime_error)?;
        let log_font = GuestOutputRange::capture(self, memory, font_pointer, LogFont16::SIZE)?;
        let font_bytes = log_font.read(self, memory)?;
        let font_record = LogFont16::decode(&font_bytes).map_err(|_| RuntimeError::new(
            Kind::GuestFault, "Win16 CHOOSEFONT LOGFONT has an invalid packed size"))?;
        let dc = if value.dc == 0 { None } else {
            Some(self.guest_gdi.dc(value.dc).ok_or_else(|| RuntimeError::new(
                Kind::GuestFault, "Win16 CHOOSEFONT HDC is not mapped"))?)
        };
        let style = self.optional_output_range(memory, value.style, CF_STYLE_BYTES as u32)?;
        let style_initial = if value.flags & CF_USESTYLE != 0 {
            let range = style.as_ref().ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 CHOOSEFONT CF_USESTYLE requires a writable lpszStyle buffer"))?;
            let bytes = range.read(self, memory)?;
            if !bytes.contains(&0) {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 CHOOSEFONT initial style has no terminator within 32 bytes"));
            }
            Some(bytes)
        } else if style.is_some() {
            Some(vec![0; CF_STYLE_BYTES])
        } else { None };
        let operation = Operation::ChooseFont(Win16HostChooseFontDialog {
            owner: self.common_dialog_owner(value.owner)?,
            dc,
            log_font: host_log_font(font_record),
            point_size: value.point_size,
            flags: value.flags,
            color: value.color,
            style: style_initial,
            font_type: value.font_type,
            min_size: value.min_size,
            max_size: value.max_size,
        });
        Ok(window_call(operation, return_kind, Win16CommonDialogOutput::Font {
            structure, log_font, log_font_far: value.log_font, style, style_far: value.style,
        }))
    }

    fn prepare_print(
        &mut self,
        memory: &Memory,
        structure_far: u32,
        return_kind: Win16ReturnKind,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16CommonDialogPreparation, RuntimeError> {
        if let DialogGate::Stop(stopped) = self.gate_structure_size(
            memory, structure_far, PrintDlg16::SIZE as u32,
        )? {
            return Ok(stopped);
        }
        let pointer = self.selectors.pointer_from_far(structure_far).map_err(crate::runtime_error)?;
        let structure = GuestOutputRange::capture(self, memory, pointer, PrintDlg16::SIZE)?;
        let raw: [u8; PrintDlg16::SIZE] = structure.read(self, memory)?.try_into()
            .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                "Win16 PRINTDLG read returned an unexpected length"))?;
        let value = PrintDlg16::decode(&raw);
        // PD_RETURNDEFAULT allocates the default printer handles. A preset
        // hDevMode or hDevNames fails with PDERR_RETDEFFAILURE and does not
        // read those globals.
        if value.flags & PD_RETURNDEFAULT != 0 && (value.dev_mode != 0 || value.dev_names != 0) {
            return Ok(self.reject_common_dialog(PDERR_RETDEFFAILURE));
        }
        // PRINTDLG keeps the preloaded template in hPrintTemplate or
        // hSetupTemplate. hInstance is the module for a named template only.
        let print_template_instance = if value.flags & PD_ENABLEPRINTTEMPLATEHANDLE != 0 {
            value.print_template
        } else {
            value.instance
        };
        let print_gate = self.gate_one_hook_template(memory, host, CommonDialogHookTemplate {
            enable_hook: value.flags & PD_ENABLEPRINHOOK != 0,
            enable_template: value.flags & PD_ENABLEPRINTTEMPLATE != 0,
            enable_template_handle: value.flags & PD_ENABLEPRINTTEMPLATEHANDLE != 0,
            hook: value.print_hook,
            instance: print_template_instance,
            template_name: value.print_template_name,
        })?;
        if let DialogGate::Stop(stopped) = print_gate {
            return Ok(stopped);
        }
        let setup_template_instance = if value.flags & PD_ENABLESETUPTEMPLATEHANDLE != 0 {
            value.setup_template
        } else {
            value.instance
        };
        let setup_gate = self.gate_one_hook_template(memory, host, CommonDialogHookTemplate {
            enable_hook: value.flags & PD_ENABLESETUPHOOK != 0,
            enable_template: value.flags & PD_ENABLESETUPTEMPLATE != 0,
            enable_template_handle: value.flags & PD_ENABLESETUPTEMPLATEHANDLE != 0,
            hook: value.setup_hook,
            instance: setup_template_instance,
            template_name: value.setup_template_name,
        })?;
        if let DialogGate::Stop(stopped) = setup_gate {
            return Ok(stopped);
        }
        if matches!(print_gate, DialogGate::HookUnavailable)
            || matches!(setup_gate, DialogGate::HookUnavailable)
        {
            report_common_dialog_gap(host,
                "Win16 PRINTDLG hook is not called: no print-dialog window exists, so the call returns FALSE");
            return Ok(Win16CommonDialogPreparation::Immediate(0));
        }
        let dev_mode_capture = if value.dev_mode == 0 { None }
            else { Some(self.capture_guest_global(value.dev_mode, memory)?) };
        let dev_names_capture = if value.dev_names == 0 { None }
            else { Some(self.capture_guest_global(value.dev_names, memory)?) };
        let dev_mode = dev_mode_capture.as_ref().map(|block| block.read(self, memory))
            .transpose()?.map(|bytes| decode_devmode16(&bytes).map_err(|_| RuntimeError::new(
                Kind::GuestFault, "Win16 PRINTDLG DEVMODE block is malformed")))
            .transpose()?.map(Into::into);
        let dev_names = dev_names_capture.as_ref().map(|block| block.read(self, memory))
            .transpose()?;
        if let Some(bytes) = &dev_names { validate_dev_names(bytes)?; }

        let operation = Operation::Print(Win16HostPrintDialog {
            owner: self.common_dialog_owner(value.owner)?,
            dev_mode,
            dev_names,
            // PRINTDLG.hDC is output-only in the Win16 contract.
            dc: None,
            flags: value.flags,
            from_page: value.from_page,
            to_page: value.to_page,
            min_page: value.min_page,
            max_page: value.max_page,
            copies: value.copies,
        });
        Ok(window_call(operation, return_kind, Win16CommonDialogOutput::Print {
            structure,
            input_dev_mode: value.dev_mode,
            dev_mode_capture,
            input_dev_names: value.dev_names,
            dev_names_capture,
        }))
    }
}

fn window_call(
    operation: Operation,
    return_kind: Win16ReturnKind,
    output: Win16CommonDialogOutput,
) -> Win16CommonDialogPreparation {
    let guest_failure_value = if matches!(&output, Win16CommonDialogOutput::FileTitle { .. }) {
        u16::MAX as u32
    } else { 0 };
    Win16CommonDialogPreparation::WindowService(Win16CommonDialogCall {
        operation,
        continuation: Win16CommonDialogContinuation {
            return_kind,
            guest_failure_value,
            output,
        },
    })
}
