//! Private, byte-aligned wire layouts for Win16 common-dialog records.

use zerocopy::byteorder::little_endian::{I16, U16, U32};

#[derive(
    Clone,
    Copy,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub(super) struct OpenFileName16Wire {
    pub(super) structure_size: U32,
    pub(super) owner: U16,
    pub(super) instance: U16,
    pub(super) filter: U32,
    pub(super) custom_filter: U32,
    pub(super) max_custom_filter: U32,
    pub(super) filter_index: U32,
    pub(super) file: U32,
    pub(super) max_file: U32,
    pub(super) file_title: U32,
    pub(super) max_file_title: U32,
    pub(super) initial_dir: U32,
    pub(super) title: U32,
    pub(super) flags: U32,
    pub(super) file_offset: U16,
    pub(super) file_extension: U16,
    pub(super) default_extension: U32,
    pub(super) custom_data: U32,
    pub(super) hook: U32,
    pub(super) template: U32,
}

#[derive(
    Clone,
    Copy,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub(super) struct ChooseColor16Wire {
    pub(super) structure_size: U32,
    pub(super) owner: U16,
    pub(super) instance: U16,
    pub(super) initial_color: U32,
    pub(super) custom_colors: U32,
    pub(super) flags: U32,
    pub(super) custom_data: U32,
    pub(super) hook: U32,
    pub(super) template: U32,
}

#[derive(
    Clone,
    Copy,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub(super) struct FindReplace16Wire {
    pub(super) structure_size: U32,
    pub(super) owner: U16,
    pub(super) instance: U16,
    pub(super) flags: U32,
    pub(super) find_text: U32,
    pub(super) replace_text: U32,
    pub(super) find_text_capacity: U16,
    pub(super) replace_text_capacity: U16,
    pub(super) custom_data: U32,
    pub(super) hook: U32,
    pub(super) template: U32,
}

#[derive(
    Clone,
    Copy,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub(super) struct ChooseFont16Wire {
    pub(super) structure_size: U32,
    pub(super) owner: U16,
    pub(super) dc: U16,
    pub(super) log_font: U32,
    pub(super) point_size: I16,
    pub(super) flags: U32,
    pub(super) color: U32,
    pub(super) custom_data: U32,
    pub(super) hook: U32,
    pub(super) template: U32,
    pub(super) instance: U16,
    pub(super) style: U32,
    pub(super) font_type: U16,
    pub(super) min_size: I16,
    pub(super) max_size: I16,
}

#[derive(
    Clone,
    Copy,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub(super) struct PrintDlg16Wire {
    pub(super) structure_size: U32,
    pub(super) owner: U16,
    pub(super) dev_mode: U16,
    pub(super) dev_names: U16,
    pub(super) dc: U16,
    pub(super) flags: U32,
    pub(super) from_page: U16,
    pub(super) to_page: U16,
    pub(super) min_page: U16,
    pub(super) max_page: U16,
    pub(super) copies: U16,
    pub(super) instance: U16,
    pub(super) custom_data: U32,
    pub(super) print_hook: U32,
    pub(super) setup_hook: U32,
    pub(super) print_template_name: U32,
    pub(super) setup_template_name: U32,
    pub(super) print_template: U16,
    pub(super) setup_template: U16,
}
