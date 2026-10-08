//! Packed Win16 common-dialog structures.
//!
//! These codecs describe the Win16 byte layout only. Every FAR value remains
//! an integer address token; callers must validate selector bounds before
//! reading or committing pointed-to buffers. The records use byte packing,
//! 16-bit guest handles, and 32-bit guest FAR values/longs.
//! Strings, custom colors, `DEVNAMES`, `DEVMODE`, and other pointed-to buffers
//! remain caller-owned and are not read or copied by these codecs.

#[path = "commdlg_abi_wire.rs"]
mod wire;

use zerocopy::byteorder::little_endian::{I16, U16, U32};

/// Byte offsets for the packed Win16 `OPENFILENAME` record (72 bytes).
pub mod openfilename16_offsets {
    pub const STRUCT_SIZE: usize = 0;
    pub const OWNER: usize = 4;
    pub const INSTANCE: usize = 6;
    pub const FILTER: usize = 8;
    pub const CUSTOM_FILTER: usize = 12;
    pub const MAX_CUSTOM_FILTER: usize = 16;
    pub const FILTER_INDEX: usize = 20;
    pub const FILE: usize = 24;
    pub const MAX_FILE: usize = 28;
    pub const FILE_TITLE: usize = 32;
    pub const MAX_FILE_TITLE: usize = 36;
    pub const INITIAL_DIR: usize = 40;
    pub const TITLE: usize = 44;
    pub const FLAGS: usize = 48;
    pub const FILE_OFFSET: usize = 52;
    pub const FILE_EXTENSION: usize = 54;
    pub const DEFAULT_EXTENSION: usize = 56;
    pub const CUSTOM_DATA: usize = 60;
    pub const HOOK: usize = 64;
    pub const TEMPLATE: usize = 68;
    pub const SIZE: usize = 72;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpenFileName16 {
    pub structure_size: u32,
    pub owner: u16,
    pub instance: u16,
    pub filter: u32,
    pub custom_filter: u32,
    pub max_custom_filter: u32,
    pub filter_index: u32,
    pub file: u32,
    pub max_file: u32,
    pub file_title: u32,
    pub max_file_title: u32,
    pub initial_dir: u32,
    pub title: u32,
    pub flags: u32,
    pub file_offset: u16,
    pub file_extension: u16,
    pub default_extension: u32,
    pub custom_data: u32,
    pub hook: u32,
    pub template: u32,
}

impl OpenFileName16 {
    pub const SIZE: usize = openfilename16_offsets::SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::OpenFileName16Wire = zerocopy::transmute!(*bytes);
        Self {
            structure_size: wire.structure_size.get(),
            owner: wire.owner.get(),
            instance: wire.instance.get(),
            filter: wire.filter.get(),
            custom_filter: wire.custom_filter.get(),
            max_custom_filter: wire.max_custom_filter.get(),
            filter_index: wire.filter_index.get(),
            file: wire.file.get(),
            max_file: wire.max_file.get(),
            file_title: wire.file_title.get(),
            max_file_title: wire.max_file_title.get(),
            initial_dir: wire.initial_dir.get(),
            title: wire.title.get(),
            flags: wire.flags.get(),
            file_offset: wire.file_offset.get(),
            file_extension: wire.file_extension.get(),
            default_extension: wire.default_extension.get(),
            custom_data: wire.custom_data.get(),
            hook: wire.hook.get(),
            template: wire.template.get(),
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::OpenFileName16Wire {
            structure_size: U32::new(self.structure_size),
            owner: U16::new(self.owner),
            instance: U16::new(self.instance),
            filter: U32::new(self.filter),
            custom_filter: U32::new(self.custom_filter),
            max_custom_filter: U32::new(self.max_custom_filter),
            filter_index: U32::new(self.filter_index),
            file: U32::new(self.file),
            max_file: U32::new(self.max_file),
            file_title: U32::new(self.file_title),
            max_file_title: U32::new(self.max_file_title),
            initial_dir: U32::new(self.initial_dir),
            title: U32::new(self.title),
            flags: U32::new(self.flags),
            file_offset: U16::new(self.file_offset),
            file_extension: U16::new(self.file_extension),
            default_extension: U32::new(self.default_extension),
            custom_data: U32::new(self.custom_data),
            hook: U32::new(self.hook),
            template: U32::new(self.template),
        };
        zerocopy::transmute!(wire)
    }
}

pub mod choosecolor16_offsets {
    pub const STRUCT_SIZE: usize = 0;
    pub const OWNER: usize = 4;
    pub const INSTANCE: usize = 6;
    pub const INITIAL_COLOR: usize = 8;
    pub const CUSTOM_COLORS: usize = 12;
    pub const FLAGS: usize = 16;
    pub const CUSTOM_DATA: usize = 20;
    pub const HOOK: usize = 24;
    pub const TEMPLATE: usize = 28;
    pub const SIZE: usize = 32;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChooseColor16 {
    pub structure_size: u32,
    pub owner: u16,
    pub instance: u16,
    pub initial_color: u32,
    pub custom_colors: u32,
    pub flags: u32,
    pub custom_data: u32,
    pub hook: u32,
    pub template: u32,
}

impl ChooseColor16 {
    pub const SIZE: usize = choosecolor16_offsets::SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::ChooseColor16Wire = zerocopy::transmute!(*bytes);
        Self {
            structure_size: wire.structure_size.get(),
            owner: wire.owner.get(),
            instance: wire.instance.get(),
            initial_color: wire.initial_color.get(),
            custom_colors: wire.custom_colors.get(),
            flags: wire.flags.get(),
            custom_data: wire.custom_data.get(),
            hook: wire.hook.get(),
            template: wire.template.get(),
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::ChooseColor16Wire {
            structure_size: U32::new(self.structure_size),
            owner: U16::new(self.owner),
            instance: U16::new(self.instance),
            initial_color: U32::new(self.initial_color),
            custom_colors: U32::new(self.custom_colors),
            flags: U32::new(self.flags),
            custom_data: U32::new(self.custom_data),
            hook: U32::new(self.hook),
            template: U32::new(self.template),
        };
        zerocopy::transmute!(wire)
    }
}

pub mod findreplace16_offsets {
    pub const STRUCT_SIZE: usize = 0;
    pub const OWNER: usize = 4;
    pub const INSTANCE: usize = 6;
    pub const FLAGS: usize = 8;
    pub const FIND_TEXT: usize = 12;
    pub const REPLACE_TEXT: usize = 16;
    pub const FIND_TEXT_CAPACITY: usize = 20;
    pub const REPLACE_TEXT_CAPACITY: usize = 22;
    pub const CUSTOM_DATA: usize = 24;
    pub const HOOK: usize = 28;
    pub const TEMPLATE: usize = 32;
    /// Member widths under Win16 byte packing total 36 bytes. The `lStructSize`
    /// field is preserved verbatim because a historical comment on the
    /// declaration disagrees with that member sum.
    pub const SIZE: usize = 36;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FindReplace16 {
    pub structure_size: u32,
    pub owner: u16,
    pub instance: u16,
    pub flags: u32,
    pub find_text: u32,
    pub replace_text: u32,
    pub find_text_capacity: u16,
    pub replace_text_capacity: u16,
    pub custom_data: u32,
    pub hook: u32,
    pub template: u32,
}

impl FindReplace16 {
    pub const SIZE: usize = findreplace16_offsets::SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::FindReplace16Wire = zerocopy::transmute!(*bytes);
        Self {
            structure_size: wire.structure_size.get(),
            owner: wire.owner.get(),
            instance: wire.instance.get(),
            flags: wire.flags.get(),
            find_text: wire.find_text.get(),
            replace_text: wire.replace_text.get(),
            find_text_capacity: wire.find_text_capacity.get(),
            replace_text_capacity: wire.replace_text_capacity.get(),
            custom_data: wire.custom_data.get(),
            hook: wire.hook.get(),
            template: wire.template.get(),
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::FindReplace16Wire {
            structure_size: U32::new(self.structure_size),
            owner: U16::new(self.owner),
            instance: U16::new(self.instance),
            flags: U32::new(self.flags),
            find_text: U32::new(self.find_text),
            replace_text: U32::new(self.replace_text),
            find_text_capacity: U16::new(self.find_text_capacity),
            replace_text_capacity: U16::new(self.replace_text_capacity),
            custom_data: U32::new(self.custom_data),
            hook: U32::new(self.hook),
            template: U32::new(self.template),
        };
        zerocopy::transmute!(wire)
    }
}

pub mod choosefont16_offsets {
    pub const STRUCT_SIZE: usize = 0;
    pub const OWNER: usize = 4;
    pub const DC: usize = 6;
    pub const LOG_FONT: usize = 8;
    pub const POINT_SIZE: usize = 12;
    pub const FLAGS: usize = 14;
    pub const COLOR: usize = 18;
    pub const CUSTOM_DATA: usize = 22;
    pub const HOOK: usize = 26;
    pub const TEMPLATE: usize = 30;
    pub const INSTANCE: usize = 34;
    pub const STYLE: usize = 36;
    pub const FONT_TYPE: usize = 40;
    pub const MIN_SIZE: usize = 42;
    pub const MAX_SIZE: usize = 44;
    pub const SIZE: usize = 46;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChooseFont16 {
    pub structure_size: u32,
    pub owner: u16,
    pub dc: u16,
    pub log_font: u32,
    pub point_size: i16,
    pub flags: u32,
    pub color: u32,
    pub custom_data: u32,
    pub hook: u32,
    pub template: u32,
    pub instance: u16,
    pub style: u32,
    pub font_type: u16,
    pub min_size: i16,
    pub max_size: i16,
}

impl ChooseFont16 {
    pub const SIZE: usize = choosefont16_offsets::SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::ChooseFont16Wire = zerocopy::transmute!(*bytes);
        Self {
            structure_size: wire.structure_size.get(),
            owner: wire.owner.get(),
            dc: wire.dc.get(),
            log_font: wire.log_font.get(),
            point_size: wire.point_size.get(),
            flags: wire.flags.get(),
            color: wire.color.get(),
            custom_data: wire.custom_data.get(),
            hook: wire.hook.get(),
            template: wire.template.get(),
            instance: wire.instance.get(),
            style: wire.style.get(),
            font_type: wire.font_type.get(),
            min_size: wire.min_size.get(),
            max_size: wire.max_size.get(),
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::ChooseFont16Wire {
            structure_size: U32::new(self.structure_size),
            owner: U16::new(self.owner),
            dc: U16::new(self.dc),
            log_font: U32::new(self.log_font),
            point_size: I16::new(self.point_size),
            flags: U32::new(self.flags),
            color: U32::new(self.color),
            custom_data: U32::new(self.custom_data),
            hook: U32::new(self.hook),
            template: U32::new(self.template),
            instance: U16::new(self.instance),
            style: U32::new(self.style),
            font_type: U16::new(self.font_type),
            min_size: I16::new(self.min_size),
            max_size: I16::new(self.max_size),
        };
        zerocopy::transmute!(wire)
    }
}

pub mod printdlg16_offsets {
    pub const STRUCT_SIZE: usize = 0;
    pub const OWNER: usize = 4;
    pub const DEV_MODE: usize = 6;
    pub const DEV_NAMES: usize = 8;
    pub const DC: usize = 10;
    pub const FLAGS: usize = 12;
    pub const FROM_PAGE: usize = 16;
    pub const TO_PAGE: usize = 18;
    pub const MIN_PAGE: usize = 20;
    pub const MAX_PAGE: usize = 22;
    pub const COPIES: usize = 24;
    pub const INSTANCE: usize = 26;
    pub const CUSTOM_DATA: usize = 28;
    pub const PRINT_HOOK: usize = 32;
    pub const SETUP_HOOK: usize = 36;
    pub const PRINT_TEMPLATE_NAME: usize = 40;
    pub const SETUP_TEMPLATE_NAME: usize = 44;
    pub const PRINT_TEMPLATE: usize = 48;
    pub const SETUP_TEMPLATE: usize = 50;
    pub const SIZE: usize = 52;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrintDlg16 {
    pub structure_size: u32,
    pub owner: u16,
    pub dev_mode: u16,
    pub dev_names: u16,
    pub dc: u16,
    pub flags: u32,
    pub from_page: u16,
    pub to_page: u16,
    pub min_page: u16,
    pub max_page: u16,
    pub copies: u16,
    pub instance: u16,
    pub custom_data: u32,
    pub print_hook: u32,
    pub setup_hook: u32,
    pub print_template_name: u32,
    pub setup_template_name: u32,
    pub print_template: u16,
    pub setup_template: u16,
}

impl PrintDlg16 {
    pub const SIZE: usize = printdlg16_offsets::SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::PrintDlg16Wire = zerocopy::transmute!(*bytes);
        Self {
            structure_size: wire.structure_size.get(),
            owner: wire.owner.get(),
            dev_mode: wire.dev_mode.get(),
            dev_names: wire.dev_names.get(),
            dc: wire.dc.get(),
            flags: wire.flags.get(),
            from_page: wire.from_page.get(),
            to_page: wire.to_page.get(),
            min_page: wire.min_page.get(),
            max_page: wire.max_page.get(),
            copies: wire.copies.get(),
            instance: wire.instance.get(),
            custom_data: wire.custom_data.get(),
            print_hook: wire.print_hook.get(),
            setup_hook: wire.setup_hook.get(),
            print_template_name: wire.print_template_name.get(),
            setup_template_name: wire.setup_template_name.get(),
            print_template: wire.print_template.get(),
            setup_template: wire.setup_template.get(),
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::PrintDlg16Wire {
            structure_size: U32::new(self.structure_size),
            owner: U16::new(self.owner),
            dev_mode: U16::new(self.dev_mode),
            dev_names: U16::new(self.dev_names),
            dc: U16::new(self.dc),
            flags: U32::new(self.flags),
            from_page: U16::new(self.from_page),
            to_page: U16::new(self.to_page),
            min_page: U16::new(self.min_page),
            max_page: U16::new(self.max_page),
            copies: U16::new(self.copies),
            instance: U16::new(self.instance),
            custom_data: U32::new(self.custom_data),
            print_hook: U32::new(self.print_hook),
            setup_hook: U32::new(self.setup_hook),
            print_template_name: U32::new(self.print_template_name),
            setup_template_name: U32::new(self.setup_template_name),
            print_template: U16::new(self.print_template),
            setup_template: U16::new(self.setup_template),
        };
        zerocopy::transmute!(wire)
    }
}

macro_rules! assert_wire_layout {
    ($wire:ty, $offsets:ident; $($field:ident => $offset:ident),+ $(,)?) => {
        const _: () = {
            assert!(core::mem::size_of::<$wire>() == $offsets::SIZE);
            assert!(core::mem::align_of::<$wire>() == 1);
            $(assert!(core::mem::offset_of!($wire, $field) == $offsets::$offset);)+
        };
    };
}

assert_wire_layout!(wire::OpenFileName16Wire, openfilename16_offsets;
    structure_size => STRUCT_SIZE, owner => OWNER, instance => INSTANCE,
    filter => FILTER, custom_filter => CUSTOM_FILTER,
    max_custom_filter => MAX_CUSTOM_FILTER, filter_index => FILTER_INDEX,
    file => FILE, max_file => MAX_FILE, file_title => FILE_TITLE,
    max_file_title => MAX_FILE_TITLE, initial_dir => INITIAL_DIR, title => TITLE,
    flags => FLAGS, file_offset => FILE_OFFSET, file_extension => FILE_EXTENSION,
    default_extension => DEFAULT_EXTENSION, custom_data => CUSTOM_DATA,
    hook => HOOK, template => TEMPLATE,
);
assert_wire_layout!(wire::ChooseColor16Wire, choosecolor16_offsets;
    structure_size => STRUCT_SIZE, owner => OWNER, instance => INSTANCE,
    initial_color => INITIAL_COLOR, custom_colors => CUSTOM_COLORS, flags => FLAGS,
    custom_data => CUSTOM_DATA, hook => HOOK, template => TEMPLATE,
);
assert_wire_layout!(wire::FindReplace16Wire, findreplace16_offsets;
    structure_size => STRUCT_SIZE, owner => OWNER, instance => INSTANCE,
    flags => FLAGS, find_text => FIND_TEXT, replace_text => REPLACE_TEXT,
    find_text_capacity => FIND_TEXT_CAPACITY,
    replace_text_capacity => REPLACE_TEXT_CAPACITY, custom_data => CUSTOM_DATA,
    hook => HOOK, template => TEMPLATE,
);
assert_wire_layout!(wire::ChooseFont16Wire, choosefont16_offsets;
    structure_size => STRUCT_SIZE, owner => OWNER, dc => DC, log_font => LOG_FONT,
    point_size => POINT_SIZE, flags => FLAGS, color => COLOR,
    custom_data => CUSTOM_DATA, hook => HOOK, template => TEMPLATE,
    instance => INSTANCE, style => STYLE, font_type => FONT_TYPE,
    min_size => MIN_SIZE, max_size => MAX_SIZE,
);
assert_wire_layout!(wire::PrintDlg16Wire, printdlg16_offsets;
    structure_size => STRUCT_SIZE, owner => OWNER, dev_mode => DEV_MODE,
    dev_names => DEV_NAMES, dc => DC, flags => FLAGS, from_page => FROM_PAGE,
    to_page => TO_PAGE, min_page => MIN_PAGE, max_page => MAX_PAGE, copies => COPIES,
    instance => INSTANCE, custom_data => CUSTOM_DATA, print_hook => PRINT_HOOK,
    setup_hook => SETUP_HOOK, print_template_name => PRINT_TEMPLATE_NAME,
    setup_template_name => SETUP_TEMPLATE_NAME, print_template => PRINT_TEMPLATE,
    setup_template => SETUP_TEMPLATE,
);
