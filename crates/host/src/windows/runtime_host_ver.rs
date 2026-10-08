//! VERSION resource host-service delegation.

use super::RuntimeError;

pub(super) fn resource_size(
    codec: super::guest_text::GuestTextCodec,
    path: &[u8],
    resource_type: &runtime::Win16HostResourceName,
    resource_name: &runtime::Win16HostResourceName,
) -> Result<Option<(u32, u32)>, RuntimeError> {
    super::win16_compat_calls_ver::resource_size(codec, path, resource_type, resource_name)
}

pub(super) fn resource(
    codec: super::guest_text::GuestTextCodec,
    path: &[u8],
    resource_type: &runtime::Win16HostResourceName,
    resource_name: &runtime::Win16HostResourceName,
    offset: u32,
    count: u32,
    initial: Vec<u8>,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    super::win16_compat_calls_ver::resource(
        codec,
        path,
        resource_type,
        resource_name,
        offset,
        count,
        initial,
    )
}

pub(super) fn file_info_size(
    codec: super::guest_text::GuestTextCodec,
    path: &[u8],
) -> Result<Option<(u32, u32)>, RuntimeError> {
    super::win16_compat_calls_ver::file_info_size(codec, path)
}

pub(super) fn file_info(
    codec: super::guest_text::GuestTextCodec,
    path: &[u8],
    handle: u32,
    initial: Vec<u8>,
) -> Result<Option<(Vec<u8>, u32)>, RuntimeError> {
    super::win16_compat_calls_ver::file_info(codec, path, handle, initial)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn find_file(
    codec: super::guest_text::GuestTextCodec,
    flags: u16,
    file: &[u8],
    windows_dir: &[u8],
    app_dir: &[u8],
    dir_buffer: Vec<u8>,
    dir_capacity: u16,
    file_buffer: Vec<u8>,
    file_capacity: u16,
) -> Result<(u32, Vec<u8>, u16, Vec<u8>, u16), RuntimeError> {
    super::win16_compat_calls_ver::find_file(
        codec,
        flags,
        file,
        windows_dir,
        app_dir,
        dir_buffer,
        dir_capacity,
        file_buffer,
        file_capacity,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn install_file(
    codec: super::guest_text::GuestTextCodec,
    flags: u16,
    source: &[u8],
    destination: &[u8],
    source_dir: &[u8],
    destination_dir: &[u8],
    current_dir: &[u8],
    scratch: Vec<u8>,
    capacity: u16,
) -> Result<(u32, Vec<u8>, u16), RuntimeError> {
    super::win16_compat_calls_ver::install_file(
        codec,
        flags,
        source,
        destination,
        source_dir,
        destination_dir,
        current_dir,
        scratch,
        capacity,
    )
}

pub(super) fn language_name(
    codec: super::guest_text::GuestTextCodec,
    language: u16,
    initial: Vec<u8>,
) -> Result<(Vec<u8>, u32), RuntimeError> {
    super::win16_compat_calls_ver::language_name(codec, language, initial)
}

pub(super) fn query_value(
    block: Vec<u8>,
    sub_block: &[u8],
) -> Result<Option<(usize, u32)>, RuntimeError> {
    super::win16_compat_calls_ver::query_value(block, sub_block)
}

macro_rules! ver_runtime_host_methods {
    () => {
        fn win16_ver_resource_size(
            &mut self,
            path: &[u8],
            resource_type: &runtime::Win16HostResourceName,
            resource_name: &runtime::Win16HostResourceName,
        ) -> Result<Option<(u32, u32)>, RuntimeError> {
            runtime_host_ver::resource_size(
                self.win16_dcs.text_codec(),
                path,
                resource_type,
                resource_name,
            )
        }
        fn win16_ver_resource(
            &mut self,
            path: &[u8],
            resource_type: &runtime::Win16HostResourceName,
            resource_name: &runtime::Win16HostResourceName,
            offset: u32,
            count: u32,
            initial: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, RuntimeError> {
            runtime_host_ver::resource(
                self.win16_dcs.text_codec(),
                path,
                resource_type,
                resource_name,
                offset,
                count,
                initial,
            )
        }
        fn win16_ver_file_info_size(
            &mut self,
            path: &[u8],
        ) -> Result<Option<(u32, u32)>, RuntimeError> {
            runtime_host_ver::file_info_size(self.win16_dcs.text_codec(), path)
        }
        fn win16_ver_file_info(
            &mut self,
            path: &[u8],
            handle: u32,
            initial: Vec<u8>,
        ) -> Result<Option<(Vec<u8>, u32)>, RuntimeError> {
            runtime_host_ver::file_info(self.win16_dcs.text_codec(), path, handle, initial)
        }
        fn win16_ver_find_file(
            &mut self,
            flags: u16,
            file: &[u8],
            windows_dir: &[u8],
            app_dir: &[u8],
            dir_buffer: Vec<u8>,
            dir_capacity: u16,
            file_buffer: Vec<u8>,
            file_capacity: u16,
        ) -> Result<(u32, Vec<u8>, u16, Vec<u8>, u16), RuntimeError> {
            runtime_host_ver::find_file(
                self.win16_dcs.text_codec(),
                flags,
                file,
                windows_dir,
                app_dir,
                dir_buffer,
                dir_capacity,
                file_buffer,
                file_capacity,
            )
        }
        fn win16_ver_install_file(
            &mut self,
            flags: u16,
            source: &[u8],
            destination: &[u8],
            source_dir: &[u8],
            destination_dir: &[u8],
            current_dir: &[u8],
            scratch: Vec<u8>,
            capacity: u16,
        ) -> Result<(u32, Vec<u8>, u16), RuntimeError> {
            runtime_host_ver::install_file(
                self.win16_dcs.text_codec(),
                flags,
                source,
                destination,
                source_dir,
                destination_dir,
                current_dir,
                scratch,
                capacity,
            )
        }
        fn win16_ver_language_name(
            &mut self,
            language: u16,
            initial: Vec<u8>,
        ) -> Result<(Vec<u8>, u32), RuntimeError> {
            runtime_host_ver::language_name(self.win16_dcs.text_codec(), language, initial)
        }
        fn win16_ver_query_value(
            &mut self,
            block: Vec<u8>,
            sub_block: &[u8],
        ) -> Result<Option<(usize, u32)>, RuntimeError> {
            runtime_host_ver::query_value(block, sub_block)
        }
    };
}

pub(super) use ver_runtime_host_methods;
