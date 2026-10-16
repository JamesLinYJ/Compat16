//! LZEXPAND host-service delegation.

use super::{RuntimeError, WindowsHost};

pub(super) fn start() -> Result<i16, RuntimeError> {
    super::win16_compat_calls_lzexpand::start()
}

pub(super) fn done() -> Result<(), RuntimeError> {
    super::win16_compat_calls_lzexpand::done();
    Ok(())
}

pub(super) fn open_file(
    host: &mut WindowsHost,
    path: &runtime::Win16GuestPath,
    search_name: Option<&str>,
    style: u16,
    ofstruct: Vec<u8>,
) -> Result<runtime::Win16HostLzOpen, RuntimeError> {
    super::win16_lz_file_paths::open(
        &mut host.filesystem,
        &mut host.win16_files,
        host.win16_dcs.text_codec(),
        path,
        search_name,
        style,
        ofstruct,
    )
}

pub(super) fn init(
    host: &mut WindowsHost,
    file: runtime::Win16HostFile,
    can_create_stream: bool,
) -> Result<runtime::Win16HostLzInit, RuntimeError> {
    super::win16_compat_calls_lzexpand::init(&mut host.win16_files, file, can_create_stream)
}

pub(super) fn read(
    host: &WindowsHost,
    file: runtime::Win16HostFile,
    count: u16,
) -> Result<Option<runtime::Win16HostLzRead>, RuntimeError> {
    super::win16_compat_calls_lzexpand::read(&host.win16_files, file, count)
}

pub(super) fn seek(
    host: &WindowsHost,
    file: runtime::Win16HostFile,
    offset: i32,
    origin: u16,
) -> Result<Option<i32>, RuntimeError> {
    super::win16_compat_calls_lzexpand::seek(&host.win16_files, file, offset, origin)
}

pub(super) fn close(
    host: &mut WindowsHost,
    file: runtime::Win16HostFile,
) -> Result<runtime::Win16HostFileClose, RuntimeError> {
    super::win16_compat_calls_lzexpand::close(&mut host.win16_files, file)
}

pub(super) fn copy(
    host: &WindowsHost,
    source: runtime::Win16HostFile,
    destination: runtime::Win16HostFile,
) -> Result<Option<i32>, RuntimeError> {
    super::win16_compat_calls_lzexpand::copy(&host.win16_files, source, destination)
}

pub(super) fn expanded_name(
    host: &mut WindowsHost,
    source: &[u8],
    path: &runtime::Win16GuestPath,
    search_name: Option<&str>,
) -> Result<runtime::Win16HostLzName, RuntimeError> {
    super::win16_lz_file_paths::expanded_name(
        &mut host.filesystem, host.win16_dcs.text_codec(),
        source, path, search_name)
}

macro_rules! lz_runtime_host_methods {
    () => {
        fn win16_lz_start(&mut self) -> Result<i16, RuntimeError> {
            runtime_host_lz::start()
        }
        fn win16_lz_done(&mut self) -> Result<(), RuntimeError> {
            runtime_host_lz::done()
        }
        fn win16_lz_open_file(
            &mut self,
            path: &runtime::Win16GuestPath,
            search_name: Option<&str>,
            style: u16,
            ofstruct: Vec<u8>,
        ) -> Result<runtime::Win16HostLzOpen, RuntimeError> {
            runtime_host_lz::open_file(self, path, search_name, style, ofstruct)
        }
        fn win16_lz_init(
            &mut self,
            file: runtime::Win16HostFile,
            can_create_stream: bool,
        ) -> Result<runtime::Win16HostLzInit, RuntimeError> {
            runtime_host_lz::init(self, file, can_create_stream)
        }
        fn win16_lz_read(
            &mut self,
            file: runtime::Win16HostFile,
            count: u16,
        ) -> Result<Option<runtime::Win16HostLzRead>, RuntimeError> {
            runtime_host_lz::read(self, file, count)
        }
        fn win16_lz_seek(
            &mut self,
            file: runtime::Win16HostFile,
            offset: i32,
            origin: u16,
        ) -> Result<Option<i32>, RuntimeError> {
            runtime_host_lz::seek(self, file, offset, origin)
        }
        fn win16_lz_close(
            &mut self,
            file: runtime::Win16HostFile,
        ) -> Result<runtime::Win16HostFileClose, RuntimeError> {
            runtime_host_lz::close(self, file)
        }
        fn win16_lz_copy(
            &mut self,
            source: runtime::Win16HostFile,
            destination: runtime::Win16HostFile,
        ) -> Result<Option<i32>, RuntimeError> {
            runtime_host_lz::copy(self, source, destination)
        }
        fn win16_lz_get_expanded_name(
            &mut self,
            source: &[u8],
            path: &runtime::Win16GuestPath,
            search_name: Option<&str>,
        ) -> Result<runtime::Win16HostLzName, RuntimeError> {
            runtime_host_lz::expanded_name(self, source, path, search_name)
        }
    };
}

pub(super) use lz_runtime_host_methods;
