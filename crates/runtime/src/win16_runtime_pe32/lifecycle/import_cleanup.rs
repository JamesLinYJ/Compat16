//! Task resource cleanup after every PE32 image owner has retired.

use super::*;
use super::super::aggregate_errors;

impl Pe32ThunkDispatcher {
    pub(super) fn retire_import_resources(
        &mut self,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let handle_count = imports.live_guest_handles().count();
        let search_count = imports.live_guest_search_handles().count();
        let provider_count = imports.live_system_modules().count();
        let mut handles = Vec::new();
        let mut searches = Vec::new();
        let mut providers = Vec::new();
        let mut first_error = None;
        if let Err(error) = handles.try_reserve_exact(handle_count) {
            keep_first(
                &mut first_error,
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve PE32 task HANDLE cleanup list",
                    error,
                ),
            );
        } else {
            handles.extend(imports.live_guest_handles());
        }
        if let Err(error) = searches.try_reserve_exact(search_count) {
            keep_first(&mut first_error, RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve PE32 task search cleanup list", error));
        } else {
            searches.extend(imports.live_guest_search_handles());
        }
        if let Err(error) = providers.try_reserve_exact(provider_count) {
            keep_first(
                &mut first_error,
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve PE32 task module cleanup list",
                    error,
                ),
            );
        } else {
            providers.extend(imports.live_system_modules());
        }
        for (guest, handle) in searches {
            if let Err(error) = imports.begin_close_search_handle(guest) {
                keep_first(&mut first_error, error);
                continue;
            }
            match host.win32_import(Win32HostImportCall::CloseOwnedSearchHandle { handle }) {
                Ok(response) => {
                    let last_error = response.last_error;
                    let error = match response.value {
                        Win32HostImportValue::Bool(true) => {
                            imports.finish_close_search_handle(guest, true).err()
                        }
                        Win32HostImportValue::Bool(false) => {
                            let primary = native_cleanup_failure(
                                "FindClose for PE32 task search",
                                Win32HostImportValue::Bool(false), last_error);
                            match imports.finish_close_search_handle(guest, false) {
                                Ok(()) => Some(primary),
                                Err(cleanup) => Some(aggregate_errors(
                                    "native search close and owner restoration failed",
                                    primary, cleanup)),
                            }
                        }
                        value => {
                            let primary = native_cleanup_failure(
                                "FindClose for PE32 task search", value, last_error);
                            match imports.finish_close_search_handle(guest, false) {
                                Ok(()) => Some(primary),
                                Err(cleanup) => Some(aggregate_errors(
                                    "native search result and owner restoration failed",
                                    primary, cleanup)),
                            }
                        }
                    };
                    if let Some(error) = error { keep_first(&mut first_error, error); }
                }
                Err(primary) => {
                    let error = match imports.finish_close_search_handle(guest, false) {
                        Ok(()) => primary,
                        Err(cleanup) => aggregate_errors(
                            "task search close failed and owner restoration failed",
                            primary, cleanup),
                    };
                    keep_first(&mut first_error, error);
                }
            }
        }
        for (guest, handle) in handles {
            if let Err(error) = imports.begin_close_handle(guest) {
                keep_first(&mut first_error, error);
                continue;
            }
            match host.win32_import(Win32HostImportCall::CloseOwnedHandle { handle }) {
                Ok(response) => {
                    let last_error = response.last_error;
                    let error = match response.value {
                        Win32HostImportValue::Bool(true) => {
                            imports.finish_close_handle(guest, true).err()
                        }
                        Win32HostImportValue::Bool(false) => {
                            let primary = native_cleanup_failure(
                                "CloseHandle for PE32 task resource",
                                Win32HostImportValue::Bool(false),
                                last_error,
                            );
                            match imports.finish_close_handle(guest, false) {
                                Ok(()) => Some(primary),
                                Err(cleanup) => Some(aggregate_errors(
                                    "native HANDLE close and owner restoration failed",
                                    primary,
                                    cleanup,
                                )),
                            }
                        }
                        value => {
                            let primary = native_cleanup_failure(
                                "CloseHandle for PE32 task resource",
                                value,
                                last_error,
                            );
                            match imports.finish_close_handle(guest, false) {
                                Ok(()) => Some(primary),
                                Err(cleanup) => Some(aggregate_errors(
                                    "native HANDLE result and owner restoration failed",
                                    primary,
                                    cleanup,
                                )),
                            }
                        }
                    };
                    if let Some(error) = error {
                        keep_first(&mut first_error, error);
                    }
                }
                Err(primary) => {
                    let error = match imports.finish_close_handle(guest, false) {
                        Ok(()) => primary,
                        Err(cleanup) => aggregate_errors(
                            "task HANDLE close failed and state restoration failed",
                            primary,
                            cleanup,
                        ),
                    };
                    keep_first(&mut first_error, error);
                }
            }
        }
        for identity in providers {
            let host_owner = match imports.host_owner(identity) {
                Ok(owner) => owner,
                Err(error) => {
                    keep_first(&mut first_error, error);
                    continue;
                }
            };
            let native = match imports.begin_shutdown_release_module(identity) {
                Ok(Some(native)) => native,
                Ok(None) => {
                    keep_first(
                        &mut first_error,
                        RuntimeError::new(
                            Kind::CompatibilityGap,
                            "PE32 system module remains pinned during task shutdown",
                        ),
                    );
                    continue;
                }
                Err(error) => {
                    keep_first(&mut first_error, error);
                    continue;
                }
            };
            match host.win32_import(Win32HostImportCall::FreeSystemModule {
                module: native, owner: host_owner,
            }) {
                Ok(response) => {
                    let last_error = response.last_error;
                    let error = match response.value {
                        Win32HostImportValue::Bool(true) => {
                            imports.finish_release_module(identity, true).err()
                        }
                        Win32HostImportValue::Bool(false) => {
                            let primary = native_cleanup_failure(
                                "FreeLibrary during PE32 task shutdown",
                                Win32HostImportValue::Bool(false),
                                last_error,
                            );
                            match imports.finish_release_module(identity, false) {
                                Ok(()) => Some(primary),
                                Err(cleanup) => Some(aggregate_errors(
                                    "native module release and owner restoration failed",
                                    primary,
                                    cleanup,
                                )),
                            }
                        }
                        value => {
                            let primary = native_cleanup_failure(
                                "FreeLibrary during PE32 task shutdown",
                                value,
                                last_error,
                            );
                            Some(finish_provider_release(imports, identity, false, primary))
                        }
                    };
                    if let Some(error) = error {
                        keep_first(&mut first_error, error);
                    }
                }
                Err(primary) => keep_first(
                    &mut first_error,
                    finish_provider_release(imports, identity, false, primary),
                ),
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
