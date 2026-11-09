use super::*;
use crate::win16_runtime::test_support::tiny_ne_executable;

#[test]
fn external_module_usage_tracks_liveness_without_losing_its_process_lease() {
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], br"C:\APP.EXE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let identity = state
        .reserve_external_application(ExternalApplicationKind::Activation)
        .unwrap();
    let process = Win16HostProcess(42);
    state
        .commit_external_application(
            identity,
            ExternalApplicationKind::Activation,
            ExternalApplicationState::ProcessStarted { process },
        )
        .unwrap();
    assert_eq!(state.external_module_usage(identity, process, true), 1);
    assert_eq!(state.external_module_usage(identity, process, false), 0);
    assert_eq!(state.modules.records[&identity].explicit_refs, 1);
    assert_eq!(
        state.external_module_usage(identity, Win16HostProcess(43), true),
        0
    );
    state.modules.records.get_mut(&identity).unwrap().state = ModuleState::Unloading;
    assert_eq!(state.external_module_usage(identity, process, true), 0);
    assert_eq!(
        state
            .finish_external_module_release(identity, Some(process), true)
            .unwrap(),
        1
    );
    assert_eq!(state.external_module_usage(identity, process, true), 0);
}

#[test]
fn external_module_usage_does_not_treat_an_activation_receipt_as_a_process() {
    let mut runtime = crate::Runtime::load(&tiny_ne_executable(), &[], br"C:\APP.EXE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let identity = state
        .reserve_external_application(ExternalApplicationKind::Activation)
        .unwrap();
    state
        .commit_external_application(
            identity,
            ExternalApplicationKind::Activation,
            ExternalApplicationState::NativeActivationReceipt,
        )
        .unwrap();
    assert_eq!(
        state.external_module_usage(identity, Win16HostProcess(42), true),
        0
    );
}
