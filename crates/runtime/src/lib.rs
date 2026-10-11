//! One owner composes the emulated machine and its DOS service state.
#![forbid(unsafe_code)]

mod clock;
mod cpu_execution;
mod diagnostics;
mod environment;
mod hardware_interrupts;
mod input;
mod interrupts;
mod load;
mod machine;
mod multiplex;
mod network;
mod nls;
mod pe32;
mod pe32_call;
mod pe32_execute;
mod win32_import_host;
mod win32_import_catalog;
mod win32_import_state;
mod win32_import_bridge;
mod win32_import_guest;
pub use win32_import_host::{
    Win32HostEnvironmentCall, Win32HostFileCall, Win32HostHandle, Win32HostSearchHandle,
    Win32HostFindData, Win32HostImportCall,
    Win32HostImportFamily, Win32HostImportResult, Win32HostImportValue, Win32HostLoaderCall,
    Win32HostModule, Win32HostModuleOwner,
    Win32HostPathCall, Win32HostResolvedExport, Win32HostServiceIdentity,
    Win32HostServiceOperation, Win32HostSystemCall, Win32HostVolumeCall, Win32ImportString,
    Win32ImportSymbol, Win32ImportTextEncoding, Win32PathQuery, Win32PathTransform,
};
mod process;
mod services;
mod trace;
mod win16_builtin_data_exports;
mod win16_dde;
mod win16_io_trace;
mod win16_loader;
mod win16_runtime;
pub use win16_abi::{Win16CharacterClassification, network_print_abi};
pub use win16_io_trace::{
    Win16IoEvent, Win16ServiceBoundaryStage, Win16WindowCallbackPhase,
    Win16WindowCallbackProcedure, Win16WindowCallbackReturn, Win16WindowCreationApi,
    Win16WindowCreationPhase,
};
mod win16_callback_mailbox;
pub use win16_callback_mailbox::{
    Win16CallbackArgumentData, Win16GuestCallbackEvent, Win16GuestCallbackPoll,
    Win16GuestCallbackReceiver, Win16GuestCallbackSendError, Win16GuestCallbackSender,
    Win16GuestCallbackToken, win16_guest_callback_channel,
};
mod win16_host_control_messages;
mod win16_host_messages;
mod win16_host_owner_draw;
pub use win16_host_owner_draw::{Win16OwnerDrawMessage, Win16OwnerDrawTarget};
pub use host_boundary::Win16HostSystemClassInfo;
mod win16_host_midi;
mod win16_host_classic_dde;
pub use win16_host_classic_dde::*;
pub use win16_host_midi::{
    Win16HostMidiCall, Win16HostMidiCaps, Win16HostMidiCloseAll, Win16HostMidiCloseFailure,
    Win16HostMidiClosedDevice, Win16HostMidiDevice, Win16HostMidiDirection,
    Win16HostMidiProducerFailure, Win16HostMidiProducerOwner,
    Win16HostMidiProducerQuiescence, Win16HostMidiProducerReceipt,
    Win16HostMidiHeader, Win16HostMidiHeaderState, Win16HostMidiMixerId,
    Win16HostMidiNotification, Win16HostMidiNotificationId,
    Win16HostMidiNotificationDisposition, Win16HostMidiCancellationReason,
    Win16HostMidiResult, Win16HostMidiSubmission,
};
mod win16_host_nonclient;
pub use win16_host_control_messages::{
    Win16HostButtonMessage, Win16HostComboBoxMessage, Win16HostControlCall,
    Win16HostControlDispatch, Win16HostControlFamily, Win16HostControlIdentity,
    Win16HostControlItem, Win16HostControlMessage, Win16HostControlOutput, Win16HostControlQuery,
    Win16HostControlQueryReply, Win16HostControlReply, Win16HostControlResult,
    Win16HostControlValue, Win16HostEditMessage, Win16HostListBoxMessage, Win16HostStaticMessage,
    WIN16_CONTROL_TEXT_CAPACITY,
};
mod win16_host_window_input;
pub use win16_host_window_input::Win16WindowInputMessage;
mod win16_host_thunks;
pub use win16_host_thunks::{
    Win16ThunkArgument, Win16ThunkConvention, Win16ThunkOperation, Win16ThunkResult,
};
mod win16_host_menus;
mod win16_host_window_ops;
mod win16_host_window_properties;
pub use win16_host_window_properties::{Win16HostPropertyCallbackName, Win16HostPropertyName};
mod win16_host_window_data;
pub use win16_host_window_data::{
    Win16HostWindowParentObservation,
    Win16WindowDataCall, Win16WindowDataField, Win16WindowDataResult,
};
mod win16_host_common_controls;
mod win16_host_com;
pub use win16_host_com::{
    Win16ComHostOperationIdentity, Win16ComHostOwnerIdentity,
    Win16ComHostShutdownOperation, Win16ComHostShutdownReceipt, Win16ComHostShutdownStep,
    Win16ComHostCallbackFrame, Win16ComHostCallbackStep, Win16ComHostCallbackCall,
    Win16ComHostAdviseSinkCall, Win16ComHostFormatEtc, Win16ComHostMediumId,
    Win16ComHostOwnedMediumId, Win16ComHostCallbackRoute, Win16ComHostCallbackReply,
    Win16ComHostCallbackFailureKind, Win16ComHostCallbackFailure,
    Win16ComHostOperationFailure, Win16ComHostExecutionFailure,
    Win16ComHostCallbackOutcome, Win16ComHostCompletion, Win16ComHostStep,
    Win16ComHostResume, Win16ComHostStart, Win16ComHostContinue,
    Win16ComHostInterfaceCall, Win16ComHostStorageMedium, Win16ComHostRequest,
    Win16ComHostResult, Win16ComHostInterface, Win16OleHostOperation,
    Win16OleHostValue, Win16OleHostReply, Win16StorageHostOperation,
    Win16StorageHostReply,
};
mod win16_host_common_dialog;
mod win16_host_message_calls;
mod win16_host_user_services;
pub use win16_host_common_controls::{
    Win16HostCommonControlsOperation, Win16HostCommonControlsResult,
    Win16HostToolbarButton, Win16HostToolbarBitmap, Win16HostDragListKind,
    Win16HostDragListNotification, Win16HostMenuHelpResolution,
};
pub use win16_host_common_dialog::{
    Win16HostChooseColorDialog, Win16HostChooseFontDialog, Win16HostCommonDialogOperation,
    Win16HostCommonDialogResult, Win16HostFindReplaceDialog, Win16HostFindReplaceNotification,
    Win16HostFindReplaceUpdate, Win16HostOpenFileDialog, Win16HostPrintDialog,
};
mod win16_host_update_region;
pub use win16_host_update_region::{Win16HostUpdateOperation, Win16HostUpdateResult};
mod win16_host_scroll_bar;
pub use win16_host_scroll_bar::{Win16HostScrollBarOperation, Win16HostScrollBarResult};
mod win16_host_shell_execution;
pub use win16_host_shell_execution::{
    Win16HostProcess, Win16HostShellActivation, Win16HostShellExecutionOperation,
    Win16HostShellExecutionResult, Win16HostShellFailure, Win16HostShellInputEncodingFailure,
    Win16HostWinExecFailure,
    Win16HostShellPathEncodingCause, Win16HostShellPathEncodingFailure,
};
mod win16_host_netbios;
mod win16_host_network;
mod win16_host_nls;
mod win16_host_ime;
pub use win16_host_ime::{Win16HostImeProfile, Win16HostImeProfileCall, Win16HostImeProfileResult};
mod win16_host_path_info;
mod win16_network;
pub use win16_host_netbios::{
    Win16HostNetbiosBufferAccess, Win16HostNetbiosCall, Win16HostNetbiosId,
    Win16HostNetbiosOutput, Win16HostNetbiosPayload, Win16HostNetbiosResult,
    Win16HostNetbiosSubmission, Win16HostNetbiosTeardownPhase,
    Win16HostNetbiosTeardownReason, Win16HostNetbiosTeardownReceipt,
    Win16HostNetbiosCompletionPublication, Win16HostNetbiosFailureDiagnostics,
    Win16HostNetbiosFailureTally,
};
mod win16_sound_host;
pub use win16_sound_host::{
    Win16SoundHostOperation, Win16SoundHostResult, Win16SoundLease,
    Win16SoundPcmFormat, Win16SoundPlayback, Win16SoundPlaybackEvent,
    Win16SoundSession, Win16SoundSource, Win16SoundStopStatus, Win16SoundWaitTarget,
};
mod win16_host_wave;
mod win16_host_mci;
pub use win16_host_mci::*;
mod win16_media_services;
pub use win16_host_wave::{
    Win16HostWaveBuffer, Win16HostWaveCapabilities, Win16HostWaveCompletion, Win16HostWaveControl,
    Win16HostWaveDevice, Win16HostWaveDirection, Win16HostWaveEvent, Win16HostWaveEventKind,
    Win16HostWaveFormat, Win16HostWaveFormatShape, Win16HostWaveFormatSpec,
    Win16HostWaveHeaderState, Win16HostWaveInitialBuffer, Win16HostWaveMixerId,
    Win16HostWaveOperation, Win16HostWaveParameter, Win16HostWavePosition, Win16HostWaveResult,
    Win16HostWaveSubmission, Win16HostWaveSubmit,
};
mod win16_automation;
mod win16_automation_values;
mod win16_host_ole2disp_convert;
pub use win16_automation_values::{Win16AutomationValue, Win16SafeArrayBound, Win16SafeArrayValue};
pub(crate) use win16_host_ole2disp_convert::Win16AutomationConversionServices;
pub use win16_host_ole2disp_convert::{
    Win16Ole2DispConversionInput, Win16Ole2DispConversionOperation, Win16Ole2DispConversionResult,
    Win16Ole2DispConversionValue, Win16Ole2DispLocale,
};
mod win16_host_dde;
pub use win16_host_dde::{
    Win16DdeAbortOwnerStatus, Win16DdeAbortPhase, Win16DdeAbortReceipt,
    Win16DdeAbortWorkerStatus, Win16DdeCallbackCall, Win16DdeCallbackCancellation,
    Win16DdeCallbackCancellationStatus, Win16DdeCallbackReply, Win16DdeCallbackReplyRole,
    Win16DdeCancellationSource, Win16DdeCleanupFailure, Win16DdeCleanupStatus,
    Win16DdeNativeInstanceReceipt, Win16DdeNativeOwnerShutdownReceipt,
    Win16DdeNativeReplyReceipt, Win16DdeNativeTransferGuardReceipt,
    Win16DdeNativeTransferGuardSource, Win16DdeOperationCancellation,
    Win16DdeOperationCancellationStatus, Win16DdeOperationRetirement,
    Win16DdeOperationRetirementProof, Win16DdeOperationRequestPhase,
    Win16DdeSourceRetiredProof,
    Win16DdeOperationStartedFailure, Win16HostDdeOwner,
    Win16HostDdeCall, Win16HostDdeCallbackData,
    Win16HostDdeCallbackFrame, Win16HostDdeCallbackStep, Win16HostDdeContext,
    Win16HostDdeConversation, Win16HostDdeConversationInfo, Win16HostDdeConversationList,
    Win16HostDdeData, Win16HostDdeDataTransfer, Win16HostDdeDataTransferOutcome,
    Win16HostDdeInstance, Win16HostDdeOperation, Win16HostDdeResult, Win16HostDdeResume,
    Win16HostDdeStep, Win16HostDdeString, Win16HostDdeStringPair, Win16HostDdeTransactionData,
    Win16HostDdeValue,
};
pub use win16_host_network::{
    Win16HostAcceptedAsyncRegistration, Win16HostAsyncRequest,
    Win16HostAsyncTask, Win16HostNetworkCall, Win16HostNetworkEvent, Win16HostNetworkNameQuery,
    Win16HostNetworkNameResult, Win16HostNetworkResult, Win16HostNetworkValue, Win16HostSocket,
    Win16HostNetworkReferenceRelease, Win16HostSocketErrorReadToken,
    Win16HostSocketRetirementFailure, Win16HostSocketRetirementPhase, Win16NetworkTaskIdentity,
    Win16HostSocketOptionEncoding, Win16HostSocketOptionInput,
};
pub use win16_host_nls::{Win16NlsHostResult, Win16NlsOperation, Win16NlsString};
pub use win16_host_path_info::{
    Win16HostPathInfoOperation, Win16HostPathInfoResult, Win16HostTempFileName,
};
pub use win16_media_services::{
    Win16HostMediaIoHandle, Win16HostMediaIoOperation, Win16HostMediaIoResult,
    Win16HostMediaOpenResult, Win16HostMediaTimeOperation, Win16HostMediaTimeResult,
    Win16HostMediaTimeValue, Win16HostMmckInfo,
};
mod win16_host_shell_icons;
pub use win16_host_shell_icons::{Win16HostShellIconCall, Win16HostShellIconResult};
mod win16_host_user_cursor_accelerator;
pub use win16_host_user_cursor_accelerator::{
    Win16HostAccelEntry, Win16HostAccelerator, Win16HostHelpData,
    Win16HostUserCursorAcceleratorOperation, Win16HostUserCursorAcceleratorResult,
};
mod win16_environment;
mod win16_host_compat;
mod win16_host_gdi_bitmap;
mod win16_host_gdi_device;
mod win16_host_gdi_services;
mod win16_host_network_redirector;
pub use win16_host_network_redirector::{
    Win16HostNetworkRedirectorCall, Win16HostNetworkRedirectorResult,
    Win16HostNetworkRedirectorValue,
};
/// Existing Win16 task identity used only to scope host resource leases.
pub use guest_core::OwnerId as Win16HostTaskOwner;
mod win16_host_spool;
pub use win16_host_spool::{
    Win16HostNetworkPrintJobSnapshot, Win16HostNetworkPrintQueueSnapshot,
    Win16HostNetworkQueueOperation, Win16HostNetworkQueueResult,
    Win16HostNetworkQueueWatch, Win16HostSpoolDiagnostic, Win16HostSpoolJob,
    Win16HostSpoolOperation, Win16HostSpoolResult, Win16NetworkPrintJobControl,
};
pub use win16_host_gdi_services::{
    Win16GdiServicesOperation, Win16GdiServicesResult, Win16HostAbcWidth,
    Win16HostGdiIdentity, Win16HostKerningPair, Win16HostRasterizerCaps,
};
mod win16_host_gdi_objects;
mod win16_host_keyboard;
mod win16_host_registry;
pub use win16_host_keyboard::{Win16HostKeyboardCall, Win16HostKeyboardResult};
pub use win16_host_registry::{
    Win16HostRegistryKey, Win16HostRegistryOperation, Win16HostRegistryResult, Win16RegistryKeyRef,
    Win16RegistryRoot,
};
mod win16_host_drawing;
mod win16_host_images;
pub use win16_host_images::{Win16HostIconSize, Win16HostImageMasks};
pub use win16_host_drawing::{
    Win16DrawingOperation, Win16DrawingPoint, Win16DrawingRect, Win16DrawingResult, Win16HostBrush,
};
pub use win16_host_gdi_bitmap::{Win16GdiBitmapOperation, Win16GdiBitmapResult};
pub use win16_host_gdi_device::{
    Win16DibColorTableKind, Win16DitherPattern, Win16GdiDeviceOperation, Win16GdiDeviceResult,
    Win16GdiObjectInfo,
    Win16HostDibSection, Win16PaletteTransferKind, Win16PrintOperation,
};
pub use win16_host_gdi_objects::{
    Win16GdiObjectOperation, Win16HostBitmapInfo, Win16HostDib, Win16HostLogBrush,
    Win16HostLogFont, Win16HostLogPen,
};
pub use win16_host_message_calls::{Win16MessageCall, Win16MessageCallResult};
pub use win16_host_user_services::{
    Win16HostClipboardData, Win16HostClipboardOperation, Win16HostClipboardResult,
    Win16HostDialogAtom, Win16HostDialogControlOperation, Win16HostDialogControlResult,
    Win16HostDialogFont, Win16HostDialogItem, Win16HostDialogOperation, Win16HostDialogResult,
    Win16HostDialogTemplate, Win16HostFatalExitChoice, Win16HostSystemParametersResult,
    Win16HostSessionApiFailure, Win16HostSessionApiPhase, Win16HostSessionCleanupReceipt,
    Win16HostSessionOperation, Win16HostSessionResult, Win16HostUserServiceOperation,
    Win16HostUserServiceResult, Win16SystemParameterScalar, Win16SystemParametersRequest,
    Win16SystemParametersValue,
};
mod win16_host_printer;
pub use win16_host_compat::Win16HostResourceName;
pub use win16_host_printer::{
    Win16PrinterCapabilities, Win16PrinterCapabilitiesResult, Win16PrinterCapabilityData,
};
mod win16_host_dc;
pub use win16_host_dc::{Win16HostDevMode, Win16HostOutlineTextMetrics, Win16HostTextFace, Win16HostTextMetrics};
mod win16_host_acm;
pub use win16_host_acm::{
    Win16HostAcmChooseKind, Win16HostAcmDetailQuery, Win16HostAcmDriverDetails,
    Win16HostAcmEnumerationRecord, Win16HostAcmHandle, Win16HostAcmItemDetails,
    Win16HostAcmObjectKind, Win16HostAcmOperation, Win16HostAcmResult,
    Win16HostAcmNativeFailure, Win16HostAcmNativeOperation,
    Win16HostAcmTagDetails, Win16HostAcmTagKind,
};
mod mci_host_boundary;
pub use mci_host_boundary::*;
mod midi_host_boundary;
pub use midi_host_boundary::*;
mod netbios_host_boundary;
pub use netbios_host_boundary::RuntimeNetbiosHost;
mod host_boundary;
pub use host_boundary::*;
mod host_boundary_dde;
pub use host_boundary_dde::RuntimeDdeHost;

pub use win16_host_messages::{
    Win16HostCreationData, Win16HostMdiChildCreation, Win16HostClassName, Win16HostMessage, Win16HostDialogMessage,
    Win16HostMessageResult, Win16ScalarMessage, Win16HostActivationApp,
    Win16HostParentNotification, Win16HostParentNotificationData,
    Win16HostControlColor, Win16HostControlColorBrush,
    Win16HostWindowCreationResult, Win16NativeWindowApiReturn,
    Win16HostStaticIconOperation, Win16HostStaticIconResult,
    Win16HostRect, Win16HostPaintInfo,
    Win16HostQueuedMessage, Win16HostQueuedDelivery, Win16HostQueuedDropFiles,
    Win16HostDropRetirementReceipt,
    Win16HostDropFilesLease, Win16MessageFilter, Win16MessageParam, Win16MessageSource,
    Win16MessageWindow,
    Win16CreationId, Win16HostCallback, Win16HostWindowOperationId, Win16WindowOperation,
    Win16WindowReply, Win16WindowResult,
    Win16HostTaskQueue, Win16GuestNotification, Win16GuestNotificationSource,
    Win16GuestNotificationTarget, Win16GuestNotificationProvenance,
    is_multimedia_notification_message, multimedia_notification_has_guest_far_lparam,
    WIN16_APP_MESSAGE_NOTIFICATION_SOURCE_ID,
    Win16WindowStep, Win16WindowOperationStartedFailure,
    Win16WindowTerminalSourceTop,
    Win16WindowSourceRetiredProof,
    Win16NativeModalCancellation, Win16NativeModalCancelSignal,
    Win16NativeModalGuestWorkRetirement, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationProof, Win16NativeWindowOperationState,
    Win16WindowTerminalAck, Win16NativeCallbackSource,
    Win16NativeCallbackCancellation,
    Win16NativeWindowResourceSnapshot, Win16NativeResourceRetirement,
    Win16WindowCreationRejection,
    Win16WindowAbortReceipt,
    Win16HostPoint, Win16HostMinMaxInfo, Win16HostMessageOutput, Win16HostDropFiles,
};
pub use win16_host_menus::{
    Win16MenuItem, Win16MenuItemContent, Win16MenuItemIdentity, Win16MenuOperation,
    Win16MenuResult, Win16MenuTemplate, Win16MenuTemplateItem,
};
pub use win16_host_nonclient::{Win16HostNonClientCalcSize, Win16HostWindowPos};
pub(crate) use win16_host_window_ops::Win16WindowCallOutput;
pub use win16_host_window_ops::{
    Win16CaretShape,
    Win16WindowEnumerationScope, Win16WindowEnumerationQuery, Win16WindowEnumerationReply,
    Win16WindowCall, Win16WindowCallResult, Win16WindowInsertAfter, Win16WindowSearchClass,
    Win16WindowTarget, Win16WindowPlacement,
};

pub use diagnostics::{Diagnostic, DiagnosticKind, DiagnosticSeverity, RuntimeError};
pub use load::MINIMUM_PSP_SEGMENT;
pub use machine::{Runtime, RuntimeProgress};

pub use guest_core::Registers as GuestRegisters;
use xms::GuestFarPointer;

/// Registered guest firmware far-call entry, backed by an ordinary RETF.
const XMS_ENTRY: GuestFarPointer = GuestFarPointer {
    segment: 0xf000,
    offset: 0x0100,
};

pub use win16_runtime::mdi_client_creation::Win16HostMdiClientCreate;
pub use win16_runtime::messages_mdi::{
    Win16GuestMdiMessage, Win16HostMdiCreate, Win16HostMdiCreateFields,
    Win16HostMdiMessage, Win16HostMdiMessageQueuedKind, Win16HostMdiMessageResult,
    Win16HostMdiOutput, Win16HostMdiQueuedMessage, Win16HostWindowRetirementBatch,
    Win16HostWindowRetirementReceipt,
    Win16MdiEndpoint,
};
pub use win16_runtime::kernel_file_system::{
    Win16HostDiskSpace, Win16HostFileSystemCall, Win16HostFileSystemOperation,
    Win16HostFileSystemResult, Win16HostFindData, Win16HostFindFirst,
    Win16HostSearchId, Win16CanonicalPath, Win16GuestPath, Win16HostFileSystemPath,
    Win16PathComponent, Win16PathComponentSource, Win16PathNamespace,
};

pub(crate) fn runtime_error(error: impl Into<RuntimeError>) -> RuntimeError {
    error.into()
}
