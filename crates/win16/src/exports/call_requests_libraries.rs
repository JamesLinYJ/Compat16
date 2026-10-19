//! Export decoder arms owned by the Libraries API module group.

use super::*;
use super::super::{ExportLookupTarget, call_win16_multimedia};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    // Binding ids 4000000–4999999 are the OLE stack rows that had no call.
    // Already-bound OLE2DISP, OLE2NLS, OLE1, and IsEqualGUID stay on their
    // existing decoders; those ids are outside this range.
    let id = descriptor.id as u32;
    // Binding ids 6000000–6999999 are the library rows and leftover OLE rows
    // that had no call. Already-bound rows stay on their existing decoders.
    if (6_000_000..7_000_000).contains(&id) {
        return Ok(Some(Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::LibraryRemainder {
                ordinal: descriptor.ordinal(),
            },
        )));
    }
    // Binding ids 9200000–9299999 are library signatures recovered from
    // public Microsoft documentation. Guest far pointers stay on the stack.
    if (9_200_000..9_300_000).contains(&id) {
        if descriptor.ordinal() == 111 && descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
            return Ok(Some(Win16ApiRequest::Joystick(
                super::super::call_joystick::decode(descriptor, arguments)?,
            )));
        }
        return Ok(Some(Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::LibraryRemainder {
                ordinal: descriptor.ordinal(),
            },
        )));
    }
    // Binding ids 9100000–9199999 are OLE rows whose frames come from the
    // public Learn reference. They use the same failure returns as the
    // earlier OLE remainder.
    if (9_100_000..9_200_000).contains(&id) || (4_000_000..5_000_000).contains(&id) {
        let module = super::Win16OleRemainderModule::from_catalog_name(descriptor.module())
            .ok_or(Win16Error::InvalidRange)?;
        return Ok(Some(Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::OleRemainder {
                module,
                ordinal: descriptor.ordinal(),
            },
        )));
    }
    if descriptor.id == Win16ExportId::DriverWinspool90Extdevicemode {
        return Ok(Some(Win16ApiRequest::Printer(
            decode_ext_device_mode(arguments, selectors, memory)?,
        )));
    }
    if let Some(request) = super::call_driver::decode(descriptor, arguments)? {
        return Ok(Some(Win16ApiRequest::Driver(request)));
    }
    if matches!(descriptor.module(), "OLECLI" | "OLESVR") {
        return super::super::call_ole1::decode_ole1(
            descriptor.module(), descriptor.ordinal(), arguments, selectors, memory,
        ).map(|request| request.map(Win16ApiRequest::Ole1));
    }
    if descriptor.module().eq_ignore_ascii_case("WINNLS") {
        return super::super::call_winnls::decode(descriptor, arguments, selectors, memory)
            .map(|request| Some(Win16ApiRequest::Winnls(request)));
    }
    if descriptor.module().eq_ignore_ascii_case("WINMEM32") {
        return super::super::call_winmem32::decode(descriptor.ordinal(), arguments)
            .map(|request| request.map(Win16ApiRequest::Winmem32));
    }
    if descriptor.module().eq_ignore_ascii_case("MSACM") {
        return call_win16_multimedia::decode_multimedia_export(
            descriptor.module().as_bytes(),
            ExportLookupTarget::Ordinal(descriptor.ordinal()),
            arguments,
            selectors,
            memory,
        );
    }

    let request = match descriptor.id {
        Win16ExportId::CompobjIsEqualGuid => {
            super::guid_compare_calls::decode(arguments, selectors, memory)?
        }
        Win16ExportId::DdeInitialize
        | Win16ExportId::DdeUninitialize
        | Win16ExportId::DdeConnectList
        | Win16ExportId::DdeQueryNextServer
        | Win16ExportId::DdeDisconnectList
        | Win16ExportId::DdeConnect
        | Win16ExportId::DdeDisconnect
        | Win16ExportId::DdeQueryConvInfo
        | Win16ExportId::DdeSetUserHandle
        | Win16ExportId::DdeClientTransaction
        | Win16ExportId::DdeAbandonTransaction
        | Win16ExportId::DdePostAdvise
        | Win16ExportId::DdeCreateDataHandle
        | Win16ExportId::DdeAddData
        | Win16ExportId::DdeGetData
        | Win16ExportId::DdeAccessData
        | Win16ExportId::DdeUnaccessData
        | Win16ExportId::DdeFreeDataHandle
        | Win16ExportId::DdeGetLastError
        | Win16ExportId::DdeCreateStringHandle
        | Win16ExportId::DdeFreeStringHandle
        | Win16ExportId::DdeQueryString
        | Win16ExportId::DdeKeepStringHandle
        | Win16ExportId::DdeEnableCallback
        | Win16ExportId::DdeNameService
        | Win16ExportId::DdeCmpStringHandles
        | Win16ExportId::DdeReconnect => Win16ApiRequest::Dde(
            super::super::call_dde::decode_ddeml(
                descriptor.ordinal(),
                arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?,
        ),
        Win16ExportId::Ole2DispSysAllocString
        | Win16ExportId::Ole2DispSysReallocString
        | Win16ExportId::Ole2DispSysAllocStringLen
        | Win16ExportId::Ole2DispSysReAllocStringLen
        | Win16ExportId::Ole2DispSysFreeString
        | Win16ExportId::Ole2DispSysStringLen
        | Win16ExportId::Ole2DispVariantInit
        | Win16ExportId::Ole2DispVariantClear
        | Win16ExportId::Ole2DispVariantCopy
        | Win16ExportId::Ole2DispVariantCopyInd
        | Win16ExportId::Ole2DispSafeArrayCreate
        | Win16ExportId::Ole2DispSafeArrayDestroy
        | Win16ExportId::Ole2DispSafeArrayGetDim
        | Win16ExportId::Ole2DispSafeArrayGetElemsize
        | Win16ExportId::Ole2DispSafeArrayGetUBound
        | Win16ExportId::Ole2DispSafeArrayGetLBound
        | Win16ExportId::Ole2DispSafeArrayLock
        | Win16ExportId::Ole2DispSafeArrayUnlock
        | Win16ExportId::Ole2DispSafeArrayAccessData
        | Win16ExportId::Ole2DispSafeArrayUnaccessData
        | Win16ExportId::Ole2DispSafeArrayGetElement
        | Win16ExportId::Ole2DispSafeArrayPutElement
        | Win16ExportId::Ole2DispSafeArrayPtrOfIndex
        | Win16ExportId::Ole2DispSafeArrayCopy
        | Win16ExportId::Ole2DispSafeArrayAllocDescriptor
        | Win16ExportId::Ole2DispSafeArrayAllocData
        | Win16ExportId::Ole2DispSafeArrayDestroyDescriptor
        | Win16ExportId::Ole2DispSafeArrayDestroyData => Win16ApiRequest::Ole2Disp(
            super::super::call_ole2disp::decode(descriptor, arguments, selectors, memory)?,
        ),
        Win16ExportId::AuxGetNumDevs
        | Win16ExportId::AuxGetDevCaps
        | Win16ExportId::AuxGetVolume
        | Win16ExportId::AuxSetVolume
        | Win16ExportId::AuxOutMessage => Win16ApiRequest::Aux(
            super::super::call_aux::decode(descriptor, arguments)?,
        ),
        Win16ExportId::MmsystemMixerGetNumDevs
        | Win16ExportId::MmsystemMixerGetDevCaps
        | Win16ExportId::MmsystemMixerOpen
        | Win16ExportId::MmsystemMixerClose
        | Win16ExportId::MmsystemMixerMessage
        | Win16ExportId::MmsystemMixerGetLineInfo
        | Win16ExportId::MmsystemMixerGetId
        | Win16ExportId::MmsystemMixerGetLineControls
        | Win16ExportId::MmsystemMixerGetControlDetails
        | Win16ExportId::MmsystemMixerSetControlDetails => Win16ApiRequest::Mixer(
            super::super::call_mixer::decode(descriptor, arguments)?,
        ),
        Win16ExportId::MediaTimeGetSystemTime
        | Win16ExportId::MediaTimeGetDevCaps
        | Win16ExportId::MediaTimeBeginPeriod
        | Win16ExportId::MediaTimeEndPeriod
        | Win16ExportId::MediaTimeGetTime
        | Win16ExportId::MediaTimeSetEvent
        | Win16ExportId::MediaTimeKillEvent => Win16ApiRequest::MediaTime(
            super::super::call_media_time::decode(descriptor, arguments)?,
        ),
        Win16ExportId::MmsystemJoyGetNumDevs
        | Win16ExportId::MmsystemJoyGetDevCaps
        | Win16ExportId::MmsystemJoyGetPos
        | Win16ExportId::MmsystemJoyGetThreshold
        | Win16ExportId::MmsystemJoyReleaseCapture
        | Win16ExportId::MmsystemJoySetCapture
        | Win16ExportId::MmsystemJoySetThreshold
        | Win16ExportId::MmsystemJoySetCalibration
        | Win16ExportId::MmsystemJoyGetPosEx => Win16ApiRequest::Joystick(
            super::super::call_joystick::decode(descriptor, arguments)?,
        ),
        Win16ExportId::MediaIoOpen
        | Win16ExportId::MediaIoClose
        | Win16ExportId::MediaIoRead
        | Win16ExportId::MediaIoWrite
        | Win16ExportId::MediaIoSeek
        | Win16ExportId::MediaIoFlush
        | Win16ExportId::MediaIoStringToFourCc
        | Win16ExportId::MediaIoDescend
        | Win16ExportId::MediaIoAscend
        | Win16ExportId::MediaIoCreateChunk
        | Win16ExportId::MediaIoRename
        | Win16ExportId::MediaIoGetInfo
        | Win16ExportId::MediaIoSetInfo
        | Win16ExportId::MediaIoSetBuffer
        | Win16ExportId::MediaIoAdvance
        | Win16ExportId::MediaIoInstallIoProc
        | Win16ExportId::MediaIoSendMessage => Win16ApiRequest::MediaIo(
            super::super::call_media_io::decode(descriptor, arguments, selectors, memory)?,
        ),
        Win16ExportId::MidiOutGetNumDevs
        | Win16ExportId::MidiOutGetDevCaps
        | Win16ExportId::MidiOutGetErrorText
        | Win16ExportId::MidiOutOpen
        | Win16ExportId::MidiOutClose
        | Win16ExportId::MidiOutPrepareHeader
        | Win16ExportId::MidiOutUnprepareHeader
        | Win16ExportId::MidiOutShortMsg
        | Win16ExportId::MidiOutLongMsg
        | Win16ExportId::MidiOutReset
        | Win16ExportId::MidiOutGetVolume
        | Win16ExportId::MidiOutSetVolume
        | Win16ExportId::MidiOutCachePatches
        | Win16ExportId::MidiOutCacheDrumPatches
        | Win16ExportId::MidiOutGetId
        | Win16ExportId::MidiOutMessage
        | Win16ExportId::MidiStreamProperty
        | Win16ExportId::MidiStreamOpen
        | Win16ExportId::MidiStreamClose
        | Win16ExportId::MidiStreamPosition
        | Win16ExportId::MidiStreamOut
        | Win16ExportId::MidiStreamPause
        | Win16ExportId::MidiStreamRestart
        | Win16ExportId::MidiStreamStop
        | Win16ExportId::MidiInGetNumDevs
        | Win16ExportId::MidiInGetDevCaps
        | Win16ExportId::MidiInGetErrorText
        | Win16ExportId::MidiInOpen
        | Win16ExportId::MidiInClose
        | Win16ExportId::MidiInPrepareHeader
        | Win16ExportId::MidiInUnprepareHeader
        | Win16ExportId::MidiInAddBuffer
        | Win16ExportId::MidiInStart
        | Win16ExportId::MidiInStop
        | Win16ExportId::MidiInReset
        | Win16ExportId::MidiInGetId
        | Win16ExportId::MidiInMessage => Win16ApiRequest::Midi(
            super::super::call_midi::decode(descriptor, &arguments)?,
        ),
        Win16ExportId::MmsystemWaveOutGetNumDevs
        | Win16ExportId::MmsystemWaveOutGetDevCaps
        | Win16ExportId::MmsystemWaveOutGetErrorText
        | Win16ExportId::MmsystemWaveOutOpen
        | Win16ExportId::MmsystemWaveOutClose
        | Win16ExportId::MmsystemWaveOutPrepareHeader
        | Win16ExportId::MmsystemWaveOutUnprepareHeader
        | Win16ExportId::MmsystemWaveOutWrite
        | Win16ExportId::MmsystemWaveOutPause
        | Win16ExportId::MmsystemWaveOutRestart
        | Win16ExportId::MmsystemWaveOutReset
        | Win16ExportId::MmsystemWaveOutBreakLoop
        | Win16ExportId::MmsystemWaveOutGetPitch
        | Win16ExportId::MmsystemWaveOutSetPitch
        | Win16ExportId::MmsystemWaveOutGetVolume
        | Win16ExportId::MmsystemWaveOutSetVolume
        | Win16ExportId::MmsystemWaveOutGetPlaybackRate
        | Win16ExportId::MmsystemWaveOutSetPlaybackRate
        | Win16ExportId::MmsystemWaveOutGetID
        | Win16ExportId::MmsystemWaveOutMessage
        | Win16ExportId::MmsystemWaveOutGetPosition
        | Win16ExportId::MmsystemWaveInGetNumDevs
        | Win16ExportId::MmsystemWaveInGetDevCaps
        | Win16ExportId::MmsystemWaveInGetErrorText
        | Win16ExportId::MmsystemWaveInOpen
        | Win16ExportId::MmsystemWaveInClose
        | Win16ExportId::MmsystemWaveInPrepareHeader
        | Win16ExportId::MmsystemWaveInUnprepareHeader
        | Win16ExportId::MmsystemWaveInAddBuffer
        | Win16ExportId::MmsystemWaveInStart
        | Win16ExportId::MmsystemWaveInStop
        | Win16ExportId::MmsystemWaveInReset
        | Win16ExportId::MmsystemWaveInGetID
        | Win16ExportId::MmsystemWaveInMessage
        | Win16ExportId::MmsystemWaveInGetPosition => Win16ApiRequest::Libraries(
            Win16LibraryRequest::Wave(super::super::call_wave::decode(descriptor, arguments)?),
        ),
        Win16ExportId::SoundOpen
        | Win16ExportId::SoundClose
        | Win16ExportId::SoundSetVoiceQueueSize
        | Win16ExportId::SoundSetVoiceNote
        | Win16ExportId::SoundSetVoiceAccent
        | Win16ExportId::SoundSetVoiceEnvelope
        | Win16ExportId::SoundSetSoundNoise
        | Win16ExportId::SoundSetVoiceSound
        | Win16ExportId::SoundStart
        | Win16ExportId::SoundStop
        | Win16ExportId::SoundWaitState
        | Win16ExportId::SoundSyncAllVoices
        | Win16ExportId::SoundCountVoiceNotes
        | Win16ExportId::SoundGetThresholdEvent
        | Win16ExportId::SoundGetThresholdStatus
        | Win16ExportId::SoundSetVoiceThreshold
        | Win16ExportId::MultimediaSndPlaySound
        | Win16ExportId::MultimediaPlaySound => Win16ApiRequest::Sound(
            super::super::call_sound::decode(descriptor.id, arguments)?,
        ),
        Win16ExportId::MciSendCommand
        | Win16ExportId::MciSendString
        | Win16ExportId::MciGetDeviceId
        | Win16ExportId::MciLoadCommandResource
        | Win16ExportId::MciGetErrorString
        | Win16ExportId::MciSetDriverData
        | Win16ExportId::MciGetDriverData
        | Win16ExportId::MciDriverYield
        | Win16ExportId::MciDriverNotify
        | Win16ExportId::MciExecute
        | Win16ExportId::MciFreeCommandResource
        | Win16ExportId::MciSetYieldProc
        | Win16ExportId::MciGetDeviceIdFromElement
        | Win16ExportId::MciGetYieldProc
        | Win16ExportId::MciGetCreatorTask => Win16ApiRequest::Mci(
            super::super::call_mci::decode(descriptor, arguments, selectors, memory)?,
        ),
        Win16ExportId::WinsockAccept
        | Win16ExportId::WinsockBind
        | Win16ExportId::WinsockCloseSocket
        | Win16ExportId::WinsockConnect
        | Win16ExportId::WinsockGetPeerName
        | Win16ExportId::WinsockGetSocketName
        | Win16ExportId::WinsockGetSocketOption
        | Win16ExportId::WinsockHostToNetworkLong
        | Win16ExportId::WinsockHostToNetworkShort
        | Win16ExportId::WinsockInetAddress
        | Win16ExportId::WinsockInetName
        | Win16ExportId::WinsockIoctlSocket
        | Win16ExportId::WinsockListen
        | Win16ExportId::WinsockNetworkToHostLong
        | Win16ExportId::WinsockNetworkToHostShort
        | Win16ExportId::WinsockReceive
        | Win16ExportId::WinsockReceiveFrom
        | Win16ExportId::WinsockSelect
        | Win16ExportId::WinsockSend
        | Win16ExportId::WinsockSendTo
        | Win16ExportId::WinsockSetSocketOption
        | Win16ExportId::WinsockShutdown
        | Win16ExportId::WinsockCreateSocket
        | Win16ExportId::WinsockGetHostByAddress
        | Win16ExportId::WinsockGetHostByName
        | Win16ExportId::WinsockGetProtocolByName
        | Win16ExportId::WinsockGetProtocolByNumber
        | Win16ExportId::WinsockGetServiceByName
        | Win16ExportId::WinsockGetServiceByPort
        | Win16ExportId::WinsockGetHostName
        | Win16ExportId::WinsockAsyncSelect
        | Win16ExportId::WinsockAsyncGetHostByAddress
        | Win16ExportId::WinsockAsyncGetHostByName
        | Win16ExportId::WinsockAsyncGetProtocolByNumber
        | Win16ExportId::WinsockAsyncGetProtocolByName
        | Win16ExportId::WinsockAsyncGetServiceByPort
        | Win16ExportId::WinsockAsyncGetServiceByName
        | Win16ExportId::WinsockCancelAsyncRequest
        | Win16ExportId::WinsockSetBlockingHook
        | Win16ExportId::WinsockUnhookBlockingHook
        | Win16ExportId::WinsockGetLastError
        | Win16ExportId::WinsockSetLastError
        | Win16ExportId::WinsockCancelBlockingCall
        | Win16ExportId::WinsockIsBlocking
        | Win16ExportId::WinsockStartup
        | Win16ExportId::WinsockCleanup
        | Win16ExportId::WinsockFdIsSet
        | Win16ExportId::WinsockReceiveEx
        | Win16ExportId::WinsockDefaultHook => {
            let request = super::super::call_network::decode_winsock(
                descriptor.ordinal(),
                arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?;
            Win16ApiRequest::Winsock(request)
        }
        Win16ExportId::ToolhelpStackTraceFirst
        | Win16ExportId::ToolhelpStackTraceCsipFirst
        | Win16ExportId::ToolhelpStackTraceNext => Win16ApiRequest::ToolhelpStack(
            super::super::request::decode_toolhelp_stack(descriptor.ordinal(), arguments)?
                .ok_or(Win16Error::InvalidRange)?,
        ),
        Win16ExportId::Ole2NlsGetUserDefaultLcid
        | Win16ExportId::Ole2NlsGetSystemDefaultLcid
        | Win16ExportId::Ole2NlsGetUserDefaultLangId
        | Win16ExportId::Ole2NlsGetSystemDefaultLangId
        | Win16ExportId::Ole2NlsGetLocaleInfoA
        | Win16ExportId::Ole2NlsLcMapStringA
        | Win16ExportId::Ole2NlsGetStringTypeA
        | Win16ExportId::Ole2NlsCompareStringA => Win16ApiRequest::Ole2Nls(
            super::super::call_ole2nls::decode(descriptor, arguments, selectors, memory)?,
        ),
        Win16ExportId::CommdlgGetOpenFileName
        | Win16ExportId::CommdlgGetSaveFileName
        | Win16ExportId::CommdlgChooseColor
        | Win16ExportId::CommdlgFindText
        | Win16ExportId::CommdlgReplaceText
        | Win16ExportId::CommdlgChooseFont
        | Win16ExportId::CommdlgPrintDlg
        | Win16ExportId::CommdlgGetFileTitle
        | Win16ExportId::CommdlgExtendedError => {
            super::super::call_commdlg::decode(descriptor, arguments, selectors, memory)?
        }
        Win16ExportId::Ctl3dGetVersion
        | Win16ExportId::Ctl3dSubclassDialog
        | Win16ExportId::Ctl3dSubclassControl
        | Win16ExportId::Ctl3dControlColor
        | Win16ExportId::Ctl3dIsEnabled
        | Win16ExportId::Ctl3dColorChange
        | Win16ExportId::Ctl3dRegister
        | Win16ExportId::Ctl3dUnregister
        | Win16ExportId::Ctl3dAutoSubclass
        | Win16ExportId::Ctl3dControlColorEx
        | Win16ExportId::Ctl3dDlgFramePaint
        | Win16ExportId::Ctl3dSubclassDialogEx
        | Win16ExportId::Ctl3dWinIniChange
        | Win16ExportId::Ctl3dIsAutoSubclass
        | Win16ExportId::Ctl3dUnAutoSubclass
        | Win16ExportId::Ctl3dSubclassControlEx
        | Win16ExportId::Ctl3dUnsubclassControl
        | Win16ExportId::Ctl3dAutoSubclassEx
        | Win16ExportId::Ctl3dV2GetVersion
        | Win16ExportId::Ctl3dV2SubclassDialog
        | Win16ExportId::Ctl3dV2SubclassControl
        | Win16ExportId::Ctl3dV2ControlColor
        | Win16ExportId::Ctl3dV2IsEnabled
        | Win16ExportId::Ctl3dV2ColorChange
        | Win16ExportId::Ctl3dV2Register
        | Win16ExportId::Ctl3dV2Unregister
        | Win16ExportId::Ctl3dV2AutoSubclass
        | Win16ExportId::Ctl3dV2ControlColorEx
        | Win16ExportId::Ctl3dV2DlgFramePaint
        | Win16ExportId::Ctl3dV2SubclassDialogEx
        | Win16ExportId::Ctl3dV2WinIniChange
        | Win16ExportId::Ctl3dV2IsAutoSubclass
        | Win16ExportId::Ctl3dV2UnAutoSubclass
        | Win16ExportId::Ctl3dV2SubclassControlEx
        | Win16ExportId::Ctl3dV2UnsubclassControl
        | Win16ExportId::Ctl3dV2AutoSubclassEx => {
            super::super::call_ctl3d::decode(descriptor, arguments)?
        }
        Win16ExportId::CommctrlMenuHelp
        | Win16ExportId::CommctrlGetEffectiveClientRect
        | Win16ExportId::CommctrlCreateStatusWindow
        | Win16ExportId::CommctrlCreateToolbar
        | Win16ExportId::CommctrlCreateMappedBitmap
        | Win16ExportId::CommctrlCreateHeaderWindow
        | Win16ExportId::CommctrlWritePrivateProfileStruct
        | Win16ExportId::CommctrlGetPrivateProfileStruct
        | Win16ExportId::CommctrlMakeDragList
        | Win16ExportId::CommctrlInitCommonControls
        | Win16ExportId::CommctrlCreateToolbarEx => {
            super::super::call_commctrl::decode(descriptor, &arguments, selectors, memory)?
        }
        Win16ExportId::WingCreateDc
        | Win16ExportId::WingRecommendDibFormat
        | Win16ExportId::WingCreateBitmap
        | Win16ExportId::WingGetDibPointer
        | Win16ExportId::WingGetDibColorTable
        | Win16ExportId::WingSetDibColorTable
        | Win16ExportId::WingCreateHalfTonePalette
        | Win16ExportId::WingCreateHalfToneBrush
        | Win16ExportId::WingStretchBlt
        | Win16ExportId::WingBitBlt => Win16ApiRequest::GdiDevice(
            gdi_device_calls::decode(
                descriptor.module().as_bytes(),
                descriptor.ordinal(),
                &arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?,
        ),
        Win16ExportId::WinspoolDeviceCapabilities => {
            Win16ApiRequest::Printer(decode_device_capabilities(&arguments, selectors, memory)?)
        }
        Win16ExportId::ShellExtractIcon
        | Win16ExportId::ShellExtractAssociatedIcon
        | Win16ExportId::ShellInternalExtractIcon
        | Win16ExportId::ShellExtractIconEx => Win16ApiRequest::ShellIcon(
            decode_shell_icon_export(descriptor.ordinal(), &arguments, selectors, memory)?,
        ),
        Win16ExportId::ShellExecute
        | Win16ExportId::ShellFindExecutable
        | Win16ExportId::ShellAbout => {
            Win16ApiRequest::ShellExecution(super::super::request::decode_shell_execution_export(
                descriptor.ordinal(),
                &arguments,
                selectors,
                memory,
            )?)
        }
        Win16ExportId::ShellDragAcceptFiles
        | Win16ExportId::ShellDragQueryFile
        | Win16ExportId::ShellDragFinish
        | Win16ExportId::ShellDragQueryPoint
        | Win16ExportId::ShellFormatDrive => Win16ApiRequest::ShellDrop(
            super::super::request::decode_shell_drop_export(
                descriptor.ordinal(), &arguments,
            )?,
        ),
        Win16ExportId::ShellDriveType => Win16ApiRequest::ShellDrive(
            super::super::request::decode_shell_drive_type(&arguments)?,
        ),
        Win16ExportId::ToolhelpLocalInfo
        | Win16ExportId::ToolhelpLocalFirst
        | Win16ExportId::ToolhelpLocalNext
        | Win16ExportId::ToolhelpModuleFirst
        | Win16ExportId::ToolhelpModuleNext
        | Win16ExportId::ToolhelpModuleFindName
        | Win16ExportId::ToolhelpModuleFindHandle
        | Win16ExportId::ToolhelpTaskFirst
        | Win16ExportId::ToolhelpTaskNext
        | Win16ExportId::ToolhelpTaskFindHandle
        | Win16ExportId::ToolhelpClassFirst
        | Win16ExportId::ToolhelpClassNext
        | Win16ExportId::ToolhelpTerminateApp
        | Win16ExportId::ToolhelpMemoryRead
        | Win16ExportId::ToolhelpMemoryWrite
        | Win16ExportId::ToolhelpTimerCount
        | Win16ExportId::ToolhelpTaskGetCsip
        | Win16ExportId::ToolhelpSystemHeapInfo
        | Win16ExportId::ToolhelpMemManInfo
        | Win16ExportId::ToolhelpTaskSetCsip
        | Win16ExportId::ToolhelpTaskSwitch
        | Win16ExportId::ToolhelpNotifyRegister
        | Win16ExportId::ToolhelpNotifyUnregister
        | Win16ExportId::SystemGetSystemMsecCount => {
            kernel_service_calls::decode(descriptor.id, &arguments, selectors, memory)?
                .ok_or(Win16Error::InvalidRange)?
        }
        Win16ExportId::KeyboardToAscii
        | Win16ExportId::KeyboardAnsiToOem
        | Win16ExportId::KeyboardSetSpeed
        | Win16ExportId::KeyboardScreenSwitchEnable
        | Win16ExportId::KeyboardOemKeyScan
        | Win16ExportId::KeyboardVkKeyScan
        | Win16ExportId::KeyboardGetKeyboardType
        | Win16ExportId::KeyboardMapVirtualKey
        | Win16ExportId::KeyboardGetKBCodePage
        | Win16ExportId::KeyboardGetKeyNameText
        | Win16ExportId::KeyboardAnsiToOemBuff
        | Win16ExportId::KeyboardOemToAnsiBuff => Win16ApiRequest::Keyboard(
            decode_keyboard_export(descriptor.id.ordinal(), &arguments, selectors, memory)?,
        ),
        Win16ExportId::WifemanMiscIsDbcsLeadByte => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::CodePage(
                super::Win16LibraryCodePageRequest::IsDbcsLeadByte {
                    value: decode_wifeman_dbcs_lead_byte(&arguments)?,
                },
            ))
        }
        Win16ExportId::ShellRegOpenKey
        | Win16ExportId::ShellRegCreateKey
        | Win16ExportId::ShellRegCloseKey
        | Win16ExportId::ShellRegDeleteKey
        | Win16ExportId::ShellRegSetValue
        | Win16ExportId::ShellRegQueryValue
        | Win16ExportId::ShellRegEnumKey => Win16ApiRequest::ShellRegistry(
            Win16ShellRegistryRequest::decode_export(descriptor.id.ordinal(), &arguments, selectors, memory)?,
        ),
        Win16ExportId::Win87emFpMath => {
            return Err(Win16Error::UnsupportedRegisterContextExport);
        }
        Win16ExportId::KeyboardOemToAnsi => Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::Strings(super::Win16LibraryStringsRequest::OemToAnsi {
                source: read_far_string(dword_argument(&arguments, 0)?, selectors, memory)?,
                destination: dword_argument(&arguments, 1)?,
            }),
        ),
        Win16ExportId::ToolhelpGlobalHandleToSel
        | Win16ExportId::ToolhelpGlobalFirst
        | Win16ExportId::ToolhelpGlobalNext
        | Win16ExportId::ToolhelpGlobalInfo
        | Win16ExportId::ToolhelpGlobalEntryHandle
        | Win16ExportId::ToolhelpGlobalEntryModule
        | Win16ExportId::ToolhelpInterruptRegister
        | Win16ExportId::ToolhelpInterruptUnregister => {
            toolhelp_calls::decode(descriptor.id, &arguments)?
        }
        Win16ExportId::VerGetFileResourceSize
        | Win16ExportId::VerGetFileResource
        | Win16ExportId::VerGetFileVersionInfoSize
        | Win16ExportId::VerGetFileVersionInfo
        | Win16ExportId::VerFindFile
        | Win16ExportId::VerInstallFile
        | Win16ExportId::VerLanguageName
        | Win16ExportId::VerQueryValue
        | Win16ExportId::LzexpandLzCopy
        | Win16ExportId::LzexpandLzOpenFile
        | Win16ExportId::LzexpandLzInit
        | Win16ExportId::LzexpandLzSeek
        | Win16ExportId::LzexpandLzRead
        | Win16ExportId::LzexpandLzClose
        | Win16ExportId::LzexpandLzStart
        | Win16ExportId::LzexpandCopyLzFile
        | Win16ExportId::LzexpandLzDone
        | Win16ExportId::LzexpandGetExpandedName
        | Win16ExportId::ShellDoEnvironmentSubst
        | Win16ExportId::ShellFindEnvironmentString => {
            win16_service_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::Ole2DispVariantChangeType
        | Win16ExportId::Ole2DispVarI2FromI4
        | Win16ExportId::Ole2DispVarI2FromR4
        | Win16ExportId::Ole2DispVarI2FromR8
        | Win16ExportId::Ole2DispVarI2FromCy
        | Win16ExportId::Ole2DispVarI2FromDate
        | Win16ExportId::Ole2DispVarI2FromStr
        | Win16ExportId::Ole2DispVarI2FromBool
        | Win16ExportId::Ole2DispVarI4FromStr
        | Win16ExportId::Ole2DispVarR4FromR8
        | Win16ExportId::Ole2DispVarR4FromStr
        | Win16ExportId::Ole2DispVarR8FromStr
        | Win16ExportId::Ole2DispVarDateFromStr
        | Win16ExportId::Ole2DispVarCyFromStr
        | Win16ExportId::Ole2DispVarBstrFromI2
        | Win16ExportId::Ole2DispVarBstrFromI4
        | Win16ExportId::Ole2DispVarBstrFromR4
        | Win16ExportId::Ole2DispVarBstrFromR8
        | Win16ExportId::Ole2DispVarBstrFromCy
        | Win16ExportId::Ole2DispVarBstrFromDate
        | Win16ExportId::Ole2DispVarBstrFromDisp
        | Win16ExportId::Ole2DispVarBstrFromBool
        | Win16ExportId::Ole2DispVariantChangeTypeEx
        | Win16ExportId::Ole2DispVarUI1FromI2
        | Win16ExportId::Ole2DispVarUI1FromI4
        | Win16ExportId::Ole2DispVarUI1FromR4
        | Win16ExportId::Ole2DispVarUI1FromR8
        | Win16ExportId::Ole2DispVarUI1FromCy
        | Win16ExportId::Ole2DispVarUI1FromDate
        | Win16ExportId::Ole2DispVarUI1FromStr
        | Win16ExportId::Ole2DispVarUI1FromDisp
        | Win16ExportId::Ole2DispVarUI1FromBool
        | Win16ExportId::Ole2DispVarI2FromUI1
        | Win16ExportId::Ole2DispVarBstrFromUI1 => Win16ApiRequest::Ole2DispConvert(
            super::super::call_ole2disp_convert::decode(descriptor, arguments, selectors, memory)?,
        ),
        _ => return Ok(None),
    };
    Ok(Some(request))
}
