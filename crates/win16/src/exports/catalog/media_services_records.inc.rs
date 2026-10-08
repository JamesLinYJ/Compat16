// Synchronous timer and MMIO bindings with pointer-free native operations.
macro_rules! export_catalog_with_media_services {
    ($($existing:tt)*) => {
        export_catalog_with_sound! {
            $($existing)*
            MediaTimeGetSystemTime => MMSYSTEM_TIME_GET_SYSTEM_TIME:
                ("MMSYSTEM", 601u16, Stack, media_time::GET_SYSTEM_TIME, Word);
            MediaTimeGetDevCaps => MMSYSTEM_TIME_GET_DEV_CAPS:
                ("MMSYSTEM", 604u16, Stack, media_time::GET_DEV_CAPS, Word);
            MediaTimeBeginPeriod => MMSYSTEM_TIME_BEGIN_PERIOD:
                ("MMSYSTEM", 605u16, Stack, media_time::PERIOD, Word);
            MediaTimeEndPeriod => MMSYSTEM_TIME_END_PERIOD:
                ("MMSYSTEM", 606u16, Stack, media_time::PERIOD, Word);
            MediaTimeGetTime => MMSYSTEM_TIME_GET_TIME:
                ("MMSYSTEM", 607u16, Stack, &[], Dword);
            MediaIoOpen => MMSYSTEM_MMIO_OPEN:
                ("MMSYSTEM", 1210u16, Stack, media_io::OPEN, Word);
            MediaIoClose => MMSYSTEM_MMIO_CLOSE:
                ("MMSYSTEM", 1211u16, Stack, media_io::CLOSE, Word);
            MediaIoRead => MMSYSTEM_MMIO_READ:
                ("MMSYSTEM", 1212u16, Stack, media_io::TRANSFER, Dword);
            MediaIoWrite => MMSYSTEM_MMIO_WRITE:
                ("MMSYSTEM", 1213u16, Stack, media_io::TRANSFER, Dword);
            MediaIoSeek => MMSYSTEM_MMIO_SEEK:
                ("MMSYSTEM", 1214u16, Stack, media_io::SEEK, Dword);
            MediaIoFlush => MMSYSTEM_MMIO_FLUSH:
                ("MMSYSTEM", 1218u16, Stack, media_io::FLUSH, Word);
            MediaIoStringToFourCc => MMSYSTEM_MMIO_STRING_TO_FOURCC:
                ("MMSYSTEM", 1220u16, Stack, media_io::STRING_TO_FOURCC, Dword);
            MediaIoDescend => MMSYSTEM_MMIO_DESCEND:
                ("MMSYSTEM", 1223u16, Stack, media_io::DESCEND, Word);
            MediaIoAscend => MMSYSTEM_MMIO_ASCEND:
                ("MMSYSTEM", 1224u16, Stack, media_io::CHUNK, Word);
            MediaIoCreateChunk => MMSYSTEM_MMIO_CREATE_CHUNK:
                ("MMSYSTEM", 1225u16, Stack, media_io::CHUNK, Word);
            MediaIoRename => MMSYSTEM_MMIO_RENAME:
                ("MMSYSTEM", 1226u16, Stack, media_io::RENAME, Word);
            MsacmDllEntryPoint => MSACM_DLL_ENTRY_POINT:
                ("MSACM", 3u16, Stack, msacm::DLL_ENTRY_POINT, Dword);
            MsacmGetVersion => MSACM_GET_VERSION:
                ("MSACM", 7u16, Stack, &[], Dword);
            MsacmMetrics => MSACM_METRICS:
                ("MSACM", 8u16, Stack, msacm::METRICS, Word);
            MsacmDriverEnum => MSACM_DRIVER_ENUM:
                ("MSACM", 10u16, Stack, msacm::DRIVER_ENUM, Word);
            MsacmDriverDetails => MSACM_DRIVER_DETAILS:
                ("MSACM", 11u16, Stack, msacm::DRIVER_DETAILS, Word);
            MsacmDriverAdd => MSACM_DRIVER_ADD:
                ("MSACM", 12u16, Stack, msacm::DRIVER_ADD, Word);
            MsacmDriverRemove => MSACM_DRIVER_REMOVE:
                ("MSACM", 13u16, Stack, msacm::DRIVER_REMOVE, Word);
            MsacmDriverOpen => MSACM_DRIVER_OPEN:
                ("MSACM", 14u16, Stack, msacm::DRIVER_OPEN, Word);
            MsacmDriverClose => MSACM_DRIVER_CLOSE:
                ("MSACM", 15u16, Stack, msacm::DRIVER_CLOSE, Word);
            MsacmDriverMessage => MSACM_DRIVER_MESSAGE:
                ("MSACM", 16u16, Stack, msacm::DRIVER_MESSAGE, Dword);
            MsacmDriverId => MSACM_DRIVER_ID:
                ("MSACM", 17u16, Stack, msacm::DRIVER_ID, Word);
            MsacmDriverPriority => MSACM_DRIVER_PRIORITY:
                ("MSACM", 18u16, Stack, msacm::DRIVER_PRIORITY, Word);
            MsacmFormatTagDetails => MSACM_FORMAT_TAG_DETAILS:
                ("MSACM", 30u16, Stack, msacm::OBJECT_DETAILS, Word);
            MsacmFormatTagEnum => MSACM_FORMAT_TAG_ENUM:
                ("MSACM", 31u16, Stack, msacm::TAG_ENUM, Word);
            MsacmFormatChoose => MSACM_FORMAT_CHOOSE:
                ("MSACM", 40u16, Stack, msacm::ONE_POINTER, Word);
            MsacmFormatDetails => MSACM_FORMAT_DETAILS:
                ("MSACM", 41u16, Stack, msacm::OBJECT_DETAILS, Word);
            MsacmFormatEnum => MSACM_FORMAT_ENUM:
                ("MSACM", 42u16, Stack, msacm::TAG_ENUM, Word);
            MsacmFormatSuggest => MSACM_FORMAT_SUGGEST:
                ("MSACM", 45u16, Stack, msacm::FORMAT_SUGGEST, Word);
            MsacmFilterTagDetails => MSACM_FILTER_TAG_DETAILS:
                ("MSACM", 50u16, Stack, msacm::OBJECT_DETAILS, Word);
            MsacmFilterTagEnum => MSACM_FILTER_TAG_ENUM:
                ("MSACM", 51u16, Stack, msacm::TAG_ENUM, Word);
            MsacmFilterChoose => MSACM_FILTER_CHOOSE:
                ("MSACM", 60u16, Stack, msacm::ONE_POINTER, Word);
            MsacmFilterDetails => MSACM_FILTER_DETAILS:
                ("MSACM", 61u16, Stack, msacm::OBJECT_DETAILS, Word);
            MsacmFilterEnum => MSACM_FILTER_ENUM:
                ("MSACM", 62u16, Stack, msacm::TAG_ENUM, Word);
            MsacmStreamOpen => MSACM_STREAM_OPEN:
                ("MSACM", 70u16, Stack, msacm::STREAM_OPEN, Word);
            MsacmStreamClose => MSACM_STREAM_CLOSE:
                ("MSACM", 71u16, Stack, msacm::OBJECT_FLAGS, Word);
            MsacmStreamSize => MSACM_STREAM_SIZE:
                ("MSACM", 72u16, Stack, msacm::STREAM_SIZE, Word);
            MsacmStreamConvert => MSACM_STREAM_CONVERT:
                ("MSACM", 75u16, Stack, msacm::STREAM_HEADER_FLAGS, Word);
            MsacmStreamReset => MSACM_STREAM_RESET:
                ("MSACM", 76u16, Stack, msacm::OBJECT_FLAGS, Word);
            MsacmStreamPrepareHeader => MSACM_STREAM_PREPARE_HEADER:
                ("MSACM", 77u16, Stack, msacm::STREAM_HEADER_FLAGS, Word);
            MsacmStreamUnprepareHeader => MSACM_STREAM_UNPREPARE_HEADER:
                ("MSACM", 78u16, Stack, msacm::STREAM_HEADER_FLAGS, Word);
        }
    };
}
