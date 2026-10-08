// The target signatures come from the repository-owned MMSYSTEM specification
// and SDK 3.1 MMSYSTEM.H. `mciExecute` stays declared even though SDK source
// compatibility guards its prototype for pre-3.1 consumers.
macro_rules! export_catalog_with_mci {
    ($($existing:tt)*) => {
        export_catalog_with_kernel_diagnostics! {
            $($existing)*
            MciSendCommand => MMSYSTEM_MCI_SEND_COMMAND:
                ("MMSYSTEM", 701u16, Stack, mci::SEND_COMMAND, Dword);
            MciSendString => MMSYSTEM_MCI_SEND_STRING:
                ("MMSYSTEM", 702u16, Stack, mci::SEND_STRING, Dword);
            MciGetDeviceId => MMSYSTEM_MCI_GET_DEVICE_ID:
                ("MMSYSTEM", 703u16, Stack, mci::DEVICE_NAME, Word);
            MciLoadCommandResource => MMSYSTEM_MCI_LOAD_COMMAND_RESOURCE:
                ("MMSYSTEM", 705u16, Stack, mci::LOAD_COMMAND_RESOURCE, Word);
            MciGetErrorString => MMSYSTEM_MCI_GET_ERROR_STRING:
                ("MMSYSTEM", 706u16, Stack, mci::ERROR_STRING, Word);
            MciSetDriverData => MMSYSTEM_MCI_SET_DRIVER_DATA:
                ("MMSYSTEM", 707u16, Stack, mci::SET_DRIVER_DATA, Word);
            MciGetDriverData => MMSYSTEM_MCI_GET_DRIVER_DATA:
                ("MMSYSTEM", 708u16, Stack, mci::DEVICE_ID, Dword);
            MciDriverYield => MMSYSTEM_MCI_DRIVER_YIELD:
                ("MMSYSTEM", 710u16, Stack, mci::DEVICE_ID, Word);
            MciDriverNotify => MMSYSTEM_MCI_DRIVER_NOTIFY:
                ("MMSYSTEM", 711u16, Stack, mci::DRIVER_NOTIFY, Word);
            MciExecute => MMSYSTEM_MCI_EXECUTE:
                ("MMSYSTEM", 712u16, Stack, mci::COMMAND_STRING, Word);
            MciFreeCommandResource => MMSYSTEM_MCI_FREE_COMMAND_RESOURCE:
                ("MMSYSTEM", 713u16, Stack, mci::DEVICE_ID, Word);
            MciSetYieldProc => MMSYSTEM_MCI_SET_YIELD_PROC:
                ("MMSYSTEM", 714u16, Stack, mci::SET_YIELD_PROC, Word);
            MciGetDeviceIdFromElement => MMSYSTEM_MCI_GET_DEVICE_ID_FROM_ELEMENT:
                ("MMSYSTEM", 715u16, Stack, mci::ELEMENT_ID, Word);
            MciGetYieldProc => MMSYSTEM_MCI_GET_YIELD_PROC:
                ("MMSYSTEM", 716u16, Stack, mci::GET_YIELD_PROC, FarPointer);
            MciGetCreatorTask => MMSYSTEM_MCI_GET_CREATOR_TASK:
                ("MMSYSTEM", 717u16, Stack, mci::DEVICE_ID, Word);
        }
    };
}
