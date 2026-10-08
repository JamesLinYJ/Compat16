// Insert these ABI descriptors in the export catalog after loading
// `kernel_services.rs`; each row is backed by a typed decoder and runtime method.

KernelGetModuleName => KERNEL_GET_MODULE_NAME: ("KERNEL", 27u16, Stack, kernel_services::KERNEL_GET_MODULE_NAME, Word);
KernelGetCurrentPdb => KERNEL_GET_CURRENT_PDB: ("KERNEL", 37u16, Stack, &[], Dword);
KernelReserved1 => KERNEL_RESERVED1: ("KERNEL", 77u16, Stack, kernel_services::KERNEL_ANSI_NEXT, FarPointer);
KernelReserved2 => KERNEL_RESERVED2: ("KERNEL", 78u16, Stack, kernel_services::KERNEL_ANSI_PREV, FarPointer);
KernelReserved3 => KERNEL_RESERVED3: ("KERNEL", 79u16, Stack, kernel_services::KERNEL_ANSI_CASE, FarPointer);
KernelReserved4 => KERNEL_RESERVED4: ("KERNEL", 80u16, Stack, kernel_services::KERNEL_ANSI_CASE, FarPointer);
KernelGetExeVersion => KERNEL_GET_EXE_VERSION: ("KERNEL", 105u16, Stack, &[], Word);
KernelGetExePtr => KERNEL_GET_EXE_PTR: ("KERNEL", 133u16, Stack, kernel_services::KERNEL_GET_EXE_PTR, Word);
KernelGetNumTasks => KERNEL_GET_NUM_TASKS: ("KERNEL", 152u16, Stack, &[], Word);
KernelGetTaskDs => KERNEL_GET_TASK_DS: ("KERNEL", 155u16, Stack, &[], Word);
KernelGetExpWinVer => KERNEL_GET_EXP_WIN_VER: ("KERNEL", 167u16, Stack, kernel_services::KERNEL_GET_EXP_WIN_VER, Word);
KernelIsTask => KERNEL_IS_TASK: ("KERNEL", 320u16, Stack, kernel_services::KERNEL_IS_TASK, Word);
KernelIsBadReadPtr => KERNEL_IS_BAD_READ_PTR: ("KERNEL", 334u16, Stack, kernel_services::KERNEL_BAD_POINTER, Word);
KernelIsBadWritePtr => KERNEL_IS_BAD_WRITE_PTR: ("KERNEL", 335u16, Stack, kernel_services::KERNEL_BAD_POINTER, Word);
KernelIsBadCodePtr => KERNEL_IS_BAD_CODE_PTR: ("KERNEL", 336u16, Stack, kernel_services::KERNEL_BAD_CODE_POINTER, Word);
KernelIsBadStringPtr => KERNEL_IS_BAD_STRING_PTR: ("KERNEL", 337u16, Stack, kernel_services::KERNEL_BAD_STRING_POINTER, Word);
KernelIsBadHugeReadPtr => KERNEL_IS_BAD_HUGE_READ_PTR: ("KERNEL", 346u16, Stack, kernel_services::KERNEL_BAD_HUGE_POINTER, Word);
KernelIsBadHugeWritePtr => KERNEL_IS_BAD_HUGE_WRITE_PTR: ("KERNEL", 347u16, Stack, kernel_services::KERNEL_BAD_HUGE_POINTER, Word);
KernelLstrcatn => KERNEL_LSTRCATN: ("KERNEL", 352u16, Stack, kernel_services::KERNEL_LSTRN, FarPointer);
KernelLstrcpyn => KERNEL_LSTRCPYN: ("KERNEL", 353u16, Stack, kernel_services::KERNEL_LSTRN, FarPointer);

ToolhelpLocalInfo => TOOLHELP_LOCAL_INFO: ("TOOLHELP", 56u16, Stack, kernel_services::TOOLHELP_LOCAL_INFO, Word);
ToolhelpLocalFirst => TOOLHELP_LOCAL_FIRST: ("TOOLHELP", 57u16, Stack, kernel_services::TOOLHELP_LOCAL_INFO, Word);
ToolhelpLocalNext => TOOLHELP_LOCAL_NEXT: ("TOOLHELP", 58u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpModuleFirst => TOOLHELP_MODULE_FIRST: ("TOOLHELP", 59u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpModuleNext => TOOLHELP_MODULE_NEXT: ("TOOLHELP", 60u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpModuleFindName => TOOLHELP_MODULE_FIND_NAME: ("TOOLHELP", 61u16, Stack, kernel_services::TOOLHELP_FIND_NAME, Word);
ToolhelpModuleFindHandle => TOOLHELP_MODULE_FIND_HANDLE: ("TOOLHELP", 62u16, Stack, kernel_services::TOOLHELP_FIND_HANDLE, Word);
ToolhelpTaskFirst => TOOLHELP_TASK_FIRST: ("TOOLHELP", 63u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpTaskNext => TOOLHELP_TASK_NEXT: ("TOOLHELP", 64u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpTaskFindHandle => TOOLHELP_TASK_FIND_HANDLE: ("TOOLHELP", 65u16, Stack, kernel_services::TOOLHELP_FIND_HANDLE, Word);
ToolhelpClassFirst => TOOLHELP_CLASS_FIRST: ("TOOLHELP", 69u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpClassNext => TOOLHELP_CLASS_NEXT: ("TOOLHELP", 70u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpTerminateApp => TOOLHELP_TERMINATE_APP: ("TOOLHELP", 77u16, Stack, kernel_services::TOOLHELP_TERMINATE_APP, Word);
ToolhelpMemoryRead => TOOLHELP_MEMORY_READ: ("TOOLHELP", 78u16, Stack, kernel_services::TOOLHELP_MEMORY_READ, Dword);
ToolhelpMemoryWrite => TOOLHELP_MEMORY_WRITE: ("TOOLHELP", 79u16, Stack, kernel_services::TOOLHELP_MEMORY_WRITE, Dword);
ToolhelpTimerCount => TOOLHELP_TIMER_COUNT: ("TOOLHELP", 80u16, Stack, kernel_services::TOOLHELP_OUTPUT, Word);
ToolhelpTaskGetCsip => TOOLHELP_TASK_GET_CSIP: ("TOOLHELP", 82u16, Stack, kernel_services::TOOLHELP_TASK_HANDLE, Dword);

SystemGetSystemMsecCount => SYSTEM_GET_SYSTEM_MSEC_COUNT: ("SYSTEM", 6u16, Stack, &[], Dword);
