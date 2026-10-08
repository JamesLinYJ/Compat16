# module=KERNEL source_module=krnl386.EXE
1 pascal FatalExit(s_word)
2 pascal -ret16 ExitKernel()
3 pascal GetVersion()
4 pascal -ret16 LocalInit(word word word)
5 pascal -ret16 LocalAlloc(word word)
6 pascal -ret16 LocalReAlloc(word word word)
7 pascal -ret16 LocalFree(word)
8 pascal LocalLock(word)
9 pascal -ret16 LocalUnlock(word)
10 pascal -ret16 LocalSize(word)
11 pascal -ret16 LocalHandle(word)
12 pascal -ret16 LocalFlags(word)
13 pascal -ret16 LocalCompact(word)
14 pascal LocalNotify(long)
15 pascal -register GlobalAlloc(word long)
16 pascal -ret16 GlobalReAlloc(word long word)
17 pascal GlobalFree(word)
18 pascal GlobalLock(word)
19 pascal GlobalUnlock(word)
20 pascal GlobalSize(word)
21 pascal GlobalHandle(word)
22 pascal GlobalFlags(word)
23 pascal -ret16 LockSegment(word)
24 pascal UnlockSegment(word)
25 pascal GlobalCompact(long)
26 pascal -ret16 GlobalFreeAll(word)
27 pascal -ret16 GetModuleName(word ptr word)
28 pascal GlobalMasterHandle()
29 pascal -ret16 Yield()
30 pascal -ret16 WaitEvent(word)
31 pascal -ret16 PostEvent(word)
32 pascal -ret16 SetPriority(word s_word)
33 pascal -ret16 LockCurrentTask(word)
34 pascal -ret16 SetTaskQueue(word word)
35 pascal -ret16 GetTaskQueue(word)
36 pascal GetCurrentTask()
37 pascal GetCurrentPDB()
38 pascal SetTaskSignalProc(word segptr)
39 stub SetTaskSwitchProc
40 stub SetTaskInterchange
41 pascal -ret16 EnableDos()
42 pascal -ret16 DisableDos()
43 stub IsScreenGrab
44 stub BuildPDB
45 pascal -ret16 LoadModule(str ptr)
46 pascal -ret16 FreeModule(word)
47 pascal GetModuleHandle(segstr)
48 pascal -ret16 GetModuleUsage(word)
49 pascal -ret16 GetModuleFileName(word ptr s_word)
50 pascal GetProcAddress(word str)
51 pascal MakeProcInstance(segptr word)
52 pascal -ret16 FreeProcInstance(segptr)
53 stub CallProcInstance
54 pascal -ret16 GetInstanceData(word word word)
55 pascal -register Catch(segptr)
56 pascal -register Throw(ptr word)
57 pascal -ret16 GetProfileInt(str str s_word)
58 pascal -ret16 GetProfileString(str str str ptr word)
59 pascal -ret16 WriteProfileString(str str str)
60 pascal -ret16 FindResource(word str str)
61 pascal -ret16 LoadResource(word word)
62 pascal LockResource(word)
63 pascal -ret16 FreeResource(word)
64 pascal -ret16 AccessResource(word word)
65 pascal SizeofResource(word word)
66 pascal -ret16 AllocResource(word word long)
67 pascal SetResourceHandler(word str segptr)
68 pascal -ret16 InitAtomTable(word)
69 pascal -ret16 FindAtom(str)
70 pascal -ret16 AddAtom(str)
71 pascal -ret16 DeleteAtom(word)
72 pascal -ret16 GetAtomName(word ptr word)
73 pascal -ret16 GetAtomHandle(word)
74 pascal -ret16 OpenFile(str long word)
75 stub OpenPathName
76 stub DeletePathName
77 pascal Reserved1(segptr)
78 pascal Reserved2(segptr segptr)
79 pascal Reserved3(segstr)
80 pascal Reserved4(segstr)
81 pascal -ret16 _lclose(word)
82 pascal -ret16 _lread(word segptr word)
83 pascal -ret16 _lcreat(str word)
84 pascal _llseek(word long word)
85 pascal -ret16 _lopen(str word)
86 pascal -ret16 _lwrite(word ptr word)
87 pascal -ret16 Reserved5(str str)
88 pascal lstrcpy(segptr str)
89 pascal lstrcat(segstr str)
90 pascal -ret16 lstrlen(str)
91 pascal -register InitTask()
92 pascal GetTempDrive(word)
93 pascal GetCodeHandle(segptr)
94 pascal -ret16 DefineHandleTable(word)
95 pascal -ret16 -stkprolog LoadLibrary(str)
96 pascal FreeLibrary(word)
97 pascal -ret16 GetTempFileName(word str word ptr)
98 pascal -ret16 GetLastDiskChange()
99 stub GetLPErrMode
100 pascal -ret16 ValidateCodeSegments()
101 stub NoHookDosCall
102 pascal -register DOS3Call()
103 pascal -register NetBIOSCall()
104 pascal -ret16 GetCodeInfo(segptr ptr)
105 pascal -ret16 GetExeVersion()
106 pascal SetSwapAreaSize(word)
107 pascal -ret16 SetErrorMode(word)
108 pascal -ret16 SwitchStackTo(word word word)
109 pascal -register SwitchStackBack()
110 pascal PatchCodeHandle(word)
111 pascal GlobalWire(word)
112 pascal -ret16 GlobalUnWire(word)
113 equate __AHSHIFT 3
114 equate __AHINCR 8
115 pascal -register OutputDebugString(str)
116 stub InitLib
117 pascal -ret16 OldYield()
118 pascal -ret16 GetTaskQueueDS()
119 pascal -ret16 GetTaskQueueES()
120 stub UndefDynLink
121 pascal -ret16 LocalShrink(word word)
122 pascal -ret16 IsTaskLocked()
123 pascal -ret16 KbdRst()
124 pascal -ret16 EnableKernel()
125 pascal -ret16 DisableKernel()
126 stub MemoryFreed
127 pascal -ret16 GetPrivateProfileInt(str str s_word str)
128 pascal -ret16 GetPrivateProfileString(str str str ptr word str)
129 pascal -ret16 WritePrivateProfileString(str str str str)
130 pascal FileCDR(ptr)
131 pascal GetDOSEnvironment()
132 pascal GetWinFlags()
133 pascal -ret16 GetExePtr(word)
134 pascal -ret16 GetWindowsDirectory(ptr word)
135 pascal -ret16 GetSystemDirectory(ptr word)
136 pascal -ret16 GetDriveType(word)
137 pascal -ret16 FatalAppExit(word str)
138 pascal GetHeapSpaces(word)
139 stub DoSignal
140 pascal -ret16 SetSigHandler(segptr ptr ptr word word)
141 stub InitTask1
142 pascal -ret16 GetProfileSectionNames(ptr word)
143 pascal -ret16 GetPrivateProfileSectionNames(ptr word str)
144 pascal -ret16 CreateDirectory(ptr ptr)
145 pascal -ret16 RemoveDirectory(ptr)
146 pascal -ret16 DeleteFile(ptr)
147 pascal -ret16 SetLastError(long)
148 pascal GetLastError()
149 pascal -ret16 GetVersionEx(ptr)
150 pascal -ret16 DirectedYield(word)
151 stub WinOldApCall
152 pascal -ret16 GetNumTasks()
154 pascal -ret16 GlobalNotify(segptr)
155 pascal -ret16 GetTaskDS()
156 pascal LimitEMSPages(long)
157 pascal GetCurPID(long)
158 pascal -ret16 IsWinOldApTask(word)
159 pascal GlobalHandleNoRIP(word)
160 stub EMSCopy
161 pascal -ret16 LocalCountFree()
162 pascal -ret16 LocalHeapSize()
163 pascal -ret16 GlobalLRUOldest(word)
164 pascal -ret16 GlobalLRUNewest(word)
165 pascal -ret16 A20Proc(word)
166 pascal -ret16 WinExec(str word)
167 pascal -ret16 GetExpWinVer(word)
168 pascal -ret16 DirectResAlloc(word word word)
169 pascal GetFreeSpace(word)
170 pascal -ret16 AllocCStoDSAlias(word)
171 pascal -ret16 AllocDStoCSAlias(word)
172 pascal -ret16 AllocAlias(word)
173 equate __ROMBIOS 0
174 equate __A000H 0
175 pascal -ret16 AllocSelector(word)
176 pascal -ret16 FreeSelector(word)
177 pascal -ret16 PrestoChangoSelector(word word)
178 equate __WINFLAGS 1043
179 equate __D000H 0
180 pascal LongPtrAdd(long long)
181 equate __B000H 0
182 equate __B800H 0
183 equate __0000H 0
184 pascal GlobalDOSAlloc(long)
185 pascal -ret16 GlobalDOSFree(word)
186 pascal GetSelectorBase(word)
187 pascal -ret16 SetSelectorBase(word long)
188 pascal GetSelectorLimit(word)
189 pascal -ret16 SetSelectorLimit(word long)
190 equate __E000H 0
191 pascal -ret16 GlobalPageLock(word)
192 pascal -ret16 GlobalPageUnlock(word)
193 equate __0040H 0
194 equate __F000H 0
195 equate __C000H 0
196 pascal -ret16 SelectorAccessRights(word word word)
197 pascal -ret16 GlobalFix(word)
198 pascal -ret16 GlobalUnfix(word)
199 pascal -ret16 SetHandleCount(word)
200 pascal -ret16 ValidateFreeSpaces()
201 stub ReplaceInst
202 stub RegisterPtrace
203 pascal -register DebugBreak()
204 stub SwapRecording
205 stub CVWBreak
206 pascal -ret16 AllocSelectorArray(word)
207 pascal -ret16 IsDBCSLeadByte(word)
208 pascal K208(word long long long)
209 pascal K209(long long word long)
210 pascal K210(long long word long long)
211 pascal K211(long long word)
213 pascal K213(long long word word)
214 pascal K214(long long word)
215 pascal K215(long word)
216 pascal RegEnumKey(long long ptr long)
217 pascal RegOpenKey(long str ptr)
218 pascal RegCreateKey(long str ptr)
219 pascal RegDeleteKey(long str)
220 pascal RegCloseKey(long)
221 pascal RegSetValue(long str long ptr long)
222 pascal RegDeleteValue(long str)
223 pascal RegEnumValue(long long ptr ptr ptr ptr ptr ptr)
224 pascal RegQueryValue(long str ptr ptr)
225 pascal RegQueryValueEx(long str ptr ptr ptr ptr)
226 pascal RegSetValueEx(long str long long ptr long)
227 pascal RegFlushKey(long)
228 pascal -ret16 K228(word)
229 pascal -ret16 K229(long)
230 pascal GlobalSmartPageLock(word)
231 pascal GlobalSmartPageUnlock(word)
232 stub RegLoadKey
233 stub RegUnloadKey
234 stub RegSaveKey
235 stub InvalidateNlsCache
236 stub GetProductName
237 pascal -ret16 K237()
262 stub WOWWaitForMsgAndEvent
263 stub WOWMsgBox
273 stub K273
274 pascal -ret16 GetShortPathName(str ptr word)
310 pascal -ret16 LocalHandleDelta(word)
311 pascal GetSetKernelDOSProc(ptr)
314 stub DebugDefineSegment
315 pascal -ret16 WriteOutProfiles()
316 pascal GetFreeMemInfo()
318 stub FatalExitHook
319 stub FlushCachedFileHandle
320 pascal -ret16 IsTask(word)
323 pascal -ret16 IsRomModule(word)
324 pascal -ret16 LogError(word ptr)
325 pascal -ret16 LogParamError(word ptr ptr)
326 pascal -ret16 IsRomFile(word)
327 pascal -register K327()
328 varargs -ret16 _DebugOutput(word str)
329 pascal -ret16 K329(str word)
332 variable THHOOK (0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000)
334 pascal -ret16 IsBadReadPtr(segptr word)
335 pascal -ret16 IsBadWritePtr(segptr word)
336 pascal -ret16 IsBadCodePtr(segptr)
337 pascal -ret16 IsBadStringPtr(segptr word)
338 pascal -ret16 HasGPHandler(segptr)
339 pascal -ret16 DiagQuery()
340 pascal -ret16 DiagOutput(str)
341 pascal ToolHelpHook(ptr)
342 variable __GP (0x00000000, 0x00000000)
343 stub RegisterWinOldApHook
344 stub GetWinOldApHooks
345 pascal -ret16 IsSharedSelector(word)
346 pascal -ret16 IsBadHugeReadPtr(segptr long)
347 pascal -ret16 IsBadHugeWritePtr(segptr long)
348 pascal -ret16 hmemcpy(ptr ptr long)
349 pascal _hread(word segptr long)
350 pascal _hwrite(word ptr long)
351 pascal -ret16 BUNNY_351()
352 pascal lstrcatn(segstr str word)
353 pascal lstrcpyn(segptr str word)
354 pascal GetAppCompatFlags(word)
355 pascal -ret16 GetWinDebugInfo(ptr word)
356 pascal -ret16 SetWinDebugInfo(ptr)
357 pascal MapSL(segptr)
358 pascal MapLS(long)
359 pascal UnMapLS(segptr)
360 pascal -ret16 OpenFileEx(str ptr word)
361 pascal -ret16 PIGLET_361()
362 stub ThunkTerminateProcess
365 pascal -register GlobalChangeLockCount(word word)
403 pascal -ret16 FarSetOwner(word word)
404 pascal -ret16 FarGetOwner(word)
406 pascal -ret16 WritePrivateProfileStruct(str str ptr word str)
407 pascal -ret16 GetPrivateProfileStruct(str str ptr word str)
408 stub KERNEL_408
409 stub KERNEL_409
410 stub CreateProcessFromWinExec
411 pascal GetCurrentDirectory(long ptr)
412 pascal -ret16 SetCurrentDirectory(ptr)
413 pascal -ret16 FindFirstFile(ptr ptr)
414 pascal -ret16 FindNextFile(word ptr)
415 pascal -ret16 FindClose(word)
416 pascal -ret16 WritePrivateProfileSection(str str str)
417 pascal -ret16 WriteProfileSection(str str)
418 pascal -ret16 GetPrivateProfileSection(str ptr word str)
419 pascal -ret16 GetProfileSection(str ptr word)
420 pascal GetFileAttributes(ptr)
421 pascal -ret16 SetFileAttributes(ptr long)
422 pascal -ret16 GetDiskFreeSpace(ptr ptr ptr ptr ptr)
423 pascal -ret16 LogApiThk(str)
431 pascal -ret16 IsPeFormat(str word)
432 stub FileTimeToLocalFileTime
434 pascal -ret16 UnicodeToAnsi(ptr ptr word)
435 stub GetTaskFlags
436 pascal -ret16 _ConfirmSysLevel(ptr)
437 pascal -ret16 _CheckNotSysLevel(ptr)
438 pascal -ret16 _CreateSysLevel(ptr long)
439 pascal -ret16 _EnterSysLevel(ptr)
440 pascal -ret16 _LeaveSysLevel(ptr)
441 pascal CreateThread16(ptr long segptr segptr long ptr)
442 pascal VWin32_EventCreate()
443 pascal VWin32_EventDestroy(long)
444 pascal -ret16 Local32Info(ptr word)
445 pascal -ret16 Local32First(ptr word)
446 pascal -ret16 Local32Next(ptr)
447 pascal -ret16 WIN32_OldYield()
448 stub KERNEL_448
449 pascal GetpWin16Lock()
450 pascal VWin32_EventWait(long)
451 pascal VWin32_EventSet(long)
452 pascal LoadLibrary32(str)
453 pascal GetProcAddress32(long str)
454 equate __FLATCS 0
455 equate __FLATDS 0
456 pascal DefResourceHandler(word word word)
457 pascal CreateW32Event(long long)
458 pascal SetW32Event(long)
459 pascal ResetW32Event(long)
460 pascal WaitForSingleObject(long long)
461 pascal WaitForMultipleObjects(long ptr long long)
462 pascal GetCurrentThreadId()
463 pascal SetThreadQueue(long word)
464 pascal GetThreadQueue(long)
465 stub NukeProcess
466 pascal -ret16 ExitProcess(word)
467 stub WOACreateConsole
468 stub WOASpawnConApp
469 stub WOAGimmeTitle
470 stub WOADestroyConsole
471 pascal GetCurrentProcessId()
472 pascal -register MapHInstLS()
473 pascal -register MapHInstSL()
474 pascal CloseW32Handle(long)
475 pascal -ret16 GetTEBSelectorFS()
476 pascal ConvertToGlobalHandle(long)
477 stub WOAFullScreen
478 stub WOATerminateProcess
479 pascal KERNEL_479(long)
480 pascal -ret16 _EnterWin16Lock()
481 pascal -ret16 _LeaveWin16Lock()
482 pascal LoadSystemLibrary32(str)
483 pascal MapProcessHandle(long)
484 pascal SetProcessDword(long s_word long)
485 pascal GetProcessDword(long s_word)
486 pascal FreeLibrary32(long)
487 pascal GetModuleFileName32(long str word)
488 pascal GetModuleHandle32(str)
489 stub KERNEL_489
490 pascal -ret16 KERNEL_490(word)
491 pascal RegisterServiceProcess(long long)
492 stub WOAAbort
493 pascal -ret16 UTInit(long long long long)
494 stub KERNEL_494
495 pascal WaitForMultipleObjectsEx(long ptr long long long)
500 varargs WOW16Call(word word word)
501 stub KDDBGOUT
502 stub WOWGETNEXTVDMCOMMAND
503 stub WOWREGISTERSHELLWINDOWHANDLE
504 stub WOWLOADMODULE
505 stub WOWQUERYPERFORMANCECOUNTER
506 stub WOWCURSORICONOP
507 stub WOWFAILEDEXEC
508 stub WOWCLOSECOMPORT
511 stub WOWKILLREMOTETASK
512 stub WOWQUERYDEBUG
513 pascal LoadLibraryEx32W(str long long)
514 pascal FreeLibrary32W(long)
515 pascal GetProcAddress32W(long str)
516 pascal GetVDMPointer32W(segptr word)
517 varargs CallProc32W(long long long)
518 varargs _CallProcEx32W(long long long)
519 stub EXITKERNELTHUNK
520 equate __MOD_KERNEL 4200
521 equate __MOD_DKERNEL 4201
522 equate __MOD_USER 4203
523 equate __MOD_DUSER 4204
524 equate __MOD_GDI 4205
525 equate __MOD_DGDI 4206
526 equate __MOD_KEYBOARD 4207
527 equate __MOD_SOUND 4208
528 equate __MOD_SHELL 4209
529 equate __MOD_WINSOCK 4210
530 equate __MOD_TOOLHELP 4211
531 equate __MOD_MMEDIA 4212
532 equate __MOD_COMMDLG 4213
533 stub ConvertDDEHandleLS
534 stub ConvertDDEHandleSL
535 pascal VWin32_BoostThreadGroup(long long)
536 pascal VWin32_BoostThreadStatic(long long)
537 stub KERNEL_537
538 stub ThunkTheTemplateHandle
540 stub KERNEL_540
541 stub WOWSETEXITONLASTAPP
542 stub KERNEL_542
543 stub KERNEL_543
544 stub WOWSETCOMPATHANDLE
560 pascal SetThunkletCallbackGlue(long segptr)
561 pascal AllocLSThunkletCallback(segptr long)
562 pascal AllocSLThunkletCallback(long long)
563 pascal FindLSThunkletCallback(segptr long)
564 pascal FindSLThunkletCallback(long long)
566 stub KERNEL_566
567 pascal AllocLSThunkletCallbackEx(segptr long word)
568 pascal AllocSLThunkletCallbackEx(long long word)
600 stub AllocCodeAlias
601 stub FreeCodeAlias
602 pascal -ret16 GetDummyModuleHandleDS()
603 stub KERNEL_603
604 pascal -register CBClientGlueSL()
605 pascal AllocSLThunkletCallback_dup(long long)
606 pascal AllocLSThunkletCallback_dup(segptr long)
607 pascal AllocLSThunkletSysthunk(segptr long long)
608 pascal AllocSLThunkletSysthunk(long segptr long)
609 pascal FindLSThunkletCallback_dup(segptr long)
610 pascal FindSLThunkletCallback_dup(long long)
611 pascal -ret16 FreeThunklet(long long)
612 pascal -ret16 IsSLThunklet(ptr)
613 stub HugeMapLS
614 stub HugeUnMapLS
615 pascal -ret16 ConvertDialog32To16(long long long)
616 pascal -ret16 ConvertMenu32To16(long long long)
617 pascal -ret16 GetMenu32Size(ptr)
618 pascal -ret16 GetDialog32Size(ptr)
619 pascal -ret16 RegisterCBClient(word segptr long)
620 pascal -register CBClientThunkSL()
621 pascal -register CBClientThunkSLEx()
622 pascal -ret16 UnRegisterCBClient(word segptr long)
623 pascal -ret16 InitCBClient(long)
624 pascal SetFastQueue(long long)
625 pascal GetFastQueue()
626 stub SmashEnvironment
627 pascal -ret16 IsBadFlatReadWritePtr(segptr long word)
630 pascal -register C16ThkSL()
631 pascal -register C16ThkSL01()
651 pascal ThunkConnect16(str str word long ptr str word)
652 stub IsThreadId
653 stub OkWithKernelToChangeUsers
666 pascal UTGlue16(ptr long ptr long)
667 pascal EntryAddrProc(word word)
668 pascal MyAlloc(word word word)
669 pascal -ret16 DllEntryPoint(long word word word long word)
700 pascal SSInit()
701 stub SSOnBigStack
702 stub SSCall
703 stub CallProc32WFix
704 pascal -register SSConfirmSmallStack()
