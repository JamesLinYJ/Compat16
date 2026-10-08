# Representative entries covering legacy export declaration forms.
# krnl386/krnl386.exe16.spec
2 pascal -ret16 ExitKernel(word segptr) ExitKernel16
3 stub FatalExit
113 equate __AHSHIFT 3
# avifile/avifile.dll16.spec
10 variable _IID_IAVIStream(0x00020021 0x00000000 0x000000c0 0x46000000)
# wow32/wow32.spec
@ stdcall -arch=win32 WOWCallback16(long long)
# ole2/ole2.dll16.spec, user/user.exe16.spec, and ole2disp/ole2disp.dll16.spec
503 cdecl HGLOBALLockBytesImpl16_ReadAt(ptr int64 ptr long ptr) HGLOBALLockBytesImpl16_ReadAt
420 varargs -ret16 _wsprintf(ptr str) wsprintf16
44 pascal VarI2FromR4(float ptr) VarI2FromR416
