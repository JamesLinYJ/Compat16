# module=WINNLS source_module=winnls.DLL
1 stub WINNLSINQUIRE
2 stub HOOKKEYBOARDMESSAGE
4 stub ENUMGETFONTTYPE
5 stub ENUMFACENOTTT
6 pascal SendIMEMessage(word long)
7 pascal SendIMEMessageEx(word long)
9 stub SENDIMEMESSAGEINTERNAL
10 stub WINNLSSETKEYBOARDHOOK
11 pascal -ret16 WINNLSSetIMEHandle(segptr word)
12 pascal -ret16 WINNLSSetIMEStatus(word word)
14 pascal -ret16 WINNLSSetIMEHotkey(word word)
15 stub WINNLSGETIMEHOTKEY
16 pascal -ret16 WINNLSEnableIME(word word)
17 stub WINNLSGETKEYSTATE
18 pascal -ret16 WINNLSGetEnableStatus(word)
19 pascal -ret16 WINNLSSetKeyState(word)
20 stub IMPADDIME
21 stub IMPDELETEIME
22 pascal -ret16 IMPQueryIME(ptr)
23 pascal -ret16 IMPGetIME(word ptr)
24 pascal -ret16 IMPSetIME(word ptr)
25 pascal -ret16 IMPModifyIME(str ptr)
26 pascal -ret16 IMPGetDefaultIME(ptr)
27 pascal -ret16 IMPSetDefaultIME(ptr)
30 pascal -ret16 WINNLSSendString(word word ptr)
31 pascal -ret16 WINNLSPostAppMessage(word word word long)
32 pascal -ret16 WINNLSSendAppMessage(word word word long)
33 pascal -ret16 WINNLSSendControl(word word)
