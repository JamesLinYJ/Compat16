# module=OLE2NLS source_module=ole2nls.DLL
1 pascal GetUserDefaultLCID()
2 pascal GetSystemDefaultLCID()
3 pascal -ret16 GetUserDefaultLangID()
4 pascal -ret16 GetSystemDefaultLangID()
5 pascal GetLocaleInfoA(long long ptr word)
6 pascal -ret16 LCMapStringA(long long ptr word ptr word)
7 pascal -ret16 GetStringTypeA(long long str word ptr)
8 pascal -ret16 CompareStringA(long long str word str word)
9 pascal -ret16 RegisterNLSInfoChanged(ptr)
11 stub LIBMAIN
12 stub NOTIFYWINDOWPROC
