# module=MSACM source_module=msacm.DLL
2 stub DRIVERPROC
3 pascal DllEntryPoint(long word word word long word)
4 stub ___EXPORTEDSTUB
7 pascal acmGetVersion()
8 pascal -ret16 acmMetrics(word word ptr)
10 pascal -ret16 acmDriverEnum(ptr long long)
11 pascal -ret16 acmDriverDetails(word ptr long)
12 pascal -ret16 acmDriverAdd(ptr word long long long)
13 pascal -ret16 acmDriverRemove(word long)
14 pascal -ret16 acmDriverOpen(ptr word long)
15 pascal -ret16 acmDriverClose(word long)
16 pascal acmDriverMessage(word word long long)
17 pascal -ret16 acmDriverID(word ptr long)
18 pascal -ret16 acmDriverPriority(word long long)
30 pascal -ret16 acmFormatTagDetails(word ptr long)
31 pascal -ret16 acmFormatTagEnum(word ptr ptr long long)
40 pascal -ret16 acmFormatChoose(ptr)
41 pascal -ret16 acmFormatDetails(word ptr long)
42 pascal -ret16 acmFormatEnum(word ptr ptr long long)
45 pascal -ret16 acmFormatSuggest(word ptr ptr long long)
50 pascal -ret16 acmFilterTagDetails(word ptr long)
51 pascal -ret16 acmFilterTagEnum(word ptr ptr long long)
60 pascal -ret16 acmFilterChoose(ptr)
61 pascal -ret16 acmFilterDetails(word ptr long)
62 pascal -ret16 acmFilterEnum(word ptr ptr long long)
70 pascal -ret16 acmStreamOpen(ptr word ptr ptr ptr long long long)
71 pascal -ret16 acmStreamClose(word long)
72 pascal -ret16 acmStreamSize(word long ptr long)
75 pascal -ret16 acmStreamConvert(word ptr long)
76 pascal -ret16 acmStreamReset(word long)
77 pascal -ret16 acmStreamPrepareHeader(word ptr long)
78 pascal -ret16 acmStreamUnprepareHeader(word ptr long)
150 stub ACMAPPLICATIONEXIT
175 stub ACMHUGEPAGELOCK
176 stub ACMHUGEPAGEUNLOCK
200 stub ACMOPENCONVERSION
201 stub ACMCLOSECONVERSION
202 stub ACMCONVERT
203 stub ACMCHOOSEFORMAT
