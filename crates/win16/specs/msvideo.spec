# module=MSVIDEO source_module=msvideo.DLL
2 pascal VideoForWindowsVersion()
3 pascal DllEntryPoint(long word word word long word)
20 pascal videoGetNumDevs()
21 pascal videoGetErrorText(word word str word)
22 pascal VideoCapDriverDescAndVer(word ptr word ptr word)
28 pascal videoOpen(ptr long long)
29 pascal videoClose(word)
30 pascal videoDialog(word word long)
31 pascal videoFrame(word ptr)
32 pascal videoConfigure(word word long ptr ptr long ptr long)
33 pascal videoConfigureStorage(word str long)
34 pascal videoGetChannelCaps(word ptr long)
35 pascal videoUpdate(word word word)
40 pascal videoStreamAddBuffer(word ptr long)
41 pascal videoStreamFini(word)
42 pascal videoStreamGetError(word ptr ptr)
43 pascal videoStreamGetPosition(word ptr long)
44 pascal videoStreamInit(word long long long long)
46 pascal videoStreamPrepareHeader(word ptr long)
47 pascal videoStreamReset(word)
49 pascal videoStreamStart(word)
50 pascal videoStreamStop(word)
51 pascal videoStreamUnprepareHeader(word ptr long)
52 pascal videoStreamAllocHdrAndBuffer(word ptr long)
53 pascal videoStreamFreeHdrAndBuffer(word ptr)
60 pascal videoMessage(word word long long)
102 pascal -ret16 DrawDibOpen()
103 pascal -ret16 DrawDibClose(word)
104 pascal -ret16 DrawDibBegin(word word s_word s_word ptr s_word s_word word)
105 pascal -ret16 DrawDibEnd(word)
106 pascal -ret16 DrawDibDraw(word word s_word s_word s_word s_word ptr ptr s_word s_word s_word s_word word)
108 pascal -ret16 DrawDibGetPalette(word)
110 pascal -ret16 DrawDibSetPalette(word word)
111 stub DRAWDIBCHANGEPALETTE
112 pascal -ret16 DrawDibRealize(word word word)
113 stub DRAWDIBTIME
114 pascal -ret16 DrawDibProfileDisplay(ptr)
115 stub STRETCHDIB
118 pascal -ret16 DrawDibStart(word long)
119 pascal -ret16 DrawDibStop(word)
120 stub DRAWDIBGETBUFFER
200 pascal -ret16 ICInfo(long long segptr)
201 pascal -ret16 ICInstall(long long long ptr word)
202 pascal -ret16 ICRemove(long long word)
203 pascal -ret16 ICOpen(long long word)
204 pascal ICClose(word)
205 pascal ICSendMessage(word word long long)
206 pascal -ret16 ICOpenFunction(long long word segptr)
207 varargs _ICMessage(word word word)
212 pascal ICGetInfo(word segptr long)
213 pascal -ret16 ICLocate(long long ptr ptr word)
224 cdecl _ICCompress(word long segptr segptr segptr segptr segptr segptr long long long segptr segptr)
230 cdecl _ICDecompress(word long segptr segptr segptr segptr)
232 cdecl _ICDrawBegin(word long word word word s_word s_word s_word s_word segptr s_word s_word s_word s_word long long)
234 cdecl _ICDraw(word long segptr segptr long long)
239 pascal -ret16 ICGetDisplayFormat(word ptr ptr s_word s_word s_word)
240 stub ICIMAGECOMPRESS
241 stub ICIMAGEDECOMPRESS
242 stub ICCOMPRESSORCHOOSE
243 stub ICCOMPRESSORFREE
244 stub ICSEQCOMPRESSFRAMESTART
245 stub ICSEQCOMPRESSFRAMEEND
246 stub ICSEQCOMPRESSFRAME
250 cdecl _MCIWndCreate(word word long str)
251 cdecl _MCIWndRegisterClass()
252 stub GETOPENFILENAMEPREVIEW
253 stub GETSAVEFILENAMEPREVIEW
