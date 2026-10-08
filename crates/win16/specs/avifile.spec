# module=AVIFILE source_module=avifile.DLL
2 stub DLLGETCLASSOBJECT
3 stub DLLCANUNLOADNOW
4 stub ___EXPORTEDSTUB
10 variable _IID_IAVIStream (0x00020021, 0x00000000, 0x000000C0, 0x46000000)
11 variable _IID_IAVIFile (0x00020020, 0x00000000, 0x000000C0, 0x46000000)
12 variable _IID_IAVIEditStream (0x00020024, 0x00000000, 0x000000C0, 0x46000000)
13 variable _IID_IGetFrame (0x00020023, 0x00000000, 0x000000C0, 0x46000000)
14 variable _CLSID_AVISimpleUnMarshal (0x00020009, 0x00000000, 0x000000C0, 0x46000000)
100 pascal AVIFileInit()
101 pascal AVIFileExit()
102 pascal AVIFileOpen(ptr str word ptr)
103 pascal AVIStreamOpenFromFile(ptr str long long word ptr)
104 pascal AVIStreamCreate(ptr long long ptr)
105 stub AVIMAKECOMPRESSEDSTREAM
106 stub AVIMAKEFILEFROMSTREAMS
107 stub AVIMAKESTREAMFROMCLIPBOARD
110 pascal AVIStreamGetFrame(long long)
111 pascal AVIStreamGetFrameClose(long)
112 pascal AVIStreamGetFrameOpen(long ptr)
120 stub _AVISAVE
121 stub AVISAVEV
122 stub AVISAVEOPTIONS
123 pascal AVIBuildFilter(str long word)
124 pascal AVISaveOptionsFree(word ptr)
130 pascal AVIStreamStart(long)
131 pascal AVIStreamLength(long)
132 pascal AVIStreamTimeToSample(long long)
133 pascal AVIStreamSampleToTime(long long)
140 pascal AVIFileAddRef(long)
141 pascal AVIFileRelease(long)
142 pascal AVIFileInfo(long ptr long)
143 pascal AVIFileGetStream(long ptr long long)
144 pascal AVIFileCreateStream(long ptr ptr)
146 pascal AVIFileWriteData(long long ptr long)
147 pascal AVIFileReadData(long long ptr ptr)
148 pascal AVIFileEndRecord(long)
160 pascal AVIStreamAddRef(long)
161 pascal AVIStreamRelease(long)
162 pascal AVIStreamInfo(long ptr long)
163 pascal AVIStreamFindSample(long long long)
164 pascal AVIStreamReadFormat(long long ptr ptr)
165 pascal AVIStreamReadData(long long ptr ptr)
166 pascal AVIStreamWriteData(long long ptr long)
167 pascal AVIStreamRead(long long long ptr long ptr ptr)
168 pascal AVIStreamWrite(long long long ptr long long ptr ptr)
169 pascal AVIStreamSetFormat(long long ptr long)
180 stub EDITSTREAMCOPY
181 stub EDITSTREAMCUT
182 stub EDITSTREAMPASTE
184 stub CREATEEDITABLESTREAM
185 stub AVIPUTFILEONCLIPBOARD
187 stub AVIGETFROMCLIPBOARD
188 stub AVICLEARCLIPBOARD
190 stub EDITSTREAMCLONE
191 stub EDITSTREAMSETNAME
192 stub EDITSTREAMSETINFO
200 stub AVISTREAMBEGINSTREAMING
201 stub AVISTREAMENDSTREAMING
