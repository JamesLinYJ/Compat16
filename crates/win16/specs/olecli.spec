# module=OLECLI source_module=olecli.DLL
2 pascal -ret16 OleDelete(segptr)
3 pascal -ret16 OleSaveToStream(segptr segptr)
4 pascal -ret16 OleLoadFromStream(segptr str segptr long str ptr)
6 pascal -ret16 OleClone(segptr segptr long str ptr)
7 pascal -ret16 OLECOPYFROMLINK(segptr str segptr long str ptr)
8 pascal -ret16 OleEqual(segptr segptr)
9 pascal -ret16 OleQueryLinkFromClip(str word word)
10 pascal -ret16 OleQueryCreateFromClip(str word word)
11 pascal -ret16 OleCreateLinkFromClip(str segptr long str ptr word word)
12 pascal -ret16 OleCreateFromClip(str segptr long str ptr word word)
13 pascal -ret16 OleCopyToClipboard(segptr)
14 pascal -ret16 OleQueryType(segptr ptr)
15 pascal -ret16 OleSetHostNames(segptr str str)
16 pascal -ret16 OleSetTargetDevice(segptr word)
17 pascal -ret16 OleSetBounds(segptr ptr)
18 pascal -ret16 OleQueryBounds(segptr ptr)
19 pascal -ret16 OleDraw(segptr word ptr ptr word)
20 pascal -ret16 OleQueryOpen(segptr)
21 pascal -ret16 OleActivate(segptr word word word word ptr)
22 pascal -ret16 OleUpdate(segptr)
23 pascal -ret16 OleReconnect(segptr)
24 pascal -ret16 OleGetLinkUpdateOptions(segptr ptr)
25 pascal -ret16 OleSetLinkUpdateOptions(segptr word)
26 pascal -ret16 OleEnumFormats(segptr word)
27 pascal -ret16 OleClose(segptr)
28 pascal -ret16 OleGetData(segptr word ptr)
29 pascal -ret16 OleSetData(segptr word word)
30 pascal OLEQUERYPROTOCOL(segptr str)
31 pascal -ret16 OLEQUERYOUTOFDATE(segptr)
32 pascal -ret16 OLEOBJECTCONVERT(segptr str segptr long str ptr)
33 pascal -ret16 OLECREATEFROMTEMPLATE(str segptr str long str ptr word word)
34 pascal -ret16 OleCreate(str segptr str long str ptr word word)
35 pascal -ret16 OleQueryReleaseStatus(segptr)
36 pascal -ret16 OleQueryReleaseError(segptr)
37 pascal -ret16 OleQueryReleaseMethod(segptr)
38 pascal -ret16 OleCreateFromFile(str segptr str str long str ptr word word)
39 pascal -ret16 OLECREATELINKFROMFILE(str segptr str str str long str ptr word word)
40 pascal -ret16 OleRelease(segptr)
41 pascal -ret16 OleRegisterClientDoc(str str long ptr)
42 pascal -ret16 OleRevokeClientDoc(long)
43 pascal -ret16 OleRenameClientDoc(long str)
44 pascal -ret16 OleRevertClientDoc(long)
45 pascal -ret16 OleSavedClientDoc(long)
46 pascal -ret16 OleRename(segptr str)
47 pascal -ret16 OleEnumObjects(long ptr)
48 pascal -ret16 OleQueryName(segptr str ptr)
49 pascal -ret16 OleSetColorScheme(segptr ptr)
50 pascal -ret16 OLEREQUESTDATA(segptr word)
54 pascal -ret16 OleLockServer(segptr ptr)
55 pascal -ret16 OleUnlockServer(long)
56 pascal -ret16 OleQuerySize(segptr ptr)
57 pascal -ret16 OLEEXECUTE(segptr word word)
58 pascal -ret16 OleCreateInvisible(str segptr str long str ptr word word word)
59 pascal OleQueryClientVersion()
60 pascal -ret16 OleIsDcMeta(word)
100 stub DOCWNDPROC
101 stub SRVRWNDPROC
102 stub MFCALLBACKFUNC
110 stub DEFLOADFROMSTREAM
111 stub DEFCREATEFROMCLIP
112 stub DEFCREATELINKFROMCLIP
113 stub DEFCREATEFROMTEMPLATE
114 stub DEFCREATE
115 stub DEFCREATEFROMFILE
116 stub DEFCREATELINKFROMFILE
117 stub DEFCREATEINVISIBLE
200 stub LERELEASE
201 stub LESHOW
202 stub LEGETDATA
203 stub LESETDATA
204 stub LESETHOSTNAMES
205 stub LESETTARGETDEVICE
206 stub LESETBOUNDS
207 stub LESAVETOSTREAM
208 stub LECLONE
209 stub LECOPYFROMLINK
210 stub LEEQUAL
211 stub LECOPY
212 stub LEQUERYTYPE
213 stub LEQUERYBOUNDS
214 stub LEDRAW
215 stub LEQUERYOPEN
216 stub LEACTIVATE
218 stub LEUPDATE
219 stub LERECONNECT
220 stub LEENUMFORMAT
221 stub LEQUERYPROTOCOL
222 stub LEQUERYOUTOFDATE
223 stub LEOBJECTCONVERT
224 stub LECHANGEDATA
225 stub LECLOSE
226 stub LEGETUPDATEOPTIONS
227 stub LESETUPDATEOPTIONS
228 stub LEEXECUTE
229 stub LEOBJECTLONG
230 stub LECREATEINVISIBLE
300 stub MFRELEASE
301 stub MFGETDATA
302 stub MFSAVETOSTREAM
303 stub MFCLONE
304 stub MFEQUAL
305 stub MFCOPY
307 stub MFQUERYBOUNDS
308 stub MFDRAW
309 stub MFENUMFORMAT
310 stub MFCHANGEDATA
400 stub BMRELEASE
401 stub BMGETDATA
402 stub BMSAVETOSTREAM
403 stub BMCLONE
404 stub BMEQUAL
405 stub BMCOPY
407 stub BMQUERYBOUNDS
408 stub BMDRAW
409 stub BMENUMFORMAT
410 stub BMCHANGEDATA
500 stub DIBRELEASE
501 stub DIBGETDATA
502 stub DIBSAVETOSTREAM
503 stub DIBCLONE
504 stub DIBEQUAL
505 stub DIBCOPY
507 stub DIBQUERYBOUNDS
508 stub DIBDRAW
509 stub DIBENUMFORMAT
510 stub DIBCHANGEDATA
600 stub GENRELEASE
601 stub GENGETDATA
602 stub GENSETDATA
603 stub GENSAVETOSTREAM
604 stub GENCLONE
605 stub GENEQUAL
606 stub GENCOPY
608 stub GENQUERYBOUNDS
609 stub GENDRAW
610 stub GENENUMFORMAT
611 stub GENCHANGEDATA
701 stub ERRSHOW
702 stub ERRSETDATA
703 stub ERRSETHOSTNAMES
704 stub ERRSETTARGETDEVICE
705 stub ERRSETBOUNDS
706 stub ERRCOPYFROMLINK
707 stub ERRQUERYOPEN
708 stub ERRACTIVATE
709 stub ERRCLOSE
710 stub ERRUPDATE
711 stub ERRRECONNECT
712 stub ERRQUERYPROTOCOL
713 stub ERRQUERYOUTOFDATE
714 stub ERROBJECTCONVERT
715 stub ERRGETUPDATEOPTIONS
716 stub ERRSETUPDATEOPTIONS
717 stub ERREXECUTE
718 stub ERROBJECTLONG
800 stub PBLOADFROMSTREAM
801 stub PBCREATEFROMCLIP
802 stub PBCREATELINKFROMCLIP
803 stub PBCREATEFROMTEMPLATE
804 stub PBCREATE
805 stub PBDRAW
806 stub PBQUERYBOUNDS
807 stub PBCOPYTOCLIPBOARD
808 stub PBCREATEFROMFILE
809 stub PBCREATELINKFROMFILE
810 stub PBENUMFORMATS
811 stub PBGETDATA
812 stub PBCREATEINVISIBLE
910 stub OBJQUERYNAME
911 stub OBJRENAME
912 stub OBJQUERYTYPE
913 stub OBJQUERYSIZE
950 stub CONNECTDLGPROC
951 stub SETNETNAME
952 stub CHECKNETDRIVE
953 stub SETNEXTNETDRIVE
954 stub GETTASKVISIBLEWINDOW
