# module=OLESVR source_module=olesvr.DLL
2 pascal -ret16 OleRegisterServer(str segptr ptr word word)
3 pascal -ret16 OleRevokeServer(long)
4 pascal -ret16 OleBlockServer(long)
5 pascal -ret16 OleUnblockServer(long ptr)
6 pascal -ret16 OleRegisterServerDoc(long str segptr ptr)
7 pascal -ret16 OleRevokeServerDoc(long)
8 pascal -ret16 OleRenameServerDoc(long str)
9 pascal -ret16 OleRevertServerDoc(long)
10 pascal -ret16 OleSavedServerDoc(long)
11 pascal -ret16 OleRevokeObject(segptr)
12 pascal OleQueryServerVersion()
21 stub SRVRWNDPROC
22 stub DOCWNDPROC
23 stub ITEMWNDPROC
24 stub SENDDATAMSG
25 stub FINDITEMWND
26 pascal -ret16 ItemCallBack(ptr word long)
27 stub TERMINATECLIENTS
28 stub TERMINATEDOCCLIENTS
29 stub DELETECLIENTINFO
30 stub SENDRENAMEMSG
31 stub ENUMFORTERMINATE
32 pascal -ret16 DllEntryPoint(long word word word long word)
