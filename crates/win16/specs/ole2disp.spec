# module=OLE2DISP source_module=ole2disp.DLL
1 stub DLLGETCLASSOBJECT
2 pascal SysAllocString(str)
3 pascal SysReallocString(ptr str)
4 pascal SysAllocStringLen(segstr word)
5 pascal SysReAllocStringLen(ptr segstr word)
6 pascal SysFreeString(segstr)
7 pascal SysStringLen(segstr)
8 pascal VariantInit(ptr)
9 pascal VariantClear(ptr)
10 pascal VariantCopy(ptr ptr)
11 pascal VariantCopyInd(ptr ptr)
12 pascal VariantChangeType(ptr ptr word word)
13 stub VARIANTTIMETODOSDATETIME
14 stub DOSDATETIMETOVARIANTTIME
15 pascal SafeArrayCreate(word word ptr)
16 pascal SafeArrayDestroy(segptr)
17 pascal -ret16 SafeArrayGetDim(ptr)
18 pascal -ret16 SafeArrayGetElemsize(ptr)
19 pascal SafeArrayGetUBound(ptr word ptr)
20 pascal SafeArrayGetLBound(ptr word ptr)
21 pascal SafeArrayLock(ptr)
22 pascal SafeArrayUnlock(ptr)
23 pascal SafeArrayAccessData(ptr ptr)
24 pascal SafeArrayUnaccessData(ptr)
25 pascal SafeArrayGetElement(segptr ptr ptr)
26 stub SAFEARRAYPUTELEMENT
27 pascal SafeArrayCopy(ptr ptr)
28 pascal DispGetParam(ptr word word ptr ptr)
29 pascal DispGetIDsOfNames(segptr segptr word segptr)
30 pascal DispInvoke(segptr segptr long word segptr segptr segptr segptr)
31 pascal CreateDispTypeInfo(ptr long ptr)
32 pascal CreateStdDispatch(segptr segptr segptr ptr)
33 variable _IID_IDispatch (0x00020400, 0x00000000, 0x000000C0, 0x46000000)
34 variable _IID_IEnumVARIANT (0x00020404, 0x00000000, 0x000000C0, 0x46000000)
35 pascal RegisterActiveObject(segptr ptr long ptr)
36 pascal RevokeActiveObject(long segptr)
37 pascal GetActiveObject(ptr segptr ptr)
38 pascal SafeArrayAllocDescriptor(word ptr)
39 pascal SafeArrayAllocData(ptr)
40 pascal SafeArrayDestroyDescriptor(segptr)
41 pascal SafeArrayDestroyData(ptr)
42 pascal SafeArrayRedim(ptr ptr)
43 pascal VarI2FromI4(long ptr)
44 pascal VarI2FromR4(float ptr)
45 pascal VarI2FromR8(long long ptr)
46 pascal VarI2FromCy(long long ptr)
47 pascal VarI2FromDate(long long ptr)
48 pascal VarI2FromStr(str long long ptr)
49 stub VARI2FROMDISP
50 pascal VarI2FromBool(word ptr)
51 stub VARI4FROMI2
52 stub VARI4FROMR4
53 stub VARI4FROMR8
54 stub VARI4FROMCY
55 stub VARI4FROMDATE
56 pascal VarI4FromStr(str long long ptr)
57 stub VARI4FROMDISP
58 stub VARI4FROMBOOL
59 stub VARR4FROMI2
60 stub VARR4FROMI4
61 pascal VarR4FromR8(long long ptr)
62 stub VARR4FROMCY
63 stub VARR4FROMDATE
64 pascal VarR4FromStr(str long long ptr)
65 stub VARR4FROMDISP
66 stub VARR4FROMBOOL
67 stub VARR8FROMI2
68 stub VARR8FROMI4
69 stub VARR8FROMR4
70 stub VARR8FROMCY
71 stub VARR8FROMDATE
72 pascal VarR8FromStr(str long long ptr)
73 stub VARR8FROMDISP
74 stub VARR8FROMBOOL
75 stub VARDATEFROMI2
76 stub VARDATEFROMI4
77 stub VARDATEFROMR4
78 stub VARDATEFROMR8
79 stub VARDATEFROMCY
80 pascal VarDateFromStr(str long long ptr)
81 stub VARDATEFROMDISP
82 stub VARDATEFROMBOOL
83 stub VARCYFROMI2
84 stub VARCYFROMI4
85 stub VARCYFROMR4
86 stub VARCYFROMR8
87 stub VARCYFROMDATE
88 pascal VarCyFromStr(str long long ptr)
89 stub VARCYFROMDISP
90 stub VARCYFROMBOOL
91 pascal VarBstrFromI2(s_word long long ptr)
92 pascal VarBstrFromI4(long long long ptr)
93 pascal VarBstrFromR4(long long long ptr)
94 pascal VarBstrFromR8(long long long long ptr)
95 pascal VarBstrFromCy(long long long long ptr)
96 pascal VarBstrFromDate(long long long long ptr)
97 pascal VarBstrFromDisp(segptr long long ptr)
98 pascal VarBstrFromBool(word long long ptr)
99 stub VARBOOLFROMI2
100 stub VARBOOLFROMI4
101 stub VARBOOLFROMR4
102 stub VARBOOLFROMR8
103 stub VARBOOLFROMDATE
104 stub VARBOOLFROMCY
105 stub VARBOOLFROMSTR
106 stub VARBOOLFROMDISP
107 stub DOINVOKEMETHOD
108 pascal VariantChangeTypeEx(ptr ptr long word word)
109 pascal SafeArrayPtrOfIndex(segptr ptr ptr)
110 pascal SetErrorInfo(long segptr)
111 pascal GetErrorInfo(long ptr)
112 pascal CreateErrorInfo(ptr)
113 variable _IID_IErrorInfo (0x1CF2B120, 0x101B547D, 0x0008658E, 0x19D12B2B)
114 variable _IID_ICreateErrorInfo (0x22F03340, 0x101B547D, 0x0008658E, 0x19D12B2B)
115 variable _IID_ISupportErrorInfo (0xDF0B3D60, 0x101B548F, 0x0008658E, 0x19D12B2B)
116 pascal VarUI1FromI2(word ptr)
117 pascal VarUI1FromI4(long ptr)
118 pascal VarUI1FromR4(long ptr)
119 pascal VarUI1FromR8(long long ptr)
120 pascal VarUI1FromCy(long long ptr)
121 pascal VarUI1FromDate(long long ptr)
122 pascal VarUI1FromStr(str long long ptr)
123 pascal VarUI1FromDisp(segptr long ptr)
124 pascal VarUI1FromBool(word ptr)
125 pascal VarI2FromUI1(word ptr)
126 stub VARI4FROMUI1
127 stub VARR4FROMUI1
128 stub VARR8FROMUI1
129 stub VARDATEFROMUI1
130 stub VARCYFROMUI1
131 pascal VarBstrFromUI1(word long long ptr)
132 stub VARBOOLFROMUI1
133 stub DLLCANUNLOADNOW
