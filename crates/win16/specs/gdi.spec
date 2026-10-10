# module=GDI source_module=gdi.EXE
1 pascal SetBkColor(word long)
2 pascal -ret16 SetBkMode(word word)
3 pascal -ret16 SetMapMode(word word)
4 pascal -ret16 SetROP2(word word)
5 pascal -ret16 SetRelAbs(word word)
6 pascal -ret16 SetPolyFillMode(word word)
7 pascal -ret16 SetStretchBltMode(word word)
8 pascal -ret16 SetTextCharacterExtra(word s_word)
9 pascal SetTextColor(word long)
10 pascal -ret16 SetTextJustification(word s_word s_word)
11 pascal SetWindowOrg(word s_word s_word)
12 pascal SetWindowExt(word s_word s_word)
13 pascal SetViewportOrg(word s_word s_word)
14 pascal SetViewportExt(word s_word s_word)
15 pascal OffsetWindowOrg(word s_word s_word)
16 pascal ScaleWindowExt(word s_word s_word s_word s_word)
17 pascal OffsetViewportOrg(word s_word s_word)
18 pascal ScaleViewportExt(word s_word s_word s_word s_word)
19 pascal -ret16 LineTo(word s_word s_word)
20 pascal MoveTo(word s_word s_word)
21 pascal -ret16 ExcludeClipRect(word s_word s_word s_word s_word)
22 pascal -ret16 IntersectClipRect(word s_word s_word s_word s_word)
23 pascal -ret16 Arc(word s_word s_word s_word s_word s_word s_word s_word s_word)
24 pascal -ret16 Ellipse(word s_word s_word s_word s_word)
25 pascal -ret16 FloodFill(word s_word s_word long)
26 pascal -ret16 Pie(word s_word s_word s_word s_word s_word s_word s_word s_word)
27 pascal -ret16 Rectangle(word s_word s_word s_word s_word)
28 pascal -ret16 RoundRect(word s_word s_word s_word s_word s_word s_word)
29 pascal -ret16 PatBlt(word s_word s_word s_word s_word long)
30 pascal -ret16 SaveDC(word)
31 pascal SetPixel(word s_word s_word long)
32 pascal -ret16 OffsetClipRgn(word s_word s_word)
33 pascal -ret16 TextOut(word s_word s_word str word)
34 pascal -ret16 BitBlt(word s_word s_word s_word s_word word s_word s_word long)
35 pascal -ret16 StretchBlt(word s_word s_word s_word s_word word s_word s_word s_word s_word long)
36 pascal -ret16 Polygon(word ptr word)
37 pascal -ret16 Polyline(word ptr word)
38 pascal Escape(word word word segptr ptr)
39 pascal -ret16 RestoreDC(word s_word)
40 pascal -ret16 FillRgn(word word word)
41 pascal -ret16 FrameRgn(word word word word word)
42 pascal -ret16 InvertRgn(word word)
43 pascal -ret16 PaintRgn(word word)
44 pascal -ret16 SelectClipRgn(word word)
45 pascal -ret16 SelectObject(word word)
46 stub BITMAPBITS
47 pascal -ret16 CombineRgn(word word word s_word)
48 pascal -ret16 CreateBitmap(word word word word ptr)
49 pascal -ret16 CreateBitmapIndirect(ptr)
50 pascal -ret16 CreateBrushIndirect(ptr)
51 pascal -ret16 CreateCompatibleBitmap(word word word)
52 pascal -ret16 CreateCompatibleDC(word)
53 pascal -ret16 CreateDC(str str str segptr)
54 pascal -ret16 CreateEllipticRgn(s_word s_word s_word s_word)
55 pascal -ret16 CreateEllipticRgnIndirect(ptr)
56 pascal -ret16 CreateFont(s_word s_word s_word s_word s_word word word word word word word word word str)
57 pascal -ret16 CreateFontIndirect(ptr)
58 pascal -ret16 CreateHatchBrush(word long)
60 pascal -ret16 CreatePatternBrush(word)
61 pascal -ret16 CreatePen(s_word s_word long)
62 pascal -ret16 CreatePenIndirect(ptr)
63 pascal -ret16 CreatePolygonRgn(ptr word word)
64 pascal -ret16 CreateRectRgn(s_word s_word s_word s_word)
65 pascal -ret16 CreateRectRgnIndirect(ptr)
66 pascal -ret16 CreateSolidBrush(long)
67 pascal -ret16 DPtoLP(word ptr s_word)
68 pascal -ret16 DeleteDC(word)
69 pascal -ret16 DeleteObject(word)
70 pascal -ret16 EnumFonts(word str segptr long)
71 pascal -ret16 EnumObjects(word word segptr long)
72 pascal -ret16 EqualRgn(word word)
73 pascal -ret16 ExcludeVisRect(word s_word s_word s_word s_word)
74 pascal GetBitmapBits(word long ptr)
75 pascal GetBkColor(word)
76 pascal -ret16 GetBkMode(word)
77 pascal -ret16 GetClipBox(word ptr)
78 pascal GetCurrentPosition(word)
79 pascal GetDCOrg(word)
80 pascal -ret16 GetDeviceCaps(word s_word)
81 pascal -ret16 GetMapMode(word)
82 pascal -ret16 GetObject(word s_word ptr)
83 pascal GetPixel(word s_word s_word)
84 pascal -ret16 GetPolyFillMode(word)
85 pascal -ret16 GetROP2(word)
86 pascal -ret16 GetRelAbs(word)
87 pascal -ret16 GetStockObject(word)
88 pascal -ret16 GetStretchBltMode(word)
89 pascal -ret16 GetTextCharacterExtra(word)
90 pascal GetTextColor(word)
91 pascal GetTextExtent(word ptr s_word)
92 pascal -ret16 GetTextFace(word s_word ptr)
93 pascal -ret16 GetTextMetrics(word ptr)
94 pascal GetViewportExt(word)
95 pascal GetViewportOrg(word)
96 pascal GetWindowExt(word)
97 pascal GetWindowOrg(word)
98 pascal -ret16 IntersectVisRect(word s_word s_word s_word s_word)
99 pascal -ret16 LPtoDP(word ptr s_word)
100 pascal -ret16 LineDDA(s_word s_word s_word s_word segptr long)
101 pascal -ret16 OffsetRgn(word s_word s_word)
102 pascal -ret16 OffsetVisRgn(word s_word s_word)
103 pascal -ret16 PtVisible(word s_word s_word)
104 pascal -ret16 RectVisibleOld(word ptr)
105 pascal -ret16 SelectVisRgn(word word)
106 pascal SetBitmapBits(word long ptr)
117 pascal SetDCOrg(word s_word s_word)
118 pascal -ret16 GetSystemIconFont()
119 pascal -ret16 AddFontResource(str)
120 stub GetContinuingTextExtent
121 pascal -ret16 Death(word)
122 pascal -ret16 Resurrection(word word word word word word word)
123 pascal -ret16 PlayMetaFile(word word)
124 pascal -ret16 GetMetaFile(str)
125 pascal -ret16 CreateMetaFile(str)
126 pascal -ret16 CloseMetaFile(word)
127 pascal -ret16 DeleteMetaFile(word)
128 pascal -ret16 MulDiv(s_word s_word s_word)
129 pascal -ret16 SaveVisRgn(word)
130 pascal -ret16 RestoreVisRgn(word)
131 pascal -ret16 InquireVisRgn(word)
132 pascal -ret16 SetEnvironment(str str word)
133 pascal -ret16 GetEnvironment(str str word)
134 pascal -ret16 GetRgnBox(word ptr)
135 pascal -ret16 ScanLR(word word word long word)
136 pascal -ret16 RemoveFontResource(str)
137 stub GSV
138 stub DPXlate
139 stub SetWinViewExt
140 stub ScaleExt
141 stub WordSet
142 stub RectStuff
143 stub OffsetOrg
144 stub LockDC
145 stub UnlockDC
146 stub LockUnlock
147 stub GDI_FarFrame
148 pascal SetBrushOrg(word s_word s_word)
149 pascal GetBrushOrg(word)
150 pascal -ret16 UnrealizeObject(word)
151 pascal -ret16 CopyMetaFile(word str)
152 stub GDIInitApp
153 pascal -ret16 CreateIC(str str str ptr)
154 pascal GetNearestColor(word long)
155 pascal -ret16 QueryAbort(word word)
156 pascal -ret16 CreateDiscardableBitmap(word word word)
157 stub CompatibleBitmap
158 stub EnumCallback
159 pascal -ret16 GetMetaFileBits(word)
160 pascal -ret16 SetMetaFileBits(word)
161 pascal -ret16 PtInRegion(word s_word s_word)
162 pascal GetBitmapDimension(word)
163 pascal SetBitmapDimension(word s_word s_word)
164 stub PixToLine
169 pascal -ret16 IsDCDirty(word segptr)
170 stub SetDCStatus
171 stub LVBUNION
172 pascal -ret16 SetRectRgn(word s_word s_word s_word s_word)
173 pascal -ret16 GetClipRgn(word)
174 stub BLOAT
175 pascal -ret16 EnumMetaFile(word word segptr long)
176 pascal -ret16 PlayMetaFileRecord(word ptr ptr word)
177 stub RCOS
178 stub RSIN
179 pascal -ret16 GetDCState(word)
180 pascal -ret16 SetDCState(word word)
181 pascal -ret16 RectInRegionOld(word ptr)
182 stub REQUESTSEM
183 stub CLEARSEM
184 stub STUFFVISIBLE
185 stub STUFFINREGION
186 stub DELETEABOVELINEFONTS
188 stub GetTextExtentEx
190 pascal -ret16 SetDCHook(word segptr long)
191 pascal GetDCHook(word ptr)
192 pascal -ret16 SetHookFlags(word word)
193 pascal -ret16 SetBoundsRect(word ptr word)
194 pascal -ret16 GetBoundsRect(word ptr word)
195 pascal -ret16 SelectBitmap(word word)
196 pascal -ret16 SetMetaFileBitsBetter(word)
201 stub DMBITBLT
202 stub DMCOLORINFO
206 stub dmEnumDFonts
207 stub DMENUMOBJ
208 stub DMOUTPUT
209 stub DMPIXEL
210 stub dmRealizeObject
211 stub DMSTRBLT
212 stub DMSCANLR
213 stub BRUTE
214 stub DMEXTTEXTOUT
215 stub DMGETCHARWIDTH
216 stub DMSTRETCHBLT
217 stub DMDIBBITS
218 stub DMSTRETCHDIBITS
219 stub DMSETDIBTODEV
220 stub DMTRANSPOSE
230 pascal -ret16 CreatePQ(word)
231 pascal -ret16 MinPQ(word)
232 pascal -ret16 ExtractPQ(word)
233 pascal -ret16 InsertPQ(word word word)
234 pascal -ret16 SizePQ(word word)
235 pascal -ret16 DeletePQ(word)
240 pascal -ret16 OpenJob(str str word)
241 pascal -ret16 WriteSpool(word ptr word)
242 pascal -ret16 WriteDialog(word str word)
243 pascal -ret16 CloseJob(word)
244 pascal -ret16 DeleteJob(word word)
245 pascal GetSpoolJob(word ptr)
246 pascal -ret16 StartSpoolPage(word)
247 pascal -ret16 EndSpoolPage(word)
248 stub QueryJob
250 pascal -ret16 Copy(ptr ptr word)
253 stub DeleteSpoolPage
254 pascal -ret16 SpoolFile(ptr ptr ptr ptr)
267 stub StartDocPrintEra
268 stub StartPagePrinter
269 stub WritePrinter
270 stub EndPagePrinter
271 stub AbortPrinter
272 stub EndDocPrinter
274 stub ClosePrinter
280 stub GetRealDriverInfo
281 pascal DrvSetPrinterData(str str long ptr long)
282 pascal DrvGetPrinterData(str str ptr ptr long ptr)
299 stub ENGINEGETCHARWIDTHEX
300 pascal EngineEnumerateFont(str segptr long)
301 pascal -ret16 EngineDeleteFont(ptr)
302 pascal EngineRealizeFont(ptr ptr ptr)
303 pascal -ret16 EngineGetCharWidth(ptr word word ptr)
304 pascal -ret16 EngineSetFontContext(ptr word)
305 pascal -ret16 EngineGetGlyphBMP(word ptr word word ptr long ptr)
306 pascal EngineMakeFontDir(word ptr ptr)
307 pascal -ret16 GetCharABCWidths(word word word ptr)
308 pascal -ret16 GetOutlineTextMetrics(word word ptr)
309 pascal GetGlyphOutline(word word word ptr long ptr ptr)
310 pascal -ret16 CreateScalableFontResource(word str str str)
311 pascal GetFontData(word long long ptr long)
312 stub ConvertOutLineFontFile
313 pascal -ret16 GetRasterizerCaps(ptr word)
314 stub EngineExtTextOut
315 pascal EngineRealizeFontExt(long long long long)
316 stub EngineGetCharWidthStr
317 stub EngineGetGlyphBmpExt
330 pascal -ret16 EnumFontFamilies(word str segptr long)
332 pascal -ret16 GetKerningPairs(word word ptr)
345 pascal -ret16 GetTextAlign(word)
346 pascal -ret16 SetTextAlign(word word)
347 stub MFDRAWTEXT
348 pascal -ret16 Chord(word s_word s_word s_word s_word s_word s_word s_word s_word)
349 pascal SetMapperFlags(word long)
# Primary ordinal/header evidence: README.md (Microsoft SDK 3.10 disk 03).
350 pascal -ret16 GetCharWidth(word word word ptr)
351 pascal -ret16 ExtTextOut(word s_word s_word word ptr str word ptr)
352 pascal -ret16 GetPhysicalFontHandle(word)
353 pascal GetAspectRatioFilter(word)
354 pascal -ret16 ShrinkGDIHeap()
355 stub FTrapping0
360 pascal -ret16 CreatePalette(ptr)
361 pascal -ret16 GDISelectPalette(word word word)
362 pascal -ret16 GDIRealizePalette(word)
363 pascal -ret16 GetPaletteEntries(word word word ptr)
364 pascal -ret16 SetPaletteEntries(word word word ptr)
365 pascal -ret16 RealizeDefaultPalette(word)
366 pascal -ret16 UpdateColors(word)
367 pascal -ret16 AnimatePalette(word word word ptr)
368 pascal -ret16 ResizePalette(word word)
370 pascal -ret16 GetNearestPaletteIndex(word long)
372 pascal -ret16 ExtFloodFill(word s_word s_word long word)
373 pascal -ret16 SetSystemPaletteUse(word word)
374 pascal -ret16 GetSystemPaletteUse(word)
375 pascal -ret16 GetSystemPaletteEntries(word word word ptr)
376 pascal -ret16 ResetDC(word ptr)
377 pascal -ret16 StartDoc(word ptr)
378 pascal -ret16 EndDoc(word)
379 pascal -ret16 StartPage(word)
380 pascal -ret16 EndPage(word)
381 pascal -ret16 SetAbortProc(word segptr)
382 pascal -ret16 AbortDoc(word)
400 pascal -ret16 FastWindowFrame(word ptr s_word s_word long)
401 pascal -ret16 GdiMoveBitmap(word)
402 stub GDIGETBITSGLOBAL
403 pascal -ret16 GdiInit2(word word)
404 stub GetTTGlyphIndexMap
405 pascal -ret16 FinalGdiInit(word)
406 stub CREATEREALBITMAPINDIRECT
407 pascal -ret16 CreateUserBitmap(word word word word ptr)
408 stub CREATEREALBITMAP
409 pascal -ret16 CreateUserDiscardableBitmap(word word word)
410 pascal -ret16 IsValidMetaFile(word)
411 pascal -ret16 GetCurLogFont(word)
412 pascal -ret16 IsDCCurrentPalette(word)
439 pascal -ret16 StretchDIBits(word s_word s_word s_word s_word s_word s_word s_word s_word ptr ptr word long)
440 pascal -ret16 SetDIBits(word word word word ptr ptr word)
441 pascal -ret16 GetDIBits(word word word word ptr ptr word)
442 pascal -ret16 CreateDIBitmap(word ptr long ptr ptr word)
443 pascal -ret16 SetDIBitsToDevice(word s_word s_word s_word s_word s_word s_word word word ptr ptr word)
444 pascal -ret16 CreateRoundRectRgn(s_word s_word s_word s_word s_word s_word)
445 pascal -ret16 CreateDIBPatternBrush(word word)
449 stub DEVICECOLORMATCH
450 pascal -ret16 PolyPolygon(word ptr ptr word)
451 pascal -ret16 CreatePolyPolygonRgn(ptr ptr word word)
452 pascal GdiSeeGdiDo(word word word word)
460 pascal -ret16 GdiTaskTermination(word)
461 pascal -ret16 SetObjectOwner(word word)
462 pascal -ret16 IsGDIObject(word)
463 pascal -ret16 MakeObjectPrivate(word word)
464 stub FIXUPBOGUSPUBLISHERMETAFILE
465 pascal -ret16 RectVisible(word ptr)
466 pascal -ret16 RectInRegion(word ptr)
467 pascal -ret16 UnicodeToAnsi(segptr segptr)
468 pascal -ret16 GetBitmapDimensionEx(word ptr)
469 pascal -ret16 GetBrushOrgEx(word ptr)
470 pascal -ret16 GetCurrentPositionEx(word ptr)
471 pascal -ret16 GetTextExtentPoint(word ptr s_word ptr)
472 pascal -ret16 GetViewportExtEx(word ptr)
473 pascal -ret16 GetViewportOrgEx(word ptr)
474 pascal -ret16 GetWindowExtEx(word ptr)
475 pascal -ret16 GetWindowOrgEx(word ptr)
476 pascal -ret16 OffsetViewportOrgEx(word s_word s_word ptr)
477 pascal -ret16 OffsetWindowOrgEx(word s_word s_word ptr)
478 pascal -ret16 SetBitmapDimensionEx(word s_word s_word ptr)
479 pascal -ret16 SetViewportExtEx(word s_word s_word ptr)
480 pascal -ret16 SetViewportOrgEx(word s_word s_word ptr)
481 pascal -ret16 SetWindowExtEx(word s_word s_word ptr)
482 pascal -ret16 SetWindowOrgEx(word s_word s_word ptr)
483 pascal -ret16 MoveToEx(word s_word s_word ptr)
484 pascal -ret16 ScaleViewportExtEx(word s_word s_word s_word s_word ptr)
485 pascal -ret16 ScaleWindowExtEx(word s_word s_word s_word s_word ptr)
486 pascal -ret16 GetAspectRatioFilterEx(word ptr)
488 pascal -ret16 GetFontAssocStatus(word)
489 pascal -ret16 CreateDIBSection(word ptr word ptr long long)
490 stub CloseEnhMetafile
491 stub CopyEnhMetafile
492 stub CreateEnhMetafile
493 stub DeleteEnhMetafile
495 stub GDIComment
496 stub GetEnhMetafile
497 stub GetEnhMetafileBits
498 stub GetEnhMetafileDescription
499 stub GetEnhMetafileHeader
501 stub GetEnhMetafilePaletteEntries
502 pascal -ret16 PolyBezier(word ptr word)
503 pascal -ret16 PolyBezierTo(word ptr word)
504 stub PlayEnhMetafileRecord
505 stub SetEnhMetafileBits
506 stub SetMetaRgn
508 pascal -ret16 ExtSelectClipRgn(word word word)
511 pascal -ret16 AbortPath(word)
512 pascal -ret16 BeginPath(word)
513 pascal -ret16 CloseFigure(word)
514 pascal -ret16 EndPath(word)
515 pascal -ret16 FillPath(word)
516 pascal -ret16 FlattenPath(word)
517 pascal -ret16 GetPath(word ptr ptr word)
518 pascal -ret16 PathToRegion(word)
519 pascal -ret16 SelectClipPath(word word)
520 pascal -ret16 StrokeAndFillPath(word)
521 pascal -ret16 StrokePath(word)
522 pascal -ret16 WidenPath(word)
523 stub ExtCreatePen
524 pascal -ret16 GetArcDirection(word)
525 pascal -ret16 SetArcDirection(word word)
526 stub GetMiterLimit
527 stub SetMiterLimit
528 stub GDIParametersInfo
529 pascal -ret16 CreateHalftonePalette(word)
530 pascal -ret16 RawTextOut(word s_word s_word str word)
531 pascal -ret16 RawExtTextOut(word s_word s_word word ptr str word ptr)
532 pascal -ret16 RawGetTextExtent(word str word)
533 pascal -ret16 RawGetTextExtentEx()
536 pascal -ret16 BiDiLayout()
537 pascal -ret16 BiDiCreateTabString()
538 pascal -ret16 BiDiCreateString()
539 pascal -ret16 BiDiStringOut()
540 pascal -ret16 BiDiGlyphOut(word word word word str word word word)
541 pascal -ret16 BiDiJustifyString()
542 pascal -ret16 BiDiSetStringTabs()
543 pascal -ret16 BiDiGetStringExtent()
544 pascal -ret16 BiDiGetNextGlyph()
545 pascal -ret16 BiDiGetPrevGlyph()
546 pascal -ret16 BiDiIsStringRTL()
547 pascal -ret16 BiDiGlyphLength()
548 pascal -ret16 BiDiCaretStringToPel()
549 pascal -ret16 BiDiCaretPelToString()
550 pascal -ret16 BiDiStringToGlyph()
551 pascal -ret16 BiDiGlyphToString()
552 pascal -ret16 BiDiPelToGlyph()
553 pascal -ret16 BiDiGlyphToPel()
554 pascal -ret16 BiDiBounds()
555 pascal -ret16 BiDiDeleteString(word)
556 pascal -ret16 BiDiSetDefaults()
558 pascal -ret16 BiDiGetDefaults()
559 pascal -ret16 BiDiCalcString(word word ptr word word word word word)
560 pascal -ret16 BiDiShape(word word word word word word word word word word word word word word word word word word word word)
561 pascal -ret16 BiDiFontComplement()
563 pascal -ret16 BiDiCalcTabString()
564 pascal -ret16 BiDiSetKashida()
565 pascal -ret16 BiDiKExtTextOut()
566 pascal -ret16 BiDiShapeEx()
569 pascal -ret16 BiDiCreateStringEx(word word word ptr word word word word word)
570 pascal -ret16 GetUnicodeMap()
571 pascal -ret16 GetTextExtentRtoL()
572 pascal -ret16 GetHDCCharSet(word)
573 pascal -ret16 BiDiLayoutEx(ptr word word word ptr word word word word ptr ptr word word word)
574 pascal -ret16 BiDiCreateTabStringEx()
575 pascal -ret16 BiDiCalcTabStringEx()
576 pascal -ret16 BiDiCalcStringEx()
588 pascal -ret16 SetTextCodePage(word word)
589 pascal -ret16 GetTextCodePage()
602 pascal -ret16 SetDIBColorTable(word word word ptr)
603 pascal -ret16 GetDIBColorTable(word word word ptr)
604 pascal -ret16 SetSolidBrush(word long)
605 pascal -ret16 SysDeleteObject(word)
606 pascal -ret16 SetMagicColors(word long word)
607 pascal GetRegionData(word long ptr)
608 stub ExtCreateRegion
609 pascal -ret16 GdiFreeResources(long)
610 pascal -ret16 GdiSignalProc32(long long long word)
611 stub GetRandomRgn
612 pascal -ret16 GetTextCharset(word)
613 pascal -ret16 EnumFontFamiliesEx(word ptr segptr long long)
614 stub AddLpkToGDI
615 stub GetCharacterPlacement
616 pascal GetFontLanguageInfo(word)
650 stub BuildInverseTableDIB
701 stub GDITHKCONNECTIONDATALS
702 stub FT_GDIFTHKTHKCONNECTIONDATA
703 stub FDTHKCONNECTIONDATASL
704 stub ICMTHKCONNECTIONDATASL
820 stub ICMCreateTransform
821 stub ICMDeleteTransform
822 stub ICMTranslateRGB
823 stub ICMTranslateRGBs
824 stub ICMCheckColorsInGamut
1000 pascal -ret16 SetLayout(word long)
1001 stub GetLayout
5000 pascal DllEntryPoint(long word word word long word)
