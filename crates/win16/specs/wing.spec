# module=WING source_module=wing.DLL
1001 pascal -ret16 WinGCreateDC()
1002 pascal -ret16 WinGRecommendDIBFormat(ptr)
1003 pascal -ret16 WinGCreateBitmap(word ptr ptr)
1004 pascal WinGGetDIBPointer(word ptr)
1005 pascal -ret16 WinGGetDIBColorTable(word word word ptr)
1006 pascal -ret16 WinGSetDIBColorTable(word word word ptr)
1007 pascal -ret16 WinGCreateHalfTonePalette()
# COLORREF occupies a DWORD in the Microsoft WinG Win16 prototype.
1008 pascal -ret16 WinGCreateHalfToneBrush(word long word)
1009 pascal -ret16 WinGStretchBlt(word word word word word word word word word word)
1010 pascal -ret16 WinGBitBlt(word word word word word word word word)
