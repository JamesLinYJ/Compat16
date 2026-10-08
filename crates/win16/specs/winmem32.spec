# module=WINMEM32 source_module=winmem32.DLL
# Ordinals verified from the Windows 3.1 SDK WINMEM32.LI_ OMF import records.
1 pascal -ret16 GetWinMem32Version()
2 pascal -ret16 Global32Alloc(long ptr long word)
3 pascal -ret16 Global32Realloc(word long word)
4 pascal -ret16 Global32Free(word word)
5 pascal -ret16 Global16PointerAlloc(word long ptr long word)
6 pascal -ret16 Global16PointerFree(word long word)
7 pascal -ret16 Global32CodeAlias(word ptr word)
8 pascal -ret16 Global32CodeAliasFree(word word word)
