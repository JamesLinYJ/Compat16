# module=STRESS source_module=stress.DLL
# Ordinals verified from the Windows 3.1 SDK STRESS.LI_ OMF import records.
2 pascal -ret16 AllocMem(long)
3 pascal FreeAllMem()
6 pascal -ret16 AllocFileHandles(word)
7 pascal UnAllocFileHandles()
8 pascal -ret16 GetFreeFileHandles()
10 pascal -ret16 AllocDiskSpace(long word)
11 pascal UnAllocDiskSpace(word)
12 pascal -ret16 AllocUserMem(word)
13 pascal FreeAllUserMem()
14 pascal -ret16 AllocGDIMem(word)
15 pascal FreeAllGDIMem()
