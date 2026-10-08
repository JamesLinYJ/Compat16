# module=STORAGE source_module=storage.DLL
1 pascal StgCreateDocFileA(str long long ptr)
2 pascal StgCreateDocfileOnILockBytes(segptr long long ptr)
3 pascal StgOpenStorage(str segptr long ptr long ptr)
4 pascal StgOpenStorageOnILockBytes(segptr segptr long ptr long ptr)
5 pascal StgIsStorageFile(str)
6 pascal StgIsStorageILockBytes(segptr)
7 pascal StgSetTimes(str ptr ptr ptr)
103 stub DllGetClassObject
