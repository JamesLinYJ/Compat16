# module=WIN87EM source_module=win87em.DLL
1 pascal -register __fpMath()
3 pascal -ret16 __Win87EmInfo(ptr word)
4 pascal -ret16 __Win87EmRestore(ptr word)
5 pascal -ret16 __Win87EmSave(ptr word)
100 pascal -register fpe_return()
