# module=SYSTEM source_module=system.DRV
1 pascal InquireSystem(word word)
2 pascal -ret16 CreateSystemTimer(word segptr)
3 pascal -ret16 KillSystemTimer(word)
4 pascal -ret16 EnableSystemTimers()
5 pascal -ret16 DisableSystemTimers()
6 pascal GetSystemMSecCount()
7 pascal -ret16 Get80x87SaveSize()
8 pascal -ret16 Save80x87State(ptr)
9 pascal -ret16 Restore80x87State(ptr)
13 stub INQUIRELONGINTS
20 pascal -ret16 A20_Proc(word)
