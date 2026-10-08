# module=MOUSE source_module=mouse.DRV
1 pascal -ret16 Inquire(ptr)
2 pascal -ret16 Enable(segptr)
3 pascal -ret16 Disable()
4 stub MOUSEGETINTVECT
5 stub GETSETMOUSEDATA
7 stub POWEREVENTPROC
