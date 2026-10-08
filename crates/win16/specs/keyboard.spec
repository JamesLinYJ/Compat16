# module=KEYBOARD source_module=keyboard.DRV
1 pascal -ret16 Inquire(ptr)
2 pascal -ret16 Enable(segptr ptr)
3 pascal -ret16 Disable()
4 pascal -ret16 ToAscii(word word ptr ptr word)
5 pascal -ret16 AnsiToOem(str ptr)
6 pascal -ret16 OemToAnsi(str ptr)
7 pascal -ret16 SetSpeed(word)
9 stub INQUIREEX
10 stub TOASCIIEX
11 stub VKKEYSCANEX
12 stub MAPVIRTUALKEYEX
13 stub NEWTABLEEX
14 stub __EXPORTEDSTUB
100 pascal ScreenSwitchEnable(word)
128 pascal OemKeyScan(word)
129 pascal -ret16 VkKeyScan(word)
130 pascal -ret16 GetKeyboardType(word)
131 pascal -ret16 MapVirtualKey(word word)
132 pascal -ret16 GetKBCodePage()
133 pascal -ret16 GetKeyNameText(long ptr word)
134 pascal -ret16 AnsiToOemBuff(ptr ptr word)
135 pascal -ret16 OemToAnsiBuff(ptr ptr word)
