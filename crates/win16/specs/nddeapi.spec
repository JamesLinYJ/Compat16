# module=NDDEAPI source_module=nddeapi.DLL
100 pascal -ret16 NDdeShareAdd(str word ptr long)
101 pascal -ret16 NDdeShareDel(str str word)
102 pascal -ret16 NDdeShareEnum(str word ptr long ptr ptr)
103 pascal -ret16 NDdeShareGetInfo(str str word ptr long ptr ptr)
104 pascal -ret16 NDdeShareSetInfo(str str word ptr long word)
105 pascal -ret16 NDdeGetClientInfo(word str long str long)
106 pascal -ret16 NDdeGetNodeName(str long)
107 pascal -ret16 NDdeGetErrorString(word str long)
108 pascal -ret16 NDdeConnectionEnum(str str long word ptr long ptr ptr)
109 pascal -ret16 NDdeIsValidShareName(str)
110 pascal -ret16 NDdeIsValidPassword(str)
111 pascal -ret16 NDdeIsValidTopic(str)
112 pascal -ret16 NDdeSessionEnum(str word ptr long ptr ptr)
113 pascal -ret16 NDdeSessionClose(str str long)
114 pascal -ret16 NDdeGetWindow()
115 stub NDDEISSHARINGALLOWED
200 stub PASSWORDGETFROMUSERMODELESS
201 stub PASSWORDGETFROMCACHE
202 stub PASSWORDADDTOCACHE
203 stub GETCURRENTUSERDOMAINNAME
204 stub PASSWDDLGWB
205 stub PASSWDDLGNT
