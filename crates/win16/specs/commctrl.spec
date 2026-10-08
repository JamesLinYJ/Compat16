# module=COMMCTRL source_module=commctrl.DLL
2 pascal -ret16 MenuHelp(word word long word word word ptr)
3 stub SHOWHIDEMENUCTL
4 pascal -ret16 GetEffectiveClientRect(word ptr ptr)
5 stub DRAWSTATUSTEXT
6 pascal -ret16 CreateStatusWindow(long str word word)
7 pascal -ret16 CreateToolbar(word long word word word word ptr word)
8 pascal -ret16 CreateMappedBitmap(word word word ptr word)
9 pascal -ret16 CreateHeaderWindow(long str word word)
10 pascal -ret16 WritePrivateProfileStruct(str str ptr word str)
11 pascal -ret16 GetPrivateProfileStruct(str str ptr word str)
13 pascal -ret16 MakeDragList(word)
14 stub LBITEMFROMPT
15 stub DRAWINSERT
16 stub CREATEUPDOWNCONTROL
17 pascal -ret16 InitCommonControls()
20 pascal -ret16 CreateToolbarEx(word long word word word word ptr word word word word word word)
40 stub IMAGELIST_CREATE
41 stub IMAGELIST_DESTROY
42 stub IMAGELIST_GETIMAGECOUNT
43 stub IMAGELIST_SETOVERLAYIMAGE
44 stub IMAGELIST_SETBKCOLOR
45 stub IMAGELIST_GETBKCOLOR
46 stub IMAGELIST_ADD
49 stub IMAGELIST_DRAW
53 stub IMAGELIST_ADDICON
54 stub IMAGELIST_REPLACEICON
159 stub PROPERTYSHEET
160 stub CREATEPROPERTYSHEETPAGE
161 stub DESTROYPROPERTYSHEETPAGE
328 stub DPA_CREATE
329 stub DPA_DESTROY
330 stub DPA_GROW
331 stub DPA_CLONE
332 stub DPA_GETPTR
333 stub DPA_GETPTRINDEX
334 stub DPA_INSERTPTR
335 stub DPA_SETPTR
336 stub DPA_DELETEPTR
337 stub DPA_DELETEALLPTRS
338 stub DPA_SORT
339 stub DPA_SEARCH
