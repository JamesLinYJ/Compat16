# module=WINSPOOL source_module=winspool.DRV
1 stub DEVBITBLT
2 stub COLORINFO
3 stub CONTROL
4 stub DISABLE
5 stub ENABLE
6 stub ENUMDFONTS
7 stub ENUMOBJ
8 stub OUTPUT
9 stub PIXEL
10 stub REALIZEOBJECT
11 stub STRBLT
12 stub SCANLR
13 pascal DeviceMode(word word str str)
14 stub DEVEXTTEXTOUT
15 stub DEVGETCHARWIDTH
19 stub DEVICEBITMAPBITS
20 stub CREATEDIBITMAP
21 stub SETDIBITSTODEVICE
28 stub STRETCHDIB
90 pascal ExtDeviceMode(word word ptr str str ptr str word)
# PRINT.H declares lpOutput as an index-dependent binary array, not ANSI text.
91 pascal DeviceCapabilities(str str word ptr ptr)
92 stub QUERYDEVICENAMES
94 stub DEVINSTALL
1000 stub ADVANCEDSETUPDIALOG
