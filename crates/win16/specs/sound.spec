# module=SOUND source_module=sound.DRV
1 pascal -ret16 OpenSound()
2 pascal CloseSound()
3 pascal -ret16 SetVoiceQueueSize(word word)
4 pascal -ret16 SetVoiceNote(word word word word)
5 pascal -ret16 SetVoiceAccent(word word word word word)
6 pascal -ret16 SetVoiceEnvelope(word word word)
7 pascal -ret16 SetSoundNoise(word word)
8 pascal -ret16 SetVoiceSound(word long word)
9 pascal -ret16 StartSound()
10 pascal -ret16 StopSound()
11 pascal -ret16 WaitSoundState(word)
12 pascal -ret16 SyncAllVoices()
13 pascal -ret16 CountVoiceNotes(word)
14 pascal GetThresholdEvent()
15 pascal -ret16 GetThresholdStatus()
16 pascal -ret16 SetVoiceThreshold(word word)
# SDK 3.0/3.1 do not establish this export's arguments or return ABI.
17 stub DoBeep
18 stub MYOPENSOUND
