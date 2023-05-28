@echo off
Setlocal EnableDelayedExpansion
Set _RNDLength=2
Set _Alphanumeric=0123456789ABCDEF
Set _Str=%_Alphanumeric%987654321
:_LenLoop
IF NOT "%_Str:~18%"=="" SET _Str=%_Str:~9%& SET /A _Len+=9& GOTO :_LenLoop
SET _tmp=%_Str:~9,1%
SET /A _Len=_Len+_tmp
Set _count=0
SET _RndAlphaNum=
:_loop
Set /a _count+=1
SET _RND=%Random%
Set /A _RND=_RND%%%_Len%
echo Spoofing...

@echo off
cd "C:\PermanentSpoof"
cd "C:\PermanentSpoof\
KernelMapper.exe /CS %_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /BS %_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /PSN %_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /SS %_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /SU AUTO > nul
KernelMapper.exe /SF %_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /IV 525.67
KernelMapper.exe /SM %_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /SP %_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum%%_RndAlphaNum% > nul
KernelMapper.exe /BP 4575364648422-7485837938678
echo Spoofed!

